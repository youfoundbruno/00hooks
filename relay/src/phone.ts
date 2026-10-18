// The phone routes (PROTOCOL §10): pairings, pairing redemption, confirmation, the phone list,
// unpairing, and the socket. The relay routes sealed envelopes between a node and its phones; it
// never opens, verifies or logs what is in them.

import { revokePhone, deviceName, sealKeyField } from "./accounts.ts";
import { accountStub, phoneStub, type Caller } from "./auth.ts";
import { importPublicKey } from "./canonical.ts";
import { constantTimeEqualStrings, fromBase64, isId, newId, toBase64Url, utf8 } from "./encoding.ts";
import { HttpError, error, invalid, json, notFound, parseJsonObject, unavailable } from "./http.ts";
import { clientKey } from "./ip.ts";
import type { SysMessage } from "./phone-object.ts";
import { isStandardBase64 } from "./phone-object.ts";

/** A pairing is valid at most this long after it is registered. */
export const PAIRING_MAX_MS = 10 * 60_000;
/** Open (unexpired, unused) pairings an account may have at once. */
export const MAX_OPEN_PAIRINGS = 5;
/** A paired phone stays pending this long past its pairing's expiry, waiting for the node to confirm. */
export const CONFIRM_GRACE_MS = 5 * 60_000;
/** The sealed hello's ciphertext, decoded, at most. */
export const HELLO_MAX_BYTES = 8 * 1024;
/** Pairings, used or not, are forgotten this long after they expire. */
const PAIRING_KEEP_MS = 24 * 3600_000;
/** Wrong proofs a pairing takes before it is burned: then not even the right proof redeems it. */
export const MAX_PROOF_FAILURES = 5;

/** Unpadded base64url of exactly `bytes` bytes, in its one spelling. */
function canonicalB64Url(v: unknown, bytes: number): v is string {
  if (typeof v !== "string" || v.length !== Math.ceil((bytes * 4) / 3) || !/^[A-Za-z0-9_-]+$/.test(v)) return false;
  const raw = fromBase64(v);
  return raw !== null && raw.byteLength === bytes && toBase64Url(raw) === v;
}

/** `b64url(SHA-256(UTF-8(proof)))`: what the relay keeps for a pairing. */
export async function pairingVerifier(proof: string): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(proof))));
}

/** `POST /v1/phone/pairings` (a node device): registers a one-time pairing. */
export async function createPairing(env: Env, caller: Caller, body: Uint8Array): Promise<Response> {
  const input = parseJsonObject(body);
  if (!canonicalB64Url(input.pairingId, 16)) throw new HttpError(invalid("pairingId", "pairingId must be 16 bytes in unpadded base64url (22 characters)."));
  if (!canonicalB64Url(input.verifier, 32)) throw new HttpError(invalid("verifier", "verifier must be 32 bytes in unpadded base64url (43 characters)."));
  const now = Date.now();
  const asked = input.expiresAt;
  if (typeof asked !== "number" || !Number.isSafeInteger(asked) || asked <= now) {
    throw new HttpError(invalid("expiresAt", "expiresAt must be a time in Unix ms in the future."));
  }
  const expiresAt = Math.min(asked, now + PAIRING_MAX_MS);
  const pairingId = input.pairingId;

  await env.DB.prepare("DELETE FROM phone_pairings WHERE account_id = ? AND expires_at < ?").bind(caller.accountId, now - PAIRING_KEEP_MS).run();
  await freeExpiredPhones(env, "account_id", caller.accountId, now);
  if (await env.DB.prepare("SELECT 1 AS x FROM phone_pairings WHERE id = ?").bind(pairingId).first()) {
    return error(409, "conflict", "That pairing id is already registered.");
  }
  // One statement: the count of open pairings and the insert can't be split by a parallel request.
  let inserted: number;
  try {
    const r = await env.DB.prepare(
      `INSERT INTO phone_pairings (id, account_id, device_id, verifier, created_at, expires_at)
       SELECT ?1, ?2, ?3, ?4, ?5, ?6
       WHERE (SELECT count(*) FROM phone_pairings
              WHERE account_id = ?2 AND used_at IS NULL AND expires_at > ?5 AND failures < ?8) < ?7`,
    )
      .bind(pairingId, caller.accountId, caller.deviceId, input.verifier, now, expiresAt, MAX_OPEN_PAIRINGS, MAX_PROOF_FAILURES)
      .run();
    inserted = r.meta.changes;
  } catch (e) {
    if (String(e).includes("UNIQUE")) return error(409, "conflict", "That pairing id is already registered.");
    throw e;
  }
  if (inserted === 0) {
    return error(429, "rate_limited", `An account may have at most ${MAX_OPEN_PAIRINGS} open pairings; wait for one to expire.`, {}, { "Retry-After": "60" });
  }
  await accountStub(env, caller.accountId).audit({ kind: "phone.pairing", actor: caller.deviceId, subject: pairingId, name: null });
  return json({ pairingId, expiresAt }, 201);
}

/** The sealed hello the phone sends its node: shape only, never opened here. */
function helloField(v: unknown): { enc: string; ct: string } {
  const bad = () => new HttpError(invalid("hello", `hello must be { enc, ct }: a 43-character base64url enc and a standard base64 ct of at most ${HELLO_MAX_BYTES} bytes.`));
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw bad();
  const h = v as Record<string, unknown>;
  if (Object.keys(h).some((k) => k !== "enc" && k !== "ct")) throw bad();
  if (!canonicalB64Url(h.enc, 32) || !isStandardBase64(h.ct)) throw bad();
  const ct = fromBase64(h.ct);
  // An AEAD ciphertext is at least its 16-byte tag.
  if (!ct || ct.byteLength < 16 || ct.byteLength > HELLO_MAX_BYTES) throw bad();
  return { enc: h.enc, ct: h.ct };
}

/**
 * Deletes the D1 rows of phones that were never confirmed and whose pending time ran out, so the
 * public keys they hold (unique across devices) are free again: such a phone never became a device
 * that could do anything but wait, and the PhoneObject's alarm revokes its side.
 */
async function freeExpiredPhones(env: Env, column: "account_id" | "public_key", value: string, now: number): Promise<void> {
  await env.DB.prepare(
    `DELETE FROM devices WHERE ${column} = ? AND kind = 'phone' AND pending_until IS NOT NULL AND pending_until <= ?`,
  )
    .bind(value, now)
    .run();
}

/** `POST /v1/phone/pair` (unsigned): a phone redeems a pairing and becomes a pending device. */
export async function redeemPairing(request: Request, env: Env, body: Uint8Array): Promise<Response> {
  // Fail closed: these limits are what make guessing proofs slow. The address first, so one address
  // past its limit doesn't spend the relay-wide budget.
  if (!env.PAIR_IP_LIMIT || !env.PAIR_GLOBAL_LIMIT) return unavailable();
  const limited = () => error(429, "rate_limited", "Too many pairing attempts; try again later.", {}, { "Retry-After": "60" });
  if (!(await env.PAIR_IP_LIMIT.limit({ key: clientKey(request) })).success) return limited();
  if (!(await env.PAIR_GLOBAL_LIMIT.limit({ key: "global" })).success) return limited();

  // The proof first: nothing costly (key imports, the trial seal, D1 lookups by key) happens, and
  // nothing about the body's other fields is said, until it holds.
  const input = parseJsonObject(body);
  if (!canonicalB64Url(input.pairingId, 16)) throw new HttpError(invalid("pairingId", "pairingId must be 16 bytes in unpadded base64url (22 characters)."));
  if (!canonicalB64Url(input.proof, 32)) throw new HttpError(invalid("proof", "proof must be 32 bytes in unpadded base64url (43 characters)."));
  const pairingId = input.pairingId;
  const proof = input.proof;

  const invalidCode = () => error(401, "unauthorized", "That pairing code isn't valid.");
  const lockedCode = () => error(401, "unauthorized", "That pairing code was locked after too many wrong attempts; make a new one.");
  const usedCode = () => error(409, "conflict", "That pairing code was already used.");
  const expiredCode = () => error(401, "unauthorized", "That pairing code has expired.");

  const now = Date.now();
  const row = await env.DB.prepare("SELECT account_id, device_id, verifier, expires_at, used_at, failures FROM phone_pairings WHERE id = ?")
    .bind(pairingId)
    .first<{ account_id: string; device_id: string; verifier: string; expires_at: number; used_at: number | null; failures: number }>();
  // Hash and compare even when there's no row, so timing doesn't say whether the id exists.
  const got = await pairingVerifier(proof);
  const proofOk = constantTimeEqualStrings(got, row?.verifier ?? "-".repeat(43));
  if (!row || !proofOk) {
    // Counted against an open pairing (the same write whether or not the id exists); the
    // MAX_PROOF_FAILURES-th wrong proof burns it.
    await env.DB.prepare("UPDATE phone_pairings SET failures = failures + 1 WHERE id = ? AND used_at IS NULL AND failures < ?")
      .bind(pairingId, MAX_PROOF_FAILURES)
      .run();
    return invalidCode();
  }
  if (row.failures >= MAX_PROOF_FAILURES) return lockedCode();
  if (row.used_at !== null) return usedCode();
  if (row.expires_at <= now) return expiredCode();

  // The rest of the body, now that the caller has shown it holds the pairing.
  const name = deviceName(input.deviceName);
  if (typeof input.publicKey !== "string" || !(await importPublicKey(input.publicKey))) {
    throw new HttpError(invalid("publicKey", "publicKey must be a raw Ed25519 public key in base64url."));
  }
  const key = input.publicKey;
  const seal = await sealKeyField(input.sealKey);
  if (!seal) throw new HttpError(invalid("sealKey", "sealKey must be a raw X25519 public key in base64url."));
  const hello = helloField(input.hello);

  // A key held by a phone that was never confirmed in time is freed; one held by any other device
  // is refused before the pairing is spent, so the phone can retry with another key.
  await freeExpiredPhones(env, "public_key", key, now);
  const keyTaken = () => error(409, "conflict", "That public key already belongs to a device.");
  if (await env.DB.prepare("SELECT 1 AS x FROM devices WHERE public_key = ?").bind(key).first()) return keyTaken();

  // Spent atomically: of two parallel redemptions, exactly one gets the row back.
  const spent = await env.DB.prepare(
    `UPDATE phone_pairings SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ? AND failures < ?
     RETURNING account_id, device_id, expires_at`,
  )
    .bind(now, pairingId, now, MAX_PROOF_FAILURES)
    .first<{ account_id: string; device_id: string; expires_at: number }>();
  if (!spent) {
    const after = await env.DB.prepare("SELECT used_at, failures FROM phone_pairings WHERE id = ?")
      .bind(pairingId)
      .first<{ used_at: number | null; failures: number }>();
    if (after?.used_at != null) return usedCode();
    return after && after.failures >= MAX_PROOF_FAILURES ? lockedCode() : expiredCode();
  }
  // Undoes the spend, so a redemption that failed after it can be retried with the same code.
  const release = () => env.DB.prepare("UPDATE phone_pairings SET used_at = NULL WHERE id = ? AND used_at = ?").bind(pairingId, now).run();

  // The node that registered it must still be a device of the account.
  const node = await env.DB.prepare("SELECT kind, revoked_at FROM devices WHERE id = ? AND account_id = ?")
    .bind(spent.device_id, spent.account_id)
    .first<{ kind: string; revoked_at: number | null }>();
  if (!node || node.kind !== "device" || node.revoked_at !== null) return invalidCode();

  // D1 first (the unique key decides a race), then the PhoneObject; if the object fails or refuses,
  // the D1 row is removed and the pairing released, so neither side is left with half a phone.
  const deviceId = newId("dev");
  const pendingUntil = spent.expires_at + CONFIRM_GRACE_MS;
  try {
    await env.DB.prepare(
      `INSERT INTO devices (id, account_id, name, public_key, created_at, seal_key, seal_kid, kind, peer, pending_until)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'phone', ?, ?)`,
    )
      .bind(deviceId, spent.account_id, name, key, now, seal.text, seal.kid, spent.device_id, pendingUntil)
      .run();
  } catch (e) {
    if (String(e).includes("UNIQUE")) {
      await release();
      return keyTaken();
    }
    throw e;
  }
  const sys: SysMessage = {
    kind: "pair",
    pairingId,
    device: deviceId,
    name,
    publicKey: key,
    sealKey: seal.text,
    hello,
    at: now,
  };
  const stub = phoneStub(env, spent.account_id);
  let seq: number | null;
  try {
    seq = await stub.pair({ phone: deviceId, node: spent.device_id, pendingUntil, sys });
  } catch (e) {
    await env.DB.prepare("DELETE FROM devices WHERE id = ?").bind(deviceId).run();
    await release();
    // The object may have stored the phone before failing: revoke it there too (its node, if it
    // heard of the phone, hears it go). Best effort: the phone's pending time ends it anyway.
    try {
      await stub.revokePhone(deviceId, spent.device_id, true);
    } catch {
      console.error("phone pairing rollback: the phone object was unreachable");
    }
    throw e;
  }
  if (seq === null) {
    // The node was revoked after the D1 check above: the pairing stays spent.
    await env.DB.prepare("DELETE FROM devices WHERE id = ?").bind(deviceId).run();
    return invalidCode();
  }
  await accountStub(env, spent.account_id).audit({ kind: "device.added", actor: spent.device_id, subject: deviceId, name });
  return json({ deviceId, node: spent.device_id });
}

/** `POST /v1/phone/devices/<id>/confirm` (the phone's node): the pending phone may now send. */
export async function confirmPhone(env: Env, caller: Caller, phoneId: string): Promise<Response> {
  if (!isId("dev", phoneId)) return notFound();
  const now = Date.now();
  const phone = await env.DB.prepare("SELECT name, kind, peer, pending_until, revoked_at FROM devices WHERE id = ? AND account_id = ?")
    .bind(phoneId, caller.accountId)
    .first<{ name: string; kind: string; peer: string | null; pending_until: number | null; revoked_at: number | null }>();
  if (
    !phone ||
    phone.kind !== "phone" ||
    phone.peer !== caller.deviceId ||
    phone.revoked_at !== null ||
    phone.pending_until === null ||
    phone.pending_until <= now
  ) {
    return notFound();
  }
  // The PhoneObject first (it is what lets the phone send), then D1: a retry after a failure in
  // between still finds the phone pending in D1 and finishes.
  if (!(await phoneStub(env, caller.accountId).confirm(phoneId, caller.deviceId))) return notFound();
  await env.DB.prepare("UPDATE devices SET pending_until = NULL WHERE id = ? AND revoked_at IS NULL").bind(phoneId).run();
  await accountStub(env, caller.accountId).audit({ kind: "phone.confirmed", actor: caller.deviceId, subject: phoneId, name: phone.name });
  return json({ device: phoneId, active: true });
}

/** `GET /v1/phone/devices` (a node device): the account's phones, with presence. */
export async function listPhones(env: Env, caller: Caller): Promise<Response> {
  const now = Date.now();
  const { results } = await env.DB.prepare(
    `SELECT id, name, peer, created_at, last_seen_at, pending_until FROM devices
     WHERE account_id = ? AND kind = 'phone' AND revoked_at IS NULL AND (pending_until IS NULL OR pending_until > ?)
     ORDER BY created_at, id`,
  )
    .bind(caller.accountId, now)
    .all<{ id: string; name: string; peer: string; created_at: number; last_seen_at: number | null; pending_until: number | null }>();
  const presence = results.length > 0 ? await phoneStub(env, caller.accountId).presence(results.map((r) => r.id)) : [];
  return json({
    phones: results.map((r, i) => ({
      id: r.id,
      name: r.name,
      peer: r.peer,
      createdAt: r.created_at,
      lastSeenAt: r.last_seen_at,
      pending: r.pending_until !== null,
      online: presence[i]?.online ?? false,
    })),
  });
}

/** `DELETE /v1/phone/self` (a phone, pending or not): it unpairs itself; its node is told. */
export async function unpairSelf(env: Env, caller: Caller): Promise<Response> {
  const row = await env.DB.prepare("SELECT name FROM devices WHERE id = ?").bind(caller.deviceId).first<{ name: string }>();
  await revokePhone(env, caller.accountId, caller.deviceId, { id: caller.deviceId, name: row?.name ?? "", peer: caller.peer ?? "" });
  return new Response(null, { status: 204 });
}

/**
 * `GET /v1/phone/socket` (a node device or a phone, signed): the Worker has authenticated it; the
 * upgrade goes to the account's PhoneObject, whose 101 answer (with the socket) goes to the client.
 */
export async function openPhoneSocket(env: Env, caller: Caller): Promise<Response> {
  const params = new URLSearchParams({ device: caller.deviceId, role: caller.kind === "phone" ? "phone" : "node" });
  const res = await phoneStub(env, caller.accountId).fetch(`https://phone/socket?${params}`, { headers: { Upgrade: "websocket" } });
  if (res.status !== 101 || !res.webSocket) {
    if (res.status === 401) throw new HttpError(error(401, "unauthorized", "The request isn't signed by a known device."));
    throw new HttpError(error(403, "forbidden", "This device can't open a phone socket."));
  }
  return res;
}
