// Accounts, devices and enrolments (PROTOCOL §2).

import { accountStub, type Caller, type Principal } from "./auth.ts";
import { importPublicKey } from "./canonical.ts";
import { constantTimeEqualStrings, newId, randomBytes } from "./encoding.ts";
import { parseSealKey, sealKid, sealTo } from "./envelope.ts";
import { HttpError, error, invalid, json, notFound, parseJsonObject, unavailable } from "./http.ts";
import { clientKey } from "./ip.ts";
import { pepperedHash } from "./seal.ts";

export const ENROLMENT_TTL_MS = 10 * 60_000;
export const ENROLMENT_MAX_FAILURES = 5;
export const ENROLMENT_WINDOW_MS = 10 * 60_000;
export const ENROLMENT_BLOCK_MS = 10 * 60_000;

function deviceName(v: unknown): string {
  if (typeof v !== "string" || v.trim().length < 1 || v.trim().length > 100) {
    throw new HttpError(invalid("deviceName", "deviceName must be 1 to 100 characters."));
  }
  return v.trim();
}

async function publicKey(env: Env, v: unknown): Promise<string> {
  if (typeof v !== "string" || !(await importPublicKey(v))) {
    throw new HttpError(invalid("publicKey", "publicKey must be a raw Ed25519 public key in base64url."));
  }
  const taken = await env.DB.prepare("SELECT 1 AS x FROM devices WHERE public_key = ?").bind(v).first();
  if (taken) throw new HttpError(error(409, "conflict", "That public key already belongs to a device."));
  return v;
}

/** A device's sealing key (PROTOCOL §2): optional, so a client that has none can still join. */
async function sealKeyField(v: unknown): Promise<{ text: string; raw: Uint8Array; kid: string } | null> {
  if (v === undefined || v === null) return null;
  const raw = parseSealKey(v);
  const bad = () => new HttpError(invalid("sealKey", "sealKey must be a raw X25519 public key in base64url."));
  if (!raw) throw bad();
  // A trial seal: a low-order point (whose shared secret is all zeros) is refused here, not at the
  // first delivery.
  try {
    await sealTo(raw, new Uint8Array(0), new Uint8Array(0));
  } catch {
    throw bad();
  }
  return { text: v as string, raw, kid: await sealKid(raw) };
}

/** Inserts the device in D1, then registers it (and its sealing key) with the account's object. */
async function addDevice(
  env: Env,
  accountId: string,
  name: string,
  key: string,
  seal: { text: string; raw: Uint8Array; kid: string } | null,
  now: number,
  actor: string | null,
): Promise<string> {
  const deviceId = newId("dev");
  await env.DB.prepare(
    "INSERT INTO devices (id, account_id, name, public_key, created_at, seal_key, seal_kid) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(deviceId, accountId, name, key, now, seal?.text ?? null, seal?.kid ?? null)
    .run();
  const stub = accountStub(env, accountId);
  await stub.addDevice(deviceId, seal ? { key: seal.raw, kid: seal.kid } : undefined);
  await stub.audit({ kind: "device.added", actor: actor ?? deviceId, subject: deviceId, name });
  return deviceId;
}

export async function createAccount(request: Request, env: Env, body: Uint8Array): Promise<Response> {
  if (env.SIGNUP_TOKEN) {
    const auth = request.headers.get("Authorization") ?? "";
    if (!constantTimeEqualStrings(auth, `Bearer ${env.SIGNUP_TOKEN}`)) {
      return error(401, "unauthorized", "Signing up on this relay needs its signup token.");
    }
  }
  const input = parseJsonObject(body);
  const name = deviceName(input.deviceName);
  const key = await publicKey(env, input.publicKey);
  const seal = await sealKeyField(input.sealKey);
  const now = Date.now();
  const accountId = newId("acc");
  await env.DB.prepare("INSERT INTO accounts (id, created_at) VALUES (?, ?)").bind(accountId, now).run();
  const deviceId = await addDevice(env, accountId, name, key, seal, now, null);
  return json({ accountId, deviceId }, 201);
}

const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** Characters in an enrolment code: 12 Crockford base32 characters are 60 bits. */
export const CODE_CHARS = 12;

/** A one-time code: 60 random bits, written `XXXX-XXXX-XXXX`. */
export function newCode(): string {
  const bytes = randomBytes(CODE_CHARS);
  let s = "";
  // 256 is a multiple of 32, so `% 32` has no bias.
  for (const b of bytes) s += CODE_ALPHABET[b % 32];
  return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8)}`;
}

/** Crockford decoding: case-insensitive, I/L read as 1 and O as 0, dashes and spaces ignored. */
export function normalizeCode(code: string): string | null {
  const s = code.toUpperCase().replace(/[\s-]/g, "").replace(/[IL]/g, "1").replace(/O/g, "0");
  return s.length === CODE_CHARS && [...s].every((c) => CODE_ALPHABET.includes(c)) ? s : null;
}

export async function createEnrolment(env: Env, caller: Caller): Promise<Response> {
  const code = newCode();
  const now = Date.now();
  const expiresAt = now + ENROLMENT_TTL_MS;
  await env.DB.prepare(
    "INSERT INTO enrolments (id, account_id, code_hash, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
  )
    .bind(newId("enr"), caller.accountId, await pepperedHash(env.HASH_PEPPER, `enrol:${normalizeCode(code)}`), caller.deviceId, now, expiresAt)
    .run();
  return json({ code, expiresAt });
}

/**
 * Counts one redemption attempt from `ipHash`, atomically, before the code is looked at: one D1
 * statement increments the window's count and starts a block once it passes the limit, so parallel
 * guesses each count. Returns when the address is blocked until, or null when this attempt may go on.
 */
async function countAttempt(env: Env, ipHash: string, now: number): Promise<number | null> {
  const row = await env.DB.prepare(
    `INSERT INTO enrolment_failures (ip_hash, window_start, failures, blocked_until) VALUES (?1, ?2, 1, NULL)
     ON CONFLICT(ip_hash) DO UPDATE SET
       window_start = CASE WHEN ?2 - window_start > ?3 AND coalesce(blocked_until, 0) <= ?2 THEN ?2 ELSE window_start END,
       failures = CASE WHEN ?2 - window_start > ?3 AND coalesce(blocked_until, 0) <= ?2 THEN 1 ELSE failures + 1 END,
       blocked_until = CASE
         WHEN coalesce(blocked_until, 0) > ?2 THEN blocked_until
         WHEN ?2 - window_start > ?3 THEN NULL
         WHEN failures + 1 > ?4 THEN ?2 + ?5
         ELSE NULL END
     RETURNING failures, blocked_until`,
  )
    .bind(ipHash, now, ENROLMENT_WINDOW_MS, ENROLMENT_MAX_FAILURES, ENROLMENT_BLOCK_MS)
    .first<{ failures: number; blocked_until: number | null }>();
  if (row?.blocked_until && row.blocked_until > now) return row.blocked_until;
  return null;
}

export async function redeemEnrolment(request: Request, env: Env, body: Uint8Array): Promise<Response> {
  // Fail closed: these are what make guessing codes slow.
  if (!env.REDEEM_IP_LIMIT || !env.REDEEM_GLOBAL_LIMIT) return unavailable();
  const ip = clientKey(request);
  const limited = (retryAfter: number) =>
    error(429, "rate_limited", "Too many enrolment attempts; try again later.", {}, { "Retry-After": String(retryAfter) });
  if (!(await env.REDEEM_GLOBAL_LIMIT.limit({ key: "global" })).success) return limited(60);
  if (!(await env.REDEEM_IP_LIMIT.limit({ key: ip })).success) return limited(60);

  const input = parseJsonObject(body);
  const name = deviceName(input.deviceName);
  const key = await publicKey(env, input.publicKey);
  const seal = await sealKeyField(input.sealKey);
  const code = typeof input.code === "string" ? normalizeCode(input.code) : null;

  const now = Date.now();
  const ipHash = await pepperedHash(env.HASH_PEPPER, `ip:${ip}`);
  const blockedUntil = await countAttempt(env, ipHash, now);
  if (blockedUntil !== null) return limited(Math.ceil((blockedUntil - now) / 1000));

  const redeemed = code
    ? await env.DB.prepare(
        "UPDATE enrolments SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ? RETURNING account_id, created_by",
      )
        .bind(now, await pepperedHash(env.HASH_PEPPER, `enrol:${code}`), now)
        .first<{ account_id: string; created_by: string }>()
    : null;
  if (!redeemed) return error(401, "unauthorized", "That enrolment code isn't valid, or has expired.");

  // A right code doesn't count against the address.
  await env.DB.prepare("UPDATE enrolment_failures SET failures = max(failures - 1, 0) WHERE ip_hash = ?").bind(ipHash).run();
  // The audit names the device that issued the code as the one that added this device.
  const deviceId = await addDevice(env, redeemed.account_id, name, key, seal, now, redeemed.created_by);
  return json({ accountId: redeemed.account_id, deviceId });
}

export async function listDevices(env: Env, caller: Principal): Promise<Response> {
  const { results } = await env.DB.prepare(
    "SELECT id, name, created_at, last_seen_at, seal_kid FROM devices WHERE account_id = ? AND revoked_at IS NULL ORDER BY created_at, id",
  )
    .bind(caller.accountId)
    .all<{ id: string; name: string; created_at: number; last_seen_at: number | null; seal_kid: string | null }>();
  return json({
    devices: results.map((d) => ({
      id: d.id,
      name: d.name,
      createdAt: d.created_at,
      lastSeenAt: d.last_seen_at,
      current: d.id === caller.deviceId,
      sealKid: d.seal_kid,
    })),
  });
}

/**
 * `PUT /v1/devices/<id>/seal-key`: a device sets (or replaces) its own sealing key. Only the device
 * itself may: a key set by anyone else would let them read what is sealed to it.
 */
export async function putSealKey(env: Env, caller: Caller, deviceId: string, body: Uint8Array): Promise<Response> {
  if (deviceId !== caller.deviceId) {
    return error(403, "forbidden", "A device can set only its own sealing key.");
  }
  const input = parseJsonObject(body);
  const seal = await sealKeyField(input.sealKey);
  if (!seal) throw new HttpError(invalid("sealKey", "sealKey must be a raw X25519 public key in base64url."));
  await env.DB.prepare("UPDATE devices SET seal_key = ?, seal_kid = ? WHERE id = ?").bind(seal.text, seal.kid, deviceId).run();
  const stub = accountStub(env, caller.accountId);
  await stub.setSealKey(deviceId, seal.raw, seal.kid);
  await stub.audit({ kind: "device.seal_key", actor: deviceId, subject: deviceId, name: seal.kid });
  return json({ kid: seal.kid });
}

/**
 * Revokes a device, idempotently. The account's Durable Object is the authority (it refuses the
 * device's nonces and closes its stream with 4401), so it is told first, every time, even when D1
 * already says revoked: a retry after a failure part-way always finishes the job.
 */
export async function revokeDevice(env: Env, caller: Principal, deviceId: string): Promise<Response> {
  const device = await env.DB.prepare("SELECT name, revoked_at FROM devices WHERE id = ? AND account_id = ?")
    .bind(deviceId, caller.accountId)
    .first<{ name: string; revoked_at: number | null }>();
  if (!device) return notFound();
  const stub = accountStub(env, caller.accountId);
  await stub.revokeDevice(deviceId);
  await env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").bind(Date.now(), deviceId).run();
  if (device.revoked_at === null) await stub.audit({ kind: "device.revoked", actor: caller.actor, subject: deviceId, name: device.name });
  return new Response(null, { status: 204 });
}

