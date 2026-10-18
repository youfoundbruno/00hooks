// Signed requests (PROTOCOL §1): Ed25519 over a canonical string, a ±300 s window, and single-use
// nonces spent in the account's Durable Object (GET requests too).

import type { AccountObject } from "./account-object.ts";
import type { PhoneObject } from "./phone-object.ts";
import {
  HEADER_DEVICE,
  HEADER_NONCE,
  HEADER_SIGNATURE,
  HEADER_TIME,
  bodyHash,
  canonicalString,
  importPublicKey,
  isUnpaddedBase64Url,
} from "./canonical.ts";
import { fromBase64, isId, utf8 } from "./encoding.ts";
import { HttpError, error, unauthorized } from "./http.ts";

export const CLOCK_WINDOW_MS = 300_000;
/** `lastSeenAt` is refreshed at most this often, so reads don't each cost a write. */
const LAST_SEEN_EVERY_MS = 60_000;

/** The kinds of device (PROTOCOL §10): a phone may use only the phone routes. */
export type DeviceKind = "device" | "phone";

/**
 * A signed request from a device. A device of kind `device` may do everything its account may; a
 * phone only what the phone routes allow (index.ts refuses it everywhere else).
 */
export interface Caller {
  accountId: string;
  deviceId: string;
  kind: DeviceKind;
  /** A phone's node; null for a device. */
  peer: string | null;
  /** Set while a phone waits for its node to confirm it; null once confirmed, and for a device. */
  pendingUntil: number | null;
}

/**
 * Who made a management request: a device (signed), or an API key (PROTOCOL §9) limited to its
 * scopes. `actor` is the device or key id the audit log names.
 */
export interface Principal {
  accountId: string;
  /** Null for an API key. */
  deviceId: string | null;
  keyId: string | null;
  actor: string;
  /** An API key's scopes; null for a device, which may do everything its account may. */
  scopes: readonly string[] | null;
}

export function deviceAsPrincipal(c: Caller): Principal {
  return { accountId: c.accountId, deviceId: c.deviceId, keyId: null, actor: c.deviceId, scopes: null };
}

/**
 * Whether a caller may be shown a hook's secret (PROTOCOL §9): a device, or an API key with the
 * `hooks:secrets` scope. `hooks:write` alone never returns a secret, so a leaked CI key can't take
 * over a hook's signing and forge verified events.
 */
export function maySeeSecrets(p: Principal): boolean {
  return p.scopes === null || p.scopes.includes("hooks:secrets");
}

export function phoneStub(env: Env, accountId: string): DurableObjectStub<PhoneObject> {
  const ns = env.PHONE as unknown as DurableObjectNamespace<PhoneObject>;
  return ns.get(ns.idFromName(accountId));
}

export function accountStub(env: Env, accountId: string): DurableObjectStub<AccountObject> {
  const ns = env.ACCOUNT as unknown as DurableObjectNamespace<AccountObject>;
  return ns.get(ns.idFromName(accountId));
}

/**
 * Checks a signed request; throws a 401 answer otherwise. The answer never says which check failed,
 * except `clock_skew`, which carries the server's time so an honest client can correct itself.
 */
export async function authenticate(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  body: Uint8Array<ArrayBuffer>,
): Promise<Caller> {
  const deviceId = request.headers.get(HEADER_DEVICE);
  const time = request.headers.get(HEADER_TIME);
  const nonce = request.headers.get(HEADER_NONCE);
  const signature = request.headers.get(HEADER_SIGNATURE);
  if (!isId("dev", deviceId) || !time || !/^\d{1,16}$/.test(time) || !nonce || !/^[A-Za-z0-9_-]{22}$/.test(nonce) || !signature) {
    throw new HttpError(unauthorized());
  }
  const now = Date.now();
  if (Math.abs(now - Number(time)) > CLOCK_WINDOW_MS) {
    throw new HttpError(
      error(401, "clock_skew", "The request's time is too far from the relay's clock.", { serverTime: now }),
    );
  }
  const device = await env.DB.prepare(
    "SELECT account_id, public_key, last_seen_at, revoked_at, kind, peer, pending_until FROM devices WHERE id = ?",
  )
    .bind(deviceId)
    .first<{
      account_id: string;
      public_key: string;
      last_seen_at: number | null;
      revoked_at: number | null;
      kind: string;
      peer: string | null;
      pending_until: number | null;
    }>();
  if (!device || device.revoked_at !== null) throw new HttpError(unauthorized());
  const kind: DeviceKind = device.kind === "phone" ? "phone" : "device";
  // A pending phone whose pairing ran out is as good as revoked (PROTOCOL §10).
  if (kind === "phone" && device.pending_until !== null && device.pending_until <= now) throw new HttpError(unauthorized());

  // The signature is 64 bytes, unpadded base64url: 86 characters.
  const sig = isUnpaddedBase64Url(signature, 86) ? fromBase64(signature) : null;
  const key = await importPublicKey(device.public_key);
  if (!sig || sig.byteLength !== 64 || !key) throw new HttpError(unauthorized());
  // Built from the URL the relay received: Workers don't rewrite the path or query (PROTOCOL §1).
  const url = new URL(request.url);
  const canonical = canonicalString({
    deviceId,
    host: url.host,
    method: request.method,
    pathAndQuery: url.pathname + url.search,
    time,
    nonce,
    bodySha256: await bodyHash(body),
  });
  // crypto.subtle.verify is the constant-time comparison here.
  const ok = await crypto.subtle.verify("Ed25519", key, sig, utf8(canonical));
  if (!ok) throw new HttpError(unauthorized());

  // Spent only after the signature holds, so unsigned junk can't fill the nonce table. A phone's
  // nonces live in the account's PhoneObject: it is never a device of the webhook log.
  const spent =
    kind === "phone"
      ? await phoneStub(env, device.account_id).spendNonce(deviceId, nonce)
      : await accountStub(env, device.account_id).spendNonce(deviceId, nonce);
  if (!spent) throw new HttpError(unauthorized());

  if (device.last_seen_at === null || now - device.last_seen_at > LAST_SEEN_EVERY_MS) {
    ctx.waitUntil(env.DB.prepare("UPDATE devices SET last_seen_at = ? WHERE id = ?").bind(now, deviceId).run());
  }
  return {
    accountId: device.account_id,
    deviceId,
    kind,
    peer: kind === "phone" ? device.peer : null,
    pendingUntil: kind === "phone" ? device.pending_until : null,
  };
}
