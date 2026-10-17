// Signed requests (PROTOCOL §1): Ed25519 over a canonical string, a ±300 s window, and single-use
// nonces spent in the account's Durable Object (GET requests too).

import type { AccountObject } from "./account-object.ts";
import {
  HEADER_DEVICE,
  HEADER_NONCE,
  HEADER_SIGNATURE,
  HEADER_TIME,
  bodyHash,
  canonicalString,
  importPublicKey,
} from "./canonical.ts";
import { fromBase64, isId, utf8 } from "./encoding.ts";
import { HttpError, error, unauthorized } from "./http.ts";

export const CLOCK_WINDOW_MS = 300_000;
/** `lastSeenAt` is refreshed at most this often, so reads don't each cost a write. */
const LAST_SEEN_EVERY_MS = 60_000;

export interface Caller {
  accountId: string;
  deviceId: string;
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
  const device = await env.DB.prepare("SELECT account_id, public_key, last_seen_at, revoked_at FROM devices WHERE id = ?")
    .bind(deviceId)
    .first<{ account_id: string; public_key: string; last_seen_at: number | null; revoked_at: number | null }>();
  if (!device || device.revoked_at !== null) throw new HttpError(unauthorized());

  const sig = fromBase64(signature);
  const key = await importPublicKey(device.public_key);
  if (!sig || sig.byteLength !== 64 || !key) throw new HttpError(unauthorized());
  const url = new URL(request.url);
  const canonical = canonicalString({
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

  // Spent only after the signature holds, so unsigned junk can't fill the nonce table.
  if (!(await accountStub(env, device.account_id).spendNonce(deviceId, nonce))) throw new HttpError(unauthorized());

  if (device.last_seen_at === null || now - device.last_seen_at > LAST_SEEN_EVERY_MS) {
    ctx.waitUntil(env.DB.prepare("UPDATE devices SET last_seen_at = ? WHERE id = ?").bind(now, deviceId).run());
  }
  return { accountId: device.account_id, deviceId };
}
