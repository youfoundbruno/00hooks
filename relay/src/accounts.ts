// Accounts, devices and enrolments (PROTOCOL §2).

import { accountStub, type Caller } from "./auth.ts";
import { importPublicKey } from "./canonical.ts";
import { constantTimeEqualStrings, newId, randomBytes } from "./encoding.ts";
import { HttpError, error, invalid, json, notFound, parseJsonObject } from "./http.ts";
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

/** Inserts the device in D1, then registers it with the account's object. */
async function addDevice(env: Env, accountId: string, name: string, key: string, now: number): Promise<string> {
  const deviceId = newId("dev");
  await env.DB.prepare("INSERT INTO devices (id, account_id, name, public_key, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(deviceId, accountId, name, key, now)
    .run();
  await accountStub(env, accountId).addDevice(deviceId);
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
  const now = Date.now();
  const accountId = newId("acc");
  await env.DB.prepare("INSERT INTO accounts (id, created_at) VALUES (?, ?)").bind(accountId, now).run();
  const deviceId = await addDevice(env, accountId, name, key, now);
  return json({ accountId, deviceId }, 201);
}

const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function newCode(): string {
  const bytes = randomBytes(8);
  let s = "";
  // 256 is a multiple of 32, so `% 32` has no bias.
  for (const b of bytes) s += CODE_ALPHABET[b % 32];
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

/** Crockford decoding: case-insensitive, I/L read as 1 and O as 0, dashes and spaces ignored. */
export function normalizeCode(code: string): string | null {
  const s = code.toUpperCase().replace(/[\s-]/g, "").replace(/[IL]/g, "1").replace(/O/g, "0");
  return s.length === 8 && [...s].every((c) => CODE_ALPHABET.includes(c)) ? s : null;
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

export async function redeemEnrolment(request: Request, env: Env, body: Uint8Array): Promise<Response> {
  const now = Date.now();
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const ipHash = await pepperedHash(env.HASH_PEPPER, `ip:${ip}`);
  const throttle = await env.DB.prepare("SELECT window_start, failures, blocked_until FROM enrolment_failures WHERE ip_hash = ?")
    .bind(ipHash)
    .first<{ window_start: number; failures: number; blocked_until: number | null }>();
  if (throttle?.blocked_until && throttle.blocked_until > now) {
    const retryAfter = Math.ceil((throttle.blocked_until - now) / 1000);
    return error(429, "rate_limited", "Too many wrong codes from this address; try again later.", {}, { "Retry-After": String(retryAfter) });
  }

  const input = parseJsonObject(body);
  const name = deviceName(input.deviceName);
  const key = await publicKey(env, input.publicKey);
  const code = typeof input.code === "string" ? normalizeCode(input.code) : null;

  const redeemed = code
    ? await env.DB.prepare(
        "UPDATE enrolments SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ? RETURNING account_id",
      )
        .bind(now, await pepperedHash(env.HASH_PEPPER, `enrol:${code}`), now)
        .first<{ account_id: string }>()
    : null;

  if (!redeemed) {
    const fresh = !throttle || now - throttle.window_start > ENROLMENT_WINDOW_MS;
    const failures = fresh ? 1 : throttle.failures + 1;
    const blockedUntil = failures >= ENROLMENT_MAX_FAILURES ? now + ENROLMENT_BLOCK_MS : null;
    await env.DB.prepare(
      `INSERT INTO enrolment_failures (ip_hash, window_start, failures, blocked_until) VALUES (?, ?, ?, ?)
       ON CONFLICT(ip_hash) DO UPDATE SET window_start = excluded.window_start, failures = excluded.failures,
         blocked_until = excluded.blocked_until`,
    )
      .bind(ipHash, fresh ? now : throttle.window_start, failures, blockedUntil)
      .run();
    return error(401, "unauthorized", "That enrolment code isn't valid, or has expired.");
  }

  const deviceId = await addDevice(env, redeemed.account_id, name, key, now);
  return json({ accountId: redeemed.account_id, deviceId });
}

export async function listDevices(env: Env, caller: Caller): Promise<Response> {
  const { results } = await env.DB.prepare(
    "SELECT id, name, created_at, last_seen_at FROM devices WHERE account_id = ? AND revoked_at IS NULL ORDER BY created_at, id",
  )
    .bind(caller.accountId)
    .all<{ id: string; name: string; created_at: number; last_seen_at: number | null }>();
  return json({
    devices: results.map((d) => ({
      id: d.id,
      name: d.name,
      createdAt: d.created_at,
      lastSeenAt: d.last_seen_at,
      current: d.id === caller.deviceId,
    })),
  });
}

export async function revokeDevice(env: Env, caller: Caller, deviceId: string): Promise<Response> {
  const res = await env.DB.prepare(
    "UPDATE devices SET revoked_at = ? WHERE id = ? AND account_id = ? AND revoked_at IS NULL",
  )
    .bind(Date.now(), deviceId, caller.accountId)
    .run();
  if (!res.meta.changes) return notFound();
  await accountStub(env, caller.accountId).revokeDevice(deviceId);
  return new Response(null, { status: 204 });
}

