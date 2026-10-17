// API keys (PLAN §4.3, PROTOCOL §9): for management and CI, never for the stream. A key is shown once,
// stored as a salted, peppered hash, limited to its scopes, and expires. Only a device may create,
// list or revoke keys, open the stream, acknowledge, enrol a device or set a sealing key, so a
// stolen key can never become a reader of the account's events.

import { accountStub, type Caller, type Principal } from "./auth.ts";
import { constantTimeEqualStrings, isId, newId, randomBytes, toBase64Url } from "./encoding.ts";
import { HttpError, error, forbidden, invalid, json, notFound, parseJsonObject } from "./http.ts";
import { pepperedHash } from "./seal.ts";

export const SCOPES = ["hooks:read", "hooks:write", "events:read", "devices:write", "audit:read"] as const;
export type Scope = (typeof SCOPES)[number];

export const DEFAULT_KEY_DAYS = 90;
export const MAX_KEY_DAYS = 365;
/** `lastUsedAt` is refreshed at most this often. */
const LAST_USED_EVERY_MS = 60_000;

/** `hk_` + the key id's 26 characters + `_` + 32 random bytes in base64url (43 characters). */
const TOKEN = /^hk_([0-9a-hjkmnp-tv-z]{26})_([A-Za-z0-9_-]{43})$/;

interface KeyRow {
  id: string;
  account_id: string;
  name: string;
  scopes: string;
  salt: string;
  hash: string;
  created_at: number;
  created_by: string;
  expires_at: number;
  last_used_at: number | null;
  revoked_at: number | null;
}

function keyJson(r: KeyRow) {
  return {
    id: r.id,
    name: r.name,
    scopes: JSON.parse(r.scopes) as Scope[],
    createdAt: r.created_at,
    createdBy: r.created_by,
    expiresAt: r.expires_at,
    lastUsedAt: r.last_used_at,
  };
}

async function tokenHash(env: Env, salt: string, secret: string): Promise<string> {
  return pepperedHash(env.HASH_PEPPER, `apikey:${salt}:${secret}`);
}

/** Whether a request presents an API key rather than a device signature. */
export function presentsKey(request: Request): boolean {
  if (request.headers.has("X-00h-Device")) return false;
  return /^Bearer hk_/i.test(request.headers.get("Authorization") ?? "");
}

/**
 * Checks an API key and that it carries `scope`; throws a 401 (unknown, wrong, revoked or expired:
 * never saying which) or a 403 (the scope is missing).
 */
export async function authenticateKey(request: Request, env: Env, ctx: ExecutionContext, scope: Scope): Promise<Principal> {
  const auth = request.headers.get("Authorization") ?? "";
  const m = TOKEN.exec(auth.slice("Bearer ".length).trim());
  const refuse = () => new HttpError(error(401, "unauthorized", "That API key isn't valid, or has expired or been revoked."));
  if (!m) throw refuse();
  const id = `key_${m[1]}`;
  const row = await env.DB.prepare("SELECT * FROM api_keys WHERE id = ?").bind(id).first<KeyRow>();
  // Hash even when there's no row, so timing doesn't say whether the id exists.
  const expected = row ? row.hash : "0".repeat(64);
  const got = await tokenHash(env, row?.salt ?? "none", m[2]!);
  const now = Date.now();
  if (!row || !constantTimeEqualStrings(got, expected) || row.revoked_at !== null || row.expires_at <= now) throw refuse();
  const scopes = JSON.parse(row.scopes) as string[];
  if (!scopes.includes(scope)) throw new HttpError(forbidden(`This API key doesn't have the ${scope} scope.`));
  ctx.waitUntil(accountStub(env, row.account_id).countAudit("key.used", id, row.name).catch(() => {}));
  if (row.last_used_at === null || now - row.last_used_at > LAST_USED_EVERY_MS) {
    ctx.waitUntil(env.DB.prepare("UPDATE api_keys SET last_used_at = ? WHERE id = ?").bind(now, id).run());
  }
  return { accountId: row.account_id, deviceId: null, keyId: id, actor: id };
}

/** Refuses an API key on a route only a device may use. */
export function deviceOnly(): never {
  throw new HttpError(forbidden("Only a device can do this; API keys are for managing hooks and reading metadata."));
}

export async function createKey(env: Env, caller: Caller, body: Uint8Array): Promise<Response> {
  const input = parseJsonObject(body);
  const name = input.name;
  if (typeof name !== "string" || name.trim().length < 1 || name.trim().length > 100) {
    throw new HttpError(invalid("name", "name must be 1 to 100 characters."));
  }
  const scopes = input.scopes;
  if (
    !Array.isArray(scopes) ||
    scopes.length === 0 ||
    !scopes.every((s) => typeof s === "string" && (SCOPES as readonly string[]).includes(s))
  ) {
    throw new HttpError(invalid("scopes", `scopes must be a non-empty list of ${SCOPES.join(", ")}.`));
  }
  const days = input.expiresInDays ?? DEFAULT_KEY_DAYS;
  if (typeof days !== "number" || !Number.isInteger(days) || days < 1 || days > MAX_KEY_DAYS) {
    throw new HttpError(invalid("expiresInDays", `expiresInDays must be a whole number from 1 to ${MAX_KEY_DAYS}.`));
  }
  const id = newId("key");
  const secret = toBase64Url(randomBytes(32));
  const salt = toBase64Url(randomBytes(16));
  const now = Date.now();
  const unique = [...new Set(scopes as string[])];
  await env.DB.prepare(
    `INSERT INTO api_keys (id, account_id, name, scopes, salt, hash, created_at, created_by, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(id, caller.accountId, name.trim(), JSON.stringify(unique), salt, await tokenHash(env, salt, secret), now, caller.deviceId, now + days * 86_400_000)
    .run();
  await accountStub(env, caller.accountId).audit({ kind: "key.created", actor: caller.deviceId, subject: id, name: name.trim() });
  const row = await env.DB.prepare("SELECT * FROM api_keys WHERE id = ?").bind(id).first<KeyRow>();
  // The token appears here only; the relay keeps only its hash.
  return json({ key: keyJson(row!), token: `hk_${id.slice("key_".length)}_${secret}` }, 201);
}

export async function listKeys(env: Env, caller: Caller): Promise<Response> {
  const { results } = await env.DB.prepare(
    "SELECT * FROM api_keys WHERE account_id = ? AND revoked_at IS NULL ORDER BY created_at, id",
  )
    .bind(caller.accountId)
    .all<KeyRow>();
  return json({ keys: results.map(keyJson) });
}

/** Revokes a key, idempotently: revoking one already revoked answers 204 again. */
export async function revokeKey(env: Env, caller: Caller, id: string): Promise<Response> {
  if (!isId("key", id)) return notFound();
  const row = await env.DB.prepare("SELECT * FROM api_keys WHERE id = ? AND account_id = ?").bind(id, caller.accountId).first<KeyRow>();
  if (!row) return notFound();
  if (row.revoked_at === null) {
    await env.DB.prepare("UPDATE api_keys SET revoked_at = ? WHERE id = ?").bind(Date.now(), id).run();
    await accountStub(env, caller.accountId).audit({ kind: "key.revoked", actor: caller.deviceId, subject: id, name: row.name });
  }
  return new Response(null, { status: 204 });
}
