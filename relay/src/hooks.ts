// Hooks (PROTOCOL §3). A hook's signing secret is shown once, in the create or rotate response, and
// is otherwise only ever held sealed.

import type { Caller } from "./auth.ts";
import { newId } from "./encoding.ts";
import { HttpError, error, invalid, json, notFound, parseJsonObject } from "./http.ts";
import { generateSecret, parseVerify, presetTakesSecret, type VerifyConfig } from "./presets.ts";
import { openSecret, sealSecret } from "./seal.ts";

export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
/** Phase 0 keeps bodies in the object's SQLite rows (2 MB each at most), so stay under that. */
export const MAX_BODY_BYTES_LIMIT = 1_835_008;
/** After a rotation the previous secret keeps verifying for this long. */
export const ROTATION_OVERLAP_MS = 24 * 3600_000;

export interface HookRow {
  id: string;
  account_id: string;
  name: string;
  enabled: number;
  verify: string;
  secret_sealed: string | null;
  previous_secret_sealed: string | null;
  previous_secret_until: number | null;
  max_body_bytes: number;
  created_at: number;
  last_event_at: number | null;
}

export function hookUrl(origin: string, id: string): string {
  return `${origin}/h/${id}`;
}

export function hookJson(row: HookRow, origin: string) {
  return {
    id: row.id,
    name: row.name,
    url: hookUrl(origin, row.id),
    enabled: row.enabled === 1,
    verify: JSON.parse(row.verify) as VerifyConfig,
    maxBodyBytes: row.max_body_bytes,
    createdAt: row.created_at,
    lastEventAt: row.last_event_at,
  };
}

/** Every secret that verifies right now: the current one, and the previous one during the overlap. */
export async function currentSecrets(env: Env, row: HookRow, now: number): Promise<string[]> {
  const out: string[] = [];
  if (row.secret_sealed) out.push(await openSecret(env.SECRETS_KEY, row.id, row.secret_sealed));
  if (row.previous_secret_sealed && (row.previous_secret_until ?? 0) > now) {
    out.push(await openSecret(env.SECRETS_KEY, row.id, row.previous_secret_sealed));
  }
  return out;
}

function hookName(v: unknown): string {
  if (typeof v !== "string" || v.trim().length < 1 || v.trim().length > 100) {
    throw new HttpError(invalid("name", "name must be 1 to 100 characters."));
  }
  return v.trim();
}

async function load(env: Env, caller: Caller, id: string): Promise<HookRow> {
  const row = await env.DB.prepare("SELECT * FROM hooks WHERE id = ? AND account_id = ?").bind(id, caller.accountId).first<HookRow>();
  if (!row) throw new HttpError(notFound());
  return row;
}

export async function createHook(env: Env, caller: Caller, origin: string, body: Uint8Array): Promise<Response> {
  const input = parseJsonObject(body);
  const name = hookName(input.name);
  const { config, secret: supplied } = parseVerify(input.verify);
  const id = newId("hk");
  const generated = supplied === null && presetTakesSecret(config.preset) ? generateSecret(config.preset) : null;
  const secret = supplied ?? generated;
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO hooks (id, account_id, name, enabled, verify, secret_sealed, max_body_bytes, created_at)
     VALUES (?, ?, ?, 1, ?, ?, ?, ?)`,
  )
    .bind(id, caller.accountId, name, JSON.stringify(config), secret ? await sealSecret(env.SECRETS_KEY, id, secret) : null, DEFAULT_MAX_BODY_BYTES, now)
    .run();
  const row = await load(env, caller, id);
  // The secret appears here only when the relay generated it: a caller-supplied one is never echoed.
  return json({ hook: hookJson(row, origin), url: hookUrl(origin, id), ...(generated ? { secret: generated } : {}) }, 201);
}

export async function listHooks(env: Env, caller: Caller, origin: string): Promise<Response> {
  const { results } = await env.DB.prepare("SELECT * FROM hooks WHERE account_id = ? ORDER BY created_at, id")
    .bind(caller.accountId)
    .all<HookRow>();
  return json({ hooks: results.map((r) => hookJson(r, origin)) });
}

export async function getHook(env: Env, caller: Caller, origin: string, id: string): Promise<Response> {
  return json(hookJson(await load(env, caller, id), origin));
}

export async function patchHook(env: Env, caller: Caller, origin: string, id: string, body: Uint8Array): Promise<Response> {
  const row = await load(env, caller, id);
  const input = parseJsonObject(body);
  const name = input.name === undefined ? row.name : hookName(input.name);
  let enabled = row.enabled;
  if (input.enabled !== undefined) {
    if (typeof input.enabled !== "boolean") throw new HttpError(invalid("enabled", "enabled must be true or false."));
    enabled = input.enabled ? 1 : 0;
  }
  let maxBodyBytes = row.max_body_bytes;
  if (input.maxBodyBytes !== undefined) {
    const v = input.maxBodyBytes;
    if (typeof v !== "number" || !Number.isInteger(v) || v < 1 || v > MAX_BODY_BYTES_LIMIT) {
      throw new HttpError(invalid("maxBodyBytes", `maxBodyBytes must be a whole number from 1 to ${MAX_BODY_BYTES_LIMIT}.`));
    }
    maxBodyBytes = v;
  }
  await env.DB.prepare("UPDATE hooks SET name = ?, enabled = ?, max_body_bytes = ? WHERE id = ?")
    .bind(name, enabled, maxBodyBytes, id)
    .run();
  return json(hookJson(await load(env, caller, id), origin));
}

export async function rotateHook(env: Env, caller: Caller, id: string): Promise<Response> {
  const row = await load(env, caller, id);
  const config = JSON.parse(row.verify) as VerifyConfig;
  if (!presetTakesSecret(config.preset) || !row.secret_sealed) {
    return error(409, "conflict", "This hook has no secret to rotate.");
  }
  const secret = generateSecret(config.preset);
  const now = Date.now();
  await env.DB.prepare(
    "UPDATE hooks SET secret_sealed = ?, previous_secret_sealed = ?, previous_secret_until = ? WHERE id = ?",
  )
    .bind(await sealSecret(env.SECRETS_KEY, id, secret), row.secret_sealed, now + ROTATION_OVERLAP_MS, id)
    .run();
  return json({ secret });
}

export async function deleteHook(env: Env, caller: Caller, id: string): Promise<Response> {
  await load(env, caller, id);
  // Events already in the log stay until they're acknowledged (or retention drops them).
  await env.DB.prepare("DELETE FROM hooks WHERE id = ? AND account_id = ?").bind(id, caller.accountId).run();
  return new Response(null, { status: 204 });
}
