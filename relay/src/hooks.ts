// Hooks (PROTOCOL §3). A hook's signing secret is shown once, in the create or rotate response, and
// is otherwise only ever held sealed.

import { accountStub, maySeeSecrets, type Principal } from "./auth.ts";
import { newId } from "./encoding.ts";
import { HttpError, error, forbidden, invalid, json, notFound, parseJsonObject } from "./http.ts";
import {
  generateSecret,
  generateVerifyToken,
  parseOfflineNotice,
  parseVerify,
  presetTakesSecret,
  relayGeneratesSecret,
  SPECS,
  type OfflineNotice,
  type VerifyConfig,
} from "./presets.ts";
import { openSecret, pepperedHash, sealSecret } from "./seal.ts";
import { parseScreen, type EdgeScreen } from "./screen.ts";
import { parseDeliverTo, parseStaticResponse, staticResponseOf } from "./hook-delivery.ts";
import { resolvePlan, secondsToMidnight, type AccountPlanColumns, type ResolvedPlan } from "./plans.ts";
import { utcDay } from "./account-object.ts";

/** An account's plan right now (one D1 read): for management routes, never per delivery. */
export async function accountPlan(env: Env, accountId: string, now: number): Promise<ResolvedPlan> {
  const row = await env.DB.prepare("SELECT plan, plan_until, limits FROM accounts WHERE id = ?").bind(accountId).first<AccountPlanColumns>();
  return resolvePlan(env, row, now);
}

/** `onLimit` (PROTOCOL §3): what a delivery past the account's daily cap gets. */
function onLimitField(v: unknown): "refuse" | "accept_and_drop" {
  if (v !== "refuse" && v !== "accept_and_drop") {
    throw new HttpError(invalid("onLimit", "onLimit must be refuse or accept_and_drop."));
  }
  return v;
}

export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
/**
 * The default for a strict or unverified hook, which anyone who knows its URL can fill with junk the
 * relay can't tell from deliveries (PROTOCOL §3): a quarter of the verified default. PATCH raises it.
 */
export const UNCHECKED_MAX_BODY_BYTES = 256 * 1024;
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
  /** Meta's verify token, as a keyed hash (HASH_PEPPER): the GET handshake is checked against it. */
  handshake_token_hash: string | null;
  /** The offline notice, as JSON (PROTOCOL §4a), or null. */
  offline_notice: string | null;
  /** The screen's rules, as JSON (PROTOCOL §4b), or null. */
  screen?: string | null;
  /** The one device the hook's events go to (PROTOCOL §3), or null for every device. */
  deliver_to?: string | null;
  /** The static answer for the provider, as JSON (src/hook-delivery.ts), or null. */
  static_response?: string | null;
  /** Paused after a flood of refusals until then (PROTOCOL §4), or null. */
  paused_until: number | null;
  /** What a delivery past the daily cap gets: `refuse` (429) or `accept_and_drop` (200, a gap). */
  on_limit: string;
}

export function screenOf(row: HookRow): EdgeScreen | null {
  if (!row.screen) return null;
  try {
    return JSON.parse(row.screen) as EdgeScreen;
  } catch {
    return null;
  }
}

/** The keyed hash a hook's verify token is kept as. */
export function verifyTokenHash(env: Env, hookId: string, token: string): Promise<string> {
  return pepperedHash(env.HASH_PEPPER, `verify-token:${hookId}:${token}`);
}

export function offlineNoticeOf(row: HookRow): OfflineNotice | null {
  if (!row.offline_notice) return null;
  try {
    return JSON.parse(row.offline_notice) as OfflineNotice;
  } catch {
    return null;
  }
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
    offlineNotice: offlineNoticeOf(row),
    screenRules: screenOf(row)?.rules.length ?? 0,
    deliverTo: row.deliver_to ?? null,
    response: staticResponseOf(row.static_response),
    onLimit: row.on_limit === "accept_and_drop" ? "accept_and_drop" : "refuse",
    pausedUntil: row.paused_until !== null && row.paused_until > Date.now() ? row.paused_until : null,
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

/** Hook names are unique per account (PROTOCOL §3): a second hook can't answer to an existing name. */
const nameTaken = () => new HttpError(error(409, "conflict", "This account already has a hook with that name."));

async function assertNameFree(env: Env, accountId: string, name: string, except: string | null): Promise<void> {
  const row = await env.DB.prepare("SELECT id FROM hooks WHERE account_id = ? AND name = ?").bind(accountId, name).first<{ id: string }>();
  if (row && row.id !== except) throw nameTaken();
}

/** Maps a lost race on the unique (account, name) index to the same 409. */
function uniqueName(e: unknown): never {
  if (e instanceof Error && /UNIQUE constraint failed: hooks\.account_id, hooks\.name/.test(e.message)) throw nameTaken();
  throw e;
}

async function load(env: Env, caller: Principal, id: string): Promise<HookRow> {
  const row = await env.DB.prepare("SELECT * FROM hooks WHERE id = ? AND account_id = ?").bind(id, caller.accountId).first<HookRow>();
  if (!row) throw new HttpError(notFound());
  return row;
}

export async function createHook(env: Env, caller: Principal, origin: string, body: Uint8Array): Promise<Response> {
  const input = parseJsonObject(body);
  const name = hookName(input.name);
  const { config, secret: supplied, verifyToken: suppliedToken } = parseVerify(input.verify);
  const notice = input.offlineNotice === undefined ? null : parseOfflineNotice(input.offlineNotice, config.preset);
  const onLimit = input.onLimit === undefined ? "refuse" : onLimitField(input.onLimit);
  const id = newId("hk");
  // Meta's GET handshake needs a verify token: the caller's, or one made here and shown once.
  const generatedToken = SPECS[config.preset].getHandshake && suppliedToken === null ? generateVerifyToken() : null;
  const token = suppliedToken ?? generatedToken;
  // A strict hook's secret stays on the devices; a provider-issued one was checked to be supplied.
  const generated =
    supplied === null && presetTakesSecret(config.preset, config.strict) && relayGeneratesSecret(config.preset)
      ? generateSecret(config.preset)
      : null;
  const secret = supplied ?? generated;
  // Only a device or a `hooks:secrets` key is ever shown a secret: refuse before anything is made.
  if ((generated || generatedToken) && !maySeeSecrets(caller)) {
    throw new HttpError(
      forbidden("This hook's secret is generated by the relay and shown once: creating it needs a device or the hooks:secrets scope."),
    );
  }
  await assertNameFree(env, caller.accountId, name, null);
  // Junk a sender can pass the edge checks with costs less storage on hooks the relay can't verify.
  const unchecked = config.strict === true || SPECS[config.preset].mac === "none";
  const now = Date.now();
  const plan = await accountPlan(env, caller.accountId, now);
  const day = utcDay(now);
  // The plan's hook cap and daily creations are checked in the insert itself, as the device cap is
  // (PROTOCOL §3): two creations racing can't both take the last place. The day's count goes up in
  // the same transaction, only when the hook was made.
  const [inserted] = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO hooks (id, account_id, name, enabled, verify, secret_sealed, max_body_bytes, created_at,
         handshake_token_hash, offline_notice, on_limit)
       SELECT ?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, ?9, ?10
       WHERE (?11 IS NULL OR (SELECT count(*) FROM hooks WHERE account_id = ?2) < ?11)
         AND (?12 IS NULL OR coalesce((SELECT count FROM hook_creates WHERE account_id = ?2 AND day = ?13), 0) < ?12)`,
    ).bind(
      id,
      caller.accountId,
      name,
      JSON.stringify(config),
      secret ? await sealSecret(env.SECRETS_KEY, id, secret) : null,
      unchecked ? UNCHECKED_MAX_BODY_BYTES : DEFAULT_MAX_BODY_BYTES,
      now,
      token ? await verifyTokenHash(env, id, token) : null,
      notice ? JSON.stringify(notice) : null,
      onLimit,
      plan.limits.hooks,
      plan.limits.hookCreatesPerDay,
      day,
    ),
    env.DB.prepare(
      `INSERT INTO hook_creates (account_id, day, count) SELECT ?1, ?2, 1 WHERE EXISTS (SELECT 1 FROM hooks WHERE id = ?3)
       ON CONFLICT(account_id, day) DO UPDATE SET count = count + 1`,
    ).bind(caller.accountId, day, id),
  ]).catch(uniqueName);
  if (!inserted || inserted.meta.changes === 0) {
    const n = await env.DB.prepare("SELECT count(*) AS n FROM hooks WHERE account_id = ?").bind(caller.accountId).first<{ n: number }>();
    if (plan.limits.hooks !== null && (n?.n ?? 0) >= plan.limits.hooks) {
      throw new HttpError(
        error(409, "conflict", "This account has as many hooks as its plan allows; delete one before adding another.", {
          scope: "hooks",
          limit: plan.limits.hooks,
        }),
      );
    }
    throw new HttpError(
      error(
        429,
        "rate_limited",
        "This account has created as many hooks today as its plan allows; try again after midnight UTC.",
        { scope: "hook_creates", limit: plan.limits.hookCreatesPerDay },
        { "Retry-After": String(secondsToMidnight(now)) },
      ),
    );
  }
  await accountStub(env, caller.accountId).hookChanged({ kind: "hook.created", hookId: id, name, actor: caller.actor });
  const row = await load(env, caller, id);
  // The secret appears here only when the relay generated it: a caller-supplied one is never echoed.
  return json(
    {
      hook: hookJson(row, origin),
      url: hookUrl(origin, id),
      ...(generated ? { secret: generated } : {}),
      ...(generatedToken ? { verifyToken: generatedToken } : {}),
    },
    201,
  );
}

export async function listHooks(env: Env, caller: Principal, origin: string): Promise<Response> {
  const { results } = await env.DB.prepare("SELECT * FROM hooks WHERE account_id = ? ORDER BY created_at, id")
    .bind(caller.accountId)
    .all<HookRow>();
  return json({ hooks: results.map((r) => hookJson(r, origin)) });
}

export async function getHook(env: Env, caller: Principal, origin: string, id: string): Promise<Response> {
  return json(hookJson(await load(env, caller, id), origin));
}

export async function patchHook(env: Env, caller: Principal, origin: string, id: string, body: Uint8Array): Promise<Response> {
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
  const onLimit = input.onLimit === undefined ? row.on_limit : onLimitField(input.onLimit);
  // `enabled: true` also lifts a pause (PROTOCOL §3): the device saw the flood and wants the hook back.
  const unpause = input.enabled === true && row.paused_until !== null && row.paused_until > Date.now();
  let notice = row.offline_notice;
  if (input.offlineNotice !== undefined) {
    const parsed = parseOfflineNotice(input.offlineNotice, (JSON.parse(row.verify) as VerifyConfig).preset);
    notice = parsed ? JSON.stringify(parsed) : null;
  }
  // Who receives the hook's events, and what the provider is answered (src/hook-delivery.ts).
  const deliverTo = input.deliverTo === undefined ? (row.deliver_to ?? null) : await parseDeliverTo(env, caller.accountId, input.deliverTo);
  let response = row.static_response ?? null;
  if (input.response !== undefined) {
    const parsed = parseStaticResponse(input.response, (JSON.parse(row.verify) as VerifyConfig).preset);
    response = parsed ? JSON.stringify(parsed) : null;
  }
  if (name !== row.name) await assertNameFree(env, caller.accountId, name, id);
  await env.DB.prepare(
    "UPDATE hooks SET name = ?, enabled = ?, max_body_bytes = ?, offline_notice = ?, deliver_to = ?, static_response = ?, on_limit = ?, paused_until = CASE WHEN ? THEN NULL ELSE paused_until END WHERE id = ?",
  )
    .bind(name, enabled, maxBodyBytes, notice, deliverTo, response, onLimit, unpause ? 1 : 0, id)
    .run()
    .catch(uniqueName);
  if (deliverTo !== (row.deliver_to ?? null)) {
    // Who reads a hook's events is worth a line in the audit: the name is the device, or `*` for all.
    await accountStub(env, caller.accountId).audit({ kind: "hook.delivery", actor: caller.actor, subject: id, name: deliverTo ?? "*" });
  }
  if (unpause) await accountStub(env, caller.accountId).hookUnpaused(id, caller.actor);
  if (name !== row.name) {
    await accountStub(env, caller.accountId).hookChanged({ kind: "hook.renamed", hookId: id, name, previousName: row.name, actor: caller.actor });
  }
  return json(hookJson(await load(env, caller, id), origin));
}

/**
 * `POST /v1/hooks/<id>/unpause` (`hooks:write`): lifts a pause at once (PROTOCOL §3). Answers the
 * hook; a hook that isn't paused is answered as it is.
 */
export async function unpauseHook(env: Env, caller: Principal, origin: string, id: string): Promise<Response> {
  const row = await load(env, caller, id);
  if (row.paused_until !== null && row.paused_until > Date.now()) {
    await env.DB.prepare("UPDATE hooks SET paused_until = NULL WHERE id = ?").bind(id).run();
    await accountStub(env, caller.accountId).hookUnpaused(id, caller.actor);
  }
  return json(hookJson(await load(env, caller, id), origin));
}

export async function rotateHook(env: Env, caller: Principal, id: string): Promise<Response> {
  // The route already asks for `hooks:secrets`; this keeps the rule where the secret is made.
  if (!maySeeSecrets(caller)) throw new HttpError(forbidden("Rotating a hook's secret needs a device or the hooks:secrets scope."));
  const row = await load(env, caller, id);
  const config = JSON.parse(row.verify) as VerifyConfig;
  if (config.strict) {
    return error(409, "conflict", "A strict hook's secret is kept on your devices; change it there.");
  }
  if (!presetTakesSecret(config.preset) || !row.secret_sealed) {
    return error(409, "conflict", "This hook has no secret to rotate.");
  }
  if (!relayGeneratesSecret(config.preset)) {
    return error(409, "conflict", "This provider issues the secret; rotate it there, then create the hook again with the new one.");
  }
  const secret = generateSecret(config.preset);
  const now = Date.now();
  await env.DB.prepare(
    "UPDATE hooks SET secret_sealed = ?, previous_secret_sealed = ?, previous_secret_until = ? WHERE id = ?",
  )
    .bind(await sealSecret(env.SECRETS_KEY, id, secret), row.secret_sealed, now + ROTATION_OVERLAP_MS, id)
    .run();
  await accountStub(env, caller.accountId).hookChanged({ kind: "hook.rotated", hookId: id, name: row.name, actor: caller.actor });
  return json({ secret });
}

export async function deleteHook(env: Env, caller: Principal, id: string): Promise<Response> {
  const row = await load(env, caller, id);
  // Events already in the log stay until they're acknowledged (or retention drops them).
  await env.DB.prepare("DELETE FROM hooks WHERE id = ? AND account_id = ?").bind(id, caller.accountId).run();
  await accountStub(env, caller.accountId).hookChanged({ kind: "hook.deleted", hookId: id, name: row.name, actor: caller.actor });
  return new Response(null, { status: 204 });
}

/** `GET /v1/hooks/<id>/screen`: the hook's screen as the relay holds it (hashes, not values). */
export async function getScreen(env: Env, caller: Principal, id: string): Promise<Response> {
  return json({ screen: screenOf(await load(env, caller, id)) });
}

/**
 * `PUT /v1/hooks/<id>/screen` `{ "screen": EdgeScreen | null }`: replaces the hook's screen. Rules
 * that make the relay read words need `consent.words`; the answer is the screen as kept.
 */
export async function putScreen(env: Env, caller: Principal, id: string, body: Uint8Array): Promise<Response> {
  const row = await load(env, caller, id);
  const input = parseJsonObject(body);
  if (!("screen" in input)) throw new HttpError(invalid("screen", "Send screen: an object, or null to remove it."));
  const screen = parseScreen(input.screen);
  await env.DB.prepare("UPDATE hooks SET screen = ? WHERE id = ?")
    .bind(screen && screen.rules.length > 0 ? JSON.stringify(screen) : null, id)
    .run();
  await accountStub(env, caller.accountId).audit({ kind: "hook.screen", actor: caller.actor, subject: id, name: row.name });
  return json({ screen: screen && screen.rules.length > 0 ? screen : null });
}
