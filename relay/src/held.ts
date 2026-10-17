// The screen's hold and its key (PROTOCOL §4b): what the relay held, released or dropped by a
// device; the account's screen key, which devices hash field values with; and what `/v1/info`
// says about the screen and any hosted extras.

import { accountStub, type Caller, type Principal } from "./auth.ts";
import { toBase64Url } from "./encoding.ts";
import { json, notFound } from "./http.ts";
import { DEFAULT_HELD_DAYS } from "./account-object.ts";
import { MAX_RULES, screenKey } from "./screen.ts";

/** `GET /v1/held` (device, or `events:read`): held events, newest first, metadata only. */
export async function listHeld(env: Env, caller: Principal): Promise<Response> {
  return json({ held: await accountStub(env, caller.accountId).listHeld() });
}

/** `POST /v1/held/<id>/release` (device, or `hooks:write`): it takes the next seq and is streamed. */
export async function releaseHeld(env: Env, caller: Principal, id: string): Promise<Response> {
  const stub = accountStub(env, caller.accountId);
  const r = await stub.releaseHeld(id);
  if (!r) return notFound();
  await stub.audit({ kind: "held.released", actor: caller.actor, subject: id, name: null });
  return json({ released: id, seq: r.seq });
}

/** `DELETE /v1/held/<id>` (device, or `hooks:write`): it is never streamed. */
export async function dropHeld(env: Env, caller: Principal, id: string): Promise<Response> {
  const stub = accountStub(env, caller.accountId);
  if (!(await stub.dropHeld(id))) return notFound();
  await stub.audit({ kind: "held.dropped", actor: caller.actor, subject: id, name: null });
  return new Response(null, { status: 204 });
}

/** `GET /v1/screen/key` (device only): the key field values are hashed with for this account. */
export async function screenKeyFor(env: Env, caller: Caller): Promise<Response> {
  return json({ key: toBase64Url(await screenKey(env.HASH_PEPPER, caller.accountId)) });
}

export interface Extra {
  id: string;
  title: string;
  description?: string;
  url?: string;
}

/**
 * Hosted extras, as the operator announces them (`HOSTED_EXTRAS`): data, never code. Anything
 * malformed is left out; a self-hosted relay announces none.
 */
export function hostedExtras(raw: string | undefined): Extra[] {
  if (!raw) return [];
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(v)) return [];
  const text = (x: unknown, max: number) => (typeof x === "string" && x.trim().length > 0 && x.length <= max ? x.trim() : undefined);
  const out: Extra[] = [];
  for (const e of v.slice(0, 20)) {
    if (typeof e !== "object" || e === null) continue;
    const o = e as Record<string, unknown>;
    const id = typeof o.id === "string" && /^[a-z0-9-]{1,40}$/.test(o.id) ? o.id : undefined;
    const title = text(o.title, 80);
    if (!id || !title) continue;
    const description = text(o.description, 400);
    const url = text(o.url, 300);
    out.push({ id, title, ...(description ? { description } : {}), ...(url && /^https:\/\//.test(url) ? { url } : {}) });
  }
  return out;
}

/** What `/v1/info` says about the screen. */
export function screenInfo(env: Env): { screen: { edge: true; maxRules: number; heldDays: number }; extras: Extra[] } {
  const days = Number(env.SCREEN_HELD_DAYS);
  return {
    screen: { edge: true, maxRules: MAX_RULES, heldDays: Number.isFinite(days) && days > 0 ? days : DEFAULT_HELD_DAYS },
    extras: hostedExtras(env.HOSTED_EXTRAS),
  };
}
