// `GET /v1/audit` and `GET /v1/events` (PROTOCOL §9): what happened on the account, and what's in its
// log. Names and ids only: never a secret, a payload or a header value.

import { accountStub, type Principal } from "./auth.ts";
import { HttpError, invalid, json } from "./http.ts";

export const MAX_LIMIT = 500;

function limitParam(url: URL, fallback: number): number {
  const raw = url.searchParams.get("limit");
  if (raw === null) return fallback;
  if (!/^\d{1,4}$/.test(raw) || Number(raw) < 1 || Number(raw) > MAX_LIMIT) {
    throw new HttpError(invalid("limit", `limit must be a whole number from 1 to ${MAX_LIMIT}.`));
  }
  return Number(raw);
}

export async function readAudit(env: Env, caller: Principal, url: URL): Promise<Response> {
  const sinceRaw = url.searchParams.get("since");
  if (sinceRaw !== null && !/^\d{1,16}$/.test(sinceRaw)) throw new HttpError(invalid("since", "since must be a time in Unix ms."));
  const since = sinceRaw === null ? 0 : Number(sinceRaw);
  const entries = await accountStub(env, caller.accountId).readAudit(since, limitParam(url, 100));
  // Counted verification failures are recorded by hook id alone; add the hook's name when it still
  // exists. The account's hooks are read once and matched here: one bound parameter, however many
  // hooks failed (D1 binds at most 100).
  if (entries.some((e) => e.kind === "verify.failed")) {
    const { results } = await env.DB.prepare("SELECT id, name FROM hooks WHERE account_id = ?")
      .bind(caller.accountId)
      .all<{ id: string; name: string }>();
    const names = new Map(results.map((r) => [r.id, r.name]));
    for (const e of entries) if (e.kind === "verify.failed") e.name = names.get(e.subject) ?? null;
  }
  return json({ entries });
}

export async function listEvents(env: Env, caller: Principal, url: URL): Promise<Response> {
  return json({ events: await accountStub(env, caller.accountId).listEvents(limitParam(url, 50)) });
}
