// `GET /v1/account` and `PUT /v1/account/plan` (PROTOCOL §2a, §2b): what an account's plan allows,
// what it has used today, and setting or refreshing the plan with an Overblast entitlement.

import { accountStub, type Caller } from "./auth.ts";
import { verifyEntitlement, workspaceConflict, workspaceTaken } from "./entitlements.ts";
import { error, json, parseJsonObject } from "./http.ts";
import { hostedPlan, resolvePlan, type AccountPlanColumns } from "./plans.ts";

interface AccountRow extends AccountPlanColumns {
  entitlement_ws: string | null;
}

async function loadAccount(env: Env, accountId: string): Promise<AccountRow | null> {
  return env.DB.prepare("SELECT plan, plan_until, limits, entitlement_ws FROM accounts WHERE id = ?").bind(accountId).first<AccountRow>();
}

/**
 * `GET /v1/account` (device): `{ accountId, plan, planUntil, expired, limits, usage, paused, upgrade? }`.
 * `usage.today` and `usage.perHook` come from the account's object (exact); the hook and device
 * counts and the pauses from D1.
 */
export async function getAccount(env: Env, caller: Caller): Promise<Response> {
  const now = Date.now();
  const row = await loadAccount(env, caller.accountId);
  const plan = resolvePlan(env, row, now);
  const [usage, hooks, devices, creates, paused] = await Promise.all([
    accountStub(env, caller.accountId).accountUsage(),
    env.DB.prepare("SELECT count(*) AS n FROM hooks WHERE account_id = ?").bind(caller.accountId).first<{ n: number }>(),
    env.DB.prepare("SELECT count(*) AS n FROM devices WHERE account_id = ? AND kind = 'device' AND revoked_at IS NULL")
      .bind(caller.accountId)
      .first<{ n: number }>(),
    env.DB.prepare("SELECT count FROM hook_creates WHERE account_id = ? AND day = ?")
      .bind(caller.accountId, Math.floor(now / 86_400_000))
      .first<{ count: number }>(),
    env.DB.prepare("SELECT id, paused_until FROM hooks WHERE account_id = ? AND paused_until > ? ORDER BY paused_until")
      .bind(caller.accountId, now)
      .all<{ id: string; paused_until: number }>(),
  ]);
  const upgrade = hostedPlan(env.HOSTED_PLAN);
  // The way to the hosted plan is offered to an account that isn't on an entitled plan (or whose
  // entitlement ran out); it is the operator's data, shown as it is.
  const offer = upgrade && (plan.until === null || plan.expired) ? upgrade : null;
  return json({
    accountId: caller.accountId,
    plan: plan.name,
    planUntil: plan.until,
    expired: plan.expired,
    limits: plan.limits,
    usage: {
      day: usage.day,
      today: usage.today,
      perHook: usage.perHook,
      backlog: usage.backlog,
      hooks: hooks?.n ?? 0,
      devices: devices?.n ?? 0,
      hookCreatesToday: creates?.count ?? 0,
    },
    paused: paused.results.map((p) => ({ hookId: p.id, until: p.paused_until })),
    ...(offer ? { upgrade: offer } : {}),
  });
}

/**
 * `PUT /v1/account/plan` `{ "entitlement" }` (device): sets or refreshes the account's plan. The
 * entitlement's subject must be this account (`sub.acc`); its workspace must not be linked to
 * another account. An entitlement that ends sooner than the one the account holds for the same
 * workspace and plan changes nothing (a replayed old token can't shorten the plan).
 */
export async function putPlan(env: Env, caller: Caller, body: Uint8Array): Promise<Response> {
  const input = parseJsonObject(body);
  const now = Date.now();
  const ent = await verifyEntitlement(env, input.entitlement, now);
  if (!("acc" in ent.sub) || ent.sub.acc !== caller.accountId) {
    return error(403, "forbidden", "This entitlement is for another account.");
  }
  const row = await loadAccount(env, caller.accountId);
  const until = ent.exp * 1000;
  const stale = row !== null && row.entitlement_ws === ent.ws && row.plan === ent.plan && row.plan_until !== null && row.plan_until >= until;
  if (!stale) {
    try {
      await env.DB.prepare("UPDATE accounts SET plan = ?, plan_until = ?, entitlement_ws = ?, limits = ? WHERE id = ?")
        .bind(ent.plan, until, ent.ws, ent.limits ? JSON.stringify(ent.limits) : null, caller.accountId)
        .run();
    } catch (e) {
      if (workspaceTaken(e)) throw workspaceConflict();
      throw e;
    }
    const stub = accountStub(env, caller.accountId);
    await stub.planChanged();
    // Only when the plan itself changes: a routine refresh (a new `exp`) isn't worth a line.
    if (row?.plan !== ent.plan || row?.entitlement_ws !== ent.ws) {
      await stub.audit({ kind: "account.plan", actor: caller.deviceId, subject: caller.accountId, name: ent.plan });
    }
  }
  return getAccount(env, caller);
}
