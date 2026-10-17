// Receiving a webhook (PROTOCOL §4): cheap checks, rate limit, verify over the raw bytes, then dedupe
// and append in one Durable Object transaction.

import { accountStub } from "./auth.ts";
import { isId } from "./encoding.ts";
import { error, json, notFound, readLimited, tooLarge, unavailable } from "./http.ts";
import { currentSecrets, type HookRow } from "./hooks.ts";
import { clientKey } from "./ip.ts";
import { keptHeaders, verifyDelivery, type VerifyConfig } from "./presets.ts";

/** The Rate Limiting bindings' period (wrangler.jsonc): what `Retry-After` says. */
export const RATE_LIMIT_PERIOD_S = 10;
/** How long a sender is asked to wait when the account's log is full. */
export const QUOTA_RETRY_AFTER_S = 60;

const slowDown = (message: string) =>
  error(429, "rate_limited", message, {}, { "Retry-After": String(RATE_LIMIT_PERIOD_S) });

export async function receive(request: Request, env: Env, ctx: ExecutionContext, hookId: string): Promise<Response> {
  // Fail closed: without its rate limits the relay would take any flood at full cost.
  if (!env.HOOK_LIMIT || !env.RECEIVE_IP_LIMIT) return unavailable();
  if (!isId("hk", hookId)) return notFound();
  // Per client address (IPv6 by /64), before the D1 lookup, so guessing hook ids costs the guesser
  // their budget and not the relay a database read each.
  if (!(await env.RECEIVE_IP_LIMIT.limit({ key: clientKey(request) })).success) {
    return slowDown("Too many deliveries from this address; slow down.");
  }
  const hook = await env.DB.prepare("SELECT * FROM hooks WHERE id = ?").bind(hookId).first<HookRow>();
  if (!hook || hook.enabled !== 1) return notFound();

  const declared = request.headers.get("Content-Length");
  if (declared !== null && /^\d+$/.test(declared) && Number(declared) > hook.max_body_bytes) return tooLarge();

  // Before reading the body, so a flood costs as little as possible.
  if (!(await env.HOOK_LIMIT.limit({ key: hookId })).success) {
    return slowDown("Too many deliveries to this hook; slow down.");
  }

  const body = await readLimited(request, hook.max_body_bytes);
  if (body === null) return tooLarge();

  const now = Date.now();
  const config = JSON.parse(hook.verify) as VerifyConfig;
  const verdict = await verifyDelivery(config, await currentSecrets(env, hook, now), { body, headers: request.headers, now });
  const stub = accountStub(env, hook.account_id);
  if (!verdict.ok) {
    ctx.waitUntil(stub.recordFailure(hookId).catch(() => {}));
    return error(401, "signature", "The delivery's signature doesn't verify.");
  }

  const result = await stub.append({
    hookId,
    dedupeKeys: verdict.dedupeKeys,
    verified: verdict.verified,
    preset: config.preset,
    eventType: verdict.eventType,
    contentType: request.headers.get("content-type")?.slice(0, 200) ?? null,
    headers: keptHeaders(config, request.headers),
    body,
    receivedAt: now,
  });
  if (result.duplicate) return json({ duplicate: true });
  if (result.full) {
    return error(
      429,
      "quota",
      "This account's event log is full; deliveries resume once its devices acknowledge what's waiting.",
      {},
      { "Retry-After": String(QUOTA_RETRY_AFTER_S) },
    );
  }
  ctx.waitUntil(env.DB.prepare("UPDATE hooks SET last_event_at = ? WHERE id = ?").bind(now, hookId).run());
  // GitHub's `ping` (sent when a webhook is created) is stored like any event, so a new hook can be
  // seen working end to end, and answered 200 like any delivery.
  return json({ received: result.id });
}
