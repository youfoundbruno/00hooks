// Receiving a webhook (PROTOCOL §4): cheap checks, rate limit, verify over the raw bytes, then dedupe
// and append in one Durable Object transaction.

import { accountStub } from "./auth.ts";
import { isId } from "./encoding.ts";
import { error, json, notFound, readLimited, tooLarge } from "./http.ts";
import { currentSecrets, type HookRow } from "./hooks.ts";
import { keptHeaders, verifyDelivery, type VerifyConfig } from "./presets.ts";

/** The Rate Limiting binding's period (wrangler.jsonc): what `Retry-After` says. */
export const RATE_LIMIT_PERIOD_S = 10;

export async function receive(request: Request, env: Env, ctx: ExecutionContext, hookId: string): Promise<Response> {
  if (!isId("hk", hookId)) return notFound();
  const hook = await env.DB.prepare("SELECT * FROM hooks WHERE id = ?").bind(hookId).first<HookRow>();
  if (!hook || hook.enabled !== 1) return notFound();

  const declared = request.headers.get("Content-Length");
  if (declared !== null && /^\d+$/.test(declared) && Number(declared) > hook.max_body_bytes) return tooLarge();

  // Before reading the body, so a flood costs as little as possible.
  if (env.HOOK_LIMIT) {
    const { success } = await env.HOOK_LIMIT.limit({ key: hookId });
    if (!success) {
      return error(429, "rate_limited", "Too many deliveries to this hook; slow down.", {}, { "Retry-After": String(RATE_LIMIT_PERIOD_S) });
    }
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
    dedupeKey: verdict.dedupeKey,
    verified: verdict.verified,
    preset: config.preset,
    eventType: verdict.eventType,
    contentType: request.headers.get("content-type"),
    headers: keptHeaders(config, request.headers),
    body,
    receivedAt: now,
  });
  if (result.duplicate) return json({ duplicate: true });
  ctx.waitUntil(env.DB.prepare("UPDATE hooks SET last_event_at = ? WHERE id = ?").bind(now, hookId).run());
  // GitHub's `ping` (sent when a webhook is created) is stored like any event, so a new hook can be
  // seen working end to end, and answered 200 like any delivery.
  return json({ received: result.id });
}
