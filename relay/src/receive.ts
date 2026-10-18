// Receiving a webhook (PROTOCOL §4): cheap checks, rate limit, verify over the raw bytes, then seal,
// dedupe and append in the account's Durable Object.

import { accountStub } from "./auth.ts";
import { isId, newId } from "./encoding.ts";
import { error, json, notFound, readLimited, tooLarge, unavailable } from "./http.ts";
import { constantTimeEqualStrings } from "./encoding.ts";
import { currentSecrets, offlineNoticeOf, verifyTokenHash, type HookRow } from "./hooks.ts";
import { decide, screenCryptoKey, screenFor } from "./screen.ts";
import type { Origin } from "./envelope.ts";
import { clientKey } from "./ip.ts";
import { countAtEdge } from "./edge-counts.ts";
import { pepperedHash } from "./seal.ts";
import {
  SPECS,
  challengeAnswer,
  handshakeAnswer,
  keptHeaders,
  metaSubscribe,
  noticeSender,
  providerAnswer,
  signsTimestamp,
  strictHeaders,
  verifyDelivery,
  type VerifyConfig,
} from "./presets.ts";

/** The Rate Limiting bindings' period (wrangler.jsonc): what `Retry-After` says. */
export const RATE_LIMIT_PERIOD_S = 10;
/** How long a sender is asked to wait when the account's log is full. */
export const QUOTA_RETRY_AFTER_S = 60;

const slowDown = (message: string) =>
  error(429, "rate_limited", message, {}, { "Retry-After": String(RATE_LIMIT_PERIOD_S) });

export async function receive(request: Request, env: Env, ctx: ExecutionContext, hookId: string): Promise<Response> {
  // Fail closed: without its rate limits the relay would take any flood at full cost.
  // …and without its signing key it couldn't seal what it takes.
  if (!env.HOOK_LIMIT || !env.RECEIVE_IP_LIMIT || !env.RELAY_SIGNING_KEY) return unavailable();
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
  // The URL as the sender reached it: Workers don't rewrite it, and Twilio signs it.
  const url = request.url;
  const verdict = await verifyDelivery(config, await currentSecrets(env, hook, now), { body, headers: request.headers, now, url });
  if (!verdict.ok) {
    // Counted at the edge, not written per request: a public URL's junk never wakes the account.
    countAtEdge(env, ctx, hook.account_id, "verify.failed", hookId);
    return error(401, "signature", "The delivery's signature doesn't verify.");
  }
  const stub = accountStub(env, hook.account_id);
  // An endpoint check (Slack's url_verification) is answered, not stored: it carries no event.
  const handshake = handshakeAnswer(config, body);
  if (handshake) return handshake;

  const strict = config.strict === true;
  const origin = originOf(request);

  // The screen (PROTOCOL §4b), after the signature (a forgery keeps its 401) and before anything is
  // stored. A drop is answered as a delivery would be, with an id that names nothing, so a sender
  // can't tell; a hold is stored aside and not streamed until a device releases it.
  // Compiled once per isolate, keyed by the hook and its screen's JSON; the key is imported once.
  const screen = await screenFor(hook.id, hook.screen);
  let held: string | undefined;
  if (screen && screen.rules.length > 0) {
    const verdict = await decide(screen, {
      ip: origin.ip ?? null,
      asn: origin.asn ?? null,
      country: origin.country ?? null,
      headers: request.headers,
      body,
      contentType: request.headers.get("content-type"),
      strict,
      key: await screenCryptoKey(env.HASH_PEPPER, hook.account_id),
    });
    if (verdict?.verdict === "drop") {
      countAtEdge(env, ctx, hook.account_id, "screen.dropped", hookId, hook.name);
      const nobody = newId("evt");
      return providerAnswer(config, null, { received: nobody }) ?? json({ received: nobody });
    }
    if (verdict?.verdict === "quarantine") held = verdict.rule;
  }

  // The offline notice (PROTOCOL §4a): only for a delivery the relay verified itself, from a sender
  // it can name; the DO decides (no device connected for long enough, and not yet today for this
  // sender) in the same transaction as the append. The sender is kept only as a keyed hash.
  const offline = offlineNoticeOf(hook);
  const sender = offline && verdict.verified && !strict && held === undefined ? noticeSender(config, body, request.headers) : null;
  const notice =
    offline && sender
      ? { mark: await pepperedHash(env.HASH_PEPPER, `notice:${hookId}:${sender}`), afterMs: offline.afterMinutes * 60_000 }
      : undefined;
  // Marks are stored as keyed hashes: a delivery id or an event id read from the body is content
  // too, and storage keeps none in the clear.
  const dedupeKeys = await Promise.all(verdict.dedupeKeys.map((k) => pepperedHash(env.HASH_PEPPER, `dedupe:${hookId}:${k}`)));
  // Without a signed timestamp a captured genuine delivery verifies forever: its body-hash mark is
  // kept for REPLAY_MARK_DAYS, not a week (PROTOCOL §4).
  const long = !signsTimestamp(config);
  const longKeys = long ? dedupeKeys.filter((_, i) => verdict.dedupeKeys[i]!.startsWith("body:")) : [];
  const result = await stub.append({
    hookId,
    dedupeKeys,
    ...(longKeys.length > 0 ? { longKeys } : {}),
    verified: verdict.verified,
    strict,
    preset: config.preset,
    eventType: verdict.eventType,
    content: {
      contentType: request.headers.get("content-type")?.slice(0, 200) ?? null,
      // A strict hook seals the signature headers and the URL too: its devices verify.
      headers: strict ? strictHeaders(config, request.headers) : keptHeaders(config, request.headers),
      ...(strict ? { url } : {}),
      origin,
    },
    body,
    receivedAt: now,
    ...(notice ? { notice } : {}),
    ...(held !== undefined ? { held } : {}),
  });
  if (result.duplicate) return providerAnswer(config, null, { duplicate: true }) ?? json({ duplicate: true });
  if (result.full) {
    const message =
      result.scope === "held"
        ? "This hook's held events are at their limit; deliveries the screen holds resume once they're released or dropped."
        : result.scope === "hook"
          ? "This hook's share of the account's event log is full; deliveries resume once its devices acknowledge what's waiting."
          : "This account's event log is full; deliveries resume once its devices acknowledge what's waiting.";
    return error(429, "quota", message, { scope: result.scope }, { "Retry-After": String(QUOTA_RETRY_AFTER_S) });
  }
  ctx.waitUntil(env.DB.prepare("UPDATE hooks SET last_event_at = ? WHERE id = ?").bind(now, hookId).run());
  if (result.held) ctx.waitUntil(stub.countAudit("screen.held", hookId, hook.name).catch(() => {}));
  // GitHub's `ping` (sent when a webhook is created) is stored like any event, so a new hook can be
  // seen working end to end, and answered 200 like any delivery. A provider that takes its answer
  // in the response (Twilio's TwiML) gets one, with the notice when it was due.
  const said = result.notice && offline ? offline.text : null;
  return providerAnswer(config, said, { received: result.id }) ?? json({ received: result.id });
}

/**
 * Where a delivery came from, as Cloudflare saw it: the client's address, its network (ASN) and its
 * country. Sealed with the content, so the devices' screen can use it too.
 */
export function originOf(request: Request): Origin {
  const cf = (request as Request & { cf?: { asn?: unknown; country?: unknown } }).cf;
  const ip = request.headers.get("CF-Connecting-IP")?.trim();
  const out: Origin = {};
  if (ip && ip.length <= 64) out.ip = ip;
  if (typeof cf?.asn === "number" && Number.isInteger(cf.asn)) out.asn = cf.asn;
  if (typeof cf?.country === "string" && /^[A-Z]{2}$/.test(cf.country)) out.country = cf.country;
  return out;
}

/**
 * `GET /h/<hookId>`: a provider checking the endpoint before it sends anything (Meta's
 * `hub.mode=subscribe` with the hook's verify token and a challenge). The same cheap checks as a
 * delivery come first; then the token must match the hook's (compared as keyed hashes), and the
 * challenge is echoed as plain text. Nothing is stored; a wrong token is a counted failure.
 */
export async function receiveGet(request: Request, env: Env, ctx: ExecutionContext, hookId: string): Promise<Response> {
  if (!env.HOOK_LIMIT || !env.RECEIVE_IP_LIMIT || !env.RELAY_SIGNING_KEY) return unavailable();
  if (!isId("hk", hookId)) return notFound();
  if (!(await env.RECEIVE_IP_LIMIT.limit({ key: clientKey(request) })).success) {
    return slowDown("Too many deliveries from this address; slow down.");
  }
  const hook = await env.DB.prepare("SELECT * FROM hooks WHERE id = ?").bind(hookId).first<HookRow>();
  if (!hook || hook.enabled !== 1) return notFound();
  const config = JSON.parse(hook.verify) as VerifyConfig;
  if (!SPECS[config.preset].getHandshake || !hook.handshake_token_hash) return notFound();
  if (!(await env.HOOK_LIMIT.limit({ key: hookId })).success) {
    return slowDown("Too many deliveries to this hook; slow down.");
  }
  const ask = metaSubscribe(new URL(request.url));
  const presented = ask ? await verifyTokenHash(env, hookId, ask.token) : "";
  if (!ask || !constantTimeEqualStrings(presented, hook.handshake_token_hash)) {
    countAtEdge(env, ctx, hook.account_id, "verify.failed", hookId);
    return error(401, "signature", "The endpoint check doesn't carry this hook's verify token.");
  }
  return challengeAnswer(ask.challenge);
}
