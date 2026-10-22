// `POST /v1/test/<hookId>` (PROTOCOL §3): a signed sample event, sent through the hook's own path.
//
// The relay writes a small sample, signs it with the hook's own secret in the way its preset's
// provider would (read from the preset table, so every preset the relay can sign for is covered),
// and hands it to `receive` exactly as if it had arrived at `/h/<hookId>`: rate limits, verification,
// the screen, dedupe, sealing and the log all apply. Only its routing `eventType` differs, set to
// `00hooks.test`, so the devices can tell a test from the provider's events and runners don't act on
// it unless an automation asks for that kind.
//
// It can't sign for a strict hook (the secret is on the devices) or an Ed25519 one (the relay holds
// only the sender's public key): those answer 409.

import type { Principal } from "./auth.ts";
import { concatBytes, fromBase64, hmac, randomBytes, toBase64, toHex, toBase64Url, utf8 } from "./encoding.ts";
import { currentSecrets, hookUrl, type HookRow } from "./hooks.ts";
import { TEST_EVENT_TYPE } from "./hook-delivery.ts";
import { error, json, notFound } from "./http.ts";
import { SPECS, twilioSigned, type Spec, type VerifyConfig } from "./presets.ts";
import { receive } from "./receive.ts";

/** What a test sends, and the headers that make it a genuine-looking delivery of its preset. */
export interface SignedSample {
  body: Uint8Array<ArrayBuffer>;
  headers: Headers;
}

/** The spec as a hook uses it: the generic hmac preset takes its header and algorithm from the hook. */
function specFor(config: VerifyConfig): Spec {
  const spec = SPECS[config.preset];
  if (config.preset !== "hmac") return spec;
  return {
    ...spec,
    mac: config.algorithm === "sha1" ? "hmac-sha1" : "hmac-sha256",
    sig: { header: config.header ?? "", format: { kind: "single", prefix: config.prefix ?? "" }, encoding: config.encoding ?? "hex" },
  };
}

/** Why the relay can't sign a sample for this hook, or null when it can. */
export function cannotSign(config: VerifyConfig): string | null {
  if (config.strict) return "This hook is strict: its secret is on your devices, so the relay can't sign a test. Send one from the provider instead.";
  const spec = specFor(config);
  if (spec.mac === "ed25519") return "The relay holds only this sender's public key, so it can't sign a test. Send one from the provider instead.";
  return null;
}

/**
 * Builds the sample and signs it with `secret` as the hook's preset says its provider does: the
 * signed parts, the timestamp where the preset has one (now), delivery ids where it dedupes on them
 * (fresh, so a test is never a duplicate), and the signature header in its format.
 */
export async function signSample(config: VerifyConfig, secret: string | null, url: string, now: number): Promise<SignedSample> {
  const spec = specFor(config);
  const nonce = toBase64Url(randomBytes(12));
  const headers = new Headers({ "user-agent": "00hooks-test" });
  const seconds = String(Math.floor(now / 1000));
  const fresh = (): string => `00hooks-test-${nonce}`;

  // The body: JSON for every preset but Twilio's, whose deliveries are forms. It carries what the
  // presets read from a body (ids, a type, Linear's signed timestamp), and says plainly what it is.
  let body: Uint8Array<ArrayBuffer>;
  if (spec.signed.some((p) => "twilio" in p)) {
    headers.set("content-type", "application/x-www-form-urlencoded");
    body = utf8(new URLSearchParams({ "00hooksTest": "true", Nonce: nonce, SentAt: String(now) }).toString());
  } else {
    headers.set("content-type", "application/json");
    const sample: Record<string, unknown> = {
      type: TEST_EVENT_TYPE,
      object: TEST_EVENT_TYPE,
      id: fresh(),
      event_id: fresh(),
      "00hooks": { test: true, sentAt: now, note: "A test event sent with 00hooks test. It is not from the provider." },
    };
    if (spec.timestamp && "bodyField" in spec.timestamp) sample[spec.timestamp.bodyField] = spec.timestamp.unit === "s" ? Number(seconds) : now;
    // (An RFC 3339 timestamp is only ever a header: Twitch's.)
    body = utf8(JSON.stringify(sample));
  }

  // Headers the preset reads: its event type, delivery ids, a header timestamp, signed headers.
  if (spec.eventType && "header" in spec.eventType) headers.set(spec.eventType.header, TEST_EVENT_TYPE);
  for (const rule of spec.dedupe) if ("header" in rule) headers.set(rule.header, fresh());
  const params = new Map<string, string>();
  if (spec.timestamp) {
    const value = spec.timestamp.unit === "s" ? seconds : spec.timestamp.unit === "rfc3339" ? new Date(now).toISOString() : String(now);
    if ("header" in spec.timestamp) headers.set(spec.timestamp.header, value);
    if ("sigParam" in spec.timestamp) params.set(spec.timestamp.sigParam, value);
  }
  // Any other signed header: a timestamp the preset signs but doesn't check (Zoom's) is now, in
  // seconds; an id is fresh.
  for (const p of spec.signed) {
    if (!("header" in p) || headers.has(p.header)) continue;
    headers.set(p.header, p.header === "webhook-id" ? `msg_${nonce}` : p.header.includes("timestamp") ? seconds : fresh());
  }

  if (spec.mac === "none" || secret === null) return { body, headers };
  if (spec.mac === "token") {
    const header = config.header ?? "authorization";
    headers.set(header, header === "authorization" ? `Bearer ${secret}` : secret);
    return { body, headers };
  }

  // The signed bytes, as the preset's table describes them.
  let signed: Uint8Array<ArrayBuffer>;
  if (spec.signed.some((p) => "twilio" in p)) {
    const strings = await twilioSigned({ body, headers, now, url });
    if (!strings) throw new Error("twilio sample has nothing to sign");
    signed = utf8(strings[0]!);
  } else {
    const parts: Uint8Array[] = [];
    for (const p of spec.signed) {
      if ("body" in p) parts.push(body);
      else if ("text" in p) parts.push(utf8(p.text));
      else if ("header" in p) parts.push(utf8(headers.get(p.header) ?? ""));
      else if ("sigParam" in p) parts.push(utf8(params.get(p.sigParam) ?? ""));
      else throw new Error("unsupported signed part");
    }
    signed = concatBytes(...parts);
  }
  const key = spec.key === "whsec" ? fromBase64(secret.slice("whsec_".length)) : utf8(secret);
  if (!key) throw new Error("the hook's secret doesn't decode");
  const mac = await hmac(spec.mac === "hmac-sha1" ? "SHA-1" : "SHA-256", key, signed);
  const encoded = spec.sig!.encoding === "hex" ? toHex(mac) : toBase64(mac);
  const f = spec.sig!.format;
  let value: string;
  if (f.kind === "single") value = `${f.prefix ?? ""}${encoded}`;
  else if (f.kind === "versioned") value = `${f.version},${encoded}`;
  else value = [...[...params].map(([k, v]) => `${k}=${v}`), `${f.param}=${encoded}`].join(f.separator ?? ",");
  headers.set(spec.sig!.header, value);
  return { body, headers };
}

/**
 * `POST /v1/test/<hookId>` (a device, or an API key with `hooks:secrets`: whoever may hold a hook's
 * secret may sign with it). Answers what the delivery got: its status and, when it was JSON, its
 * answer (`received`, `duplicate`, an error), so the CLI can say what happened.
 */
export async function sendTest(request: Request, env: Env, ctx: ExecutionContext, caller: Principal, hookId: string): Promise<Response> {
  const row = await env.DB.prepare("SELECT * FROM hooks WHERE id = ? AND account_id = ?").bind(hookId, caller.accountId).first<HookRow>();
  if (!row) return notFound();
  const config = JSON.parse(row.verify) as VerifyConfig;
  const why = cannotSign(config);
  if (why) return error(409, "conflict", why);
  const now = Date.now();
  const url = hookUrl(new URL(request.url).origin, hookId);
  const secret = (await currentSecrets(env, row, now))[0] ?? null;
  const sample = await signSample(config, secret, url, now);
  // From the caller's address, so the hook's limits and screen see who sent it.
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) sample.headers.set("CF-Connecting-IP", ip);
  const answer = await receive(new Request(url, { method: "POST", headers: sample.headers, body: sample.body }), env, ctx, hookId, true);
  let parsed: unknown = null;
  if ((answer.headers.get("content-type") ?? "").startsWith("application/json")) {
    try {
      parsed = await answer.json();
    } catch {
      parsed = null;
    }
  }
  return json({ status: answer.status, answer: parsed, eventType: TEST_EVENT_TYPE });
}
