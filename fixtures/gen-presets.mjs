#!/usr/bin/env node
// Writes fixtures/presets.v1.json: the provider-preset vectors both the relay (relay/test) and the CLI
// (cli/hooks-client) are held to. Published vectors are copied as published; the rest are computed
// here with node:crypto, from each provider's documented scheme, independently of either
// implementation. Run: node fixtures/gen-presets.mjs
import { createHash, createHmac, createPrivateKey, sign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const hmac = (alg, key, data, enc) => createHmac(alg, key).update(data).digest(enc);
const T = 1792233600; // 2026-10-17T00:00:00Z, the vectors' "now" unless a published one says otherwise
const vectors = [];
const add = (v) => vectors.push(v);

// ── github ── https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
add({
  name: "github: the documented example",
  source: "published (GitHub docs)",
  verify: { preset: "github" },
  secrets: ["It's a Secret to Everybody"],
  now: T * 1000,
  headers: {
    "x-hub-signature-256": "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
    "x-github-event": "push",
    "x-github-delivery": "72d3162e-cc78-11e3-81ab-4c9367dc0958",
  },
  body: "Hello, World!",
  expect: { ok: true, eventType: "push" },
});
add({
  name: "github: one changed byte",
  source: "published, tampered",
  verify: { preset: "github" },
  secrets: ["It's a Secret to Everybody"],
  now: T * 1000,
  headers: { "x-hub-signature-256": "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17" },
  body: "Hello, World?",
  expect: { ok: false },
});

// ── standard-webhooks ── https://github.com/standard-webhooks/standard-webhooks (spec example)
const sw = { id: "msg_p5jXN8AQM9LWM0D4loKWxJek", ts: "1614265330", body: '{"test": 2432232314}' };
add({
  name: "standard-webhooks: the specification's example",
  source: "published (Standard Webhooks spec)",
  verify: { preset: "standard-webhooks" },
  secrets: ["whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"],
  now: Number(sw.ts) * 1000,
  headers: { "webhook-id": sw.id, "webhook-timestamp": sw.ts, "webhook-signature": "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" },
  body: sw.body,
  expect: { ok: true, eventType: null },
});
add({
  name: "standard-webhooks: outside 300 s",
  source: "published, late",
  verify: { preset: "standard-webhooks" },
  secrets: ["whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"],
  now: (Number(sw.ts) + 301) * 1000,
  headers: { "webhook-id": sw.id, "webhook-timestamp": sw.ts, "webhook-signature": "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" },
  body: sw.body,
  expect: { ok: false },
});

// ── standard-webhooks-ed25519 (v1a) ── RFC 8032 §7.1 test 1's key pair
const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
const pub = Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex");
const edKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
const edBody = '{"type":"invoice.paid","data":{"id":"in_1"}}';
const edId = "msg_2AbCdEf";
const edSig = sign(null, Buffer.from(`${edId}.${T}.${edBody}`), edKey).toString("base64");
const whpk = `whpk_${pub.toString("base64")}`;
add({
  name: "standard-webhooks-ed25519: v1a, among a v1 decoy",
  source: "computed (RFC 8032 test 1 key, Standard Webhooks v1a scheme)",
  verify: { preset: "standard-webhooks-ed25519", publicKey: whpk },
  secrets: [whpk],
  now: T * 1000,
  headers: { "webhook-id": edId, "webhook-timestamp": String(T), "webhook-signature": `v1,AAAA v1a,${edSig}` },
  body: edBody,
  expect: { ok: true, eventType: "invoice.paid" },
});
add({
  name: "standard-webhooks-ed25519: a v1a signature over another id",
  source: "computed, tampered",
  verify: { preset: "standard-webhooks-ed25519", publicKey: whpk },
  secrets: [whpk],
  now: T * 1000,
  headers: { "webhook-id": "msg_other", "webhook-timestamp": String(T), "webhook-signature": `v1a,${edSig}` },
  body: edBody,
  expect: { ok: false },
});

// ── stripe ── https://docs.stripe.com/webhooks#verify-manually (scheme; Stripe publishes no fixed vector)
const stSecret = "whsec_test_00hooks_vector_secret";
const stBody = '{"id":"evt_1PtestVector","object":"event","type":"checkout.session.completed","data":{"object":{}}}';
const stSig = hmac("sha256", stSecret, `${T}.${stBody}`, "hex");
add({
  name: "stripe: t= and two v1 (the second is the right one, as during a secret roll)",
  source: "computed (Stripe's documented scheme)",
  verify: { preset: "stripe" },
  secrets: [stSecret],
  now: (T + 120) * 1000,
  headers: { "stripe-signature": `t=${T},v1=${"0".repeat(64)},v1=${stSig},v0=${"1".repeat(64)}` },
  body: stBody,
  expect: { ok: true, eventType: "checkout.session.completed" },
});
add({
  name: "stripe: outside the 300 s tolerance",
  source: "computed, late",
  verify: { preset: "stripe" },
  secrets: [stSecret],
  now: (T + 301) * 1000,
  headers: { "stripe-signature": `t=${T},v1=${stSig}` },
  body: stBody,
  expect: { ok: false },
});
add({
  name: "stripe: a new t= with the old signature",
  source: "computed, tampered",
  verify: { preset: "stripe" },
  secrets: [stSecret],
  now: (T + 1) * 1000,
  headers: { "stripe-signature": `t=${T + 1},v1=${stSig}` },
  body: stBody,
  expect: { ok: false },
});

// ── slack ── https://api.slack.com/authentication/verifying-requests-from-slack (documented example)
const slBody =
  "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
add({
  name: "slack: the documented slash-command example",
  source: "published (Slack docs)",
  verify: { preset: "slack" },
  secrets: ["8f742231b10e8888abcd99yyyzzz85a5"],
  now: 1531420618 * 1000,
  headers: {
    "x-slack-request-timestamp": "1531420618",
    "x-slack-signature": "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
    "content-type": "application/x-www-form-urlencoded",
  },
  body: slBody,
  expect: { ok: true, eventType: null },
});
const slEvent = '{"type":"event_callback","event_id":"Ev123","event":{"type":"app_mention","text":"hi"}}';
add({
  name: "slack: an Events API callback",
  source: "computed (Slack's documented scheme)",
  verify: { preset: "slack" },
  secrets: ["8f742231b10e8888abcd99yyyzzz85a5"],
  now: T * 1000,
  headers: { "x-slack-request-timestamp": String(T), "x-slack-signature": `v0=${hmac("sha256", "8f742231b10e8888abcd99yyyzzz85a5", `v0:${T}:${slEvent}`, "hex")}` },
  body: slEvent,
  expect: { ok: true, eventType: "app_mention" },
});
add({
  name: "slack: the documented example, six minutes later",
  source: "published, late",
  verify: { preset: "slack" },
  secrets: ["8f742231b10e8888abcd99yyyzzz85a5"],
  now: (1531420618 + 360) * 1000,
  headers: {
    "x-slack-request-timestamp": "1531420618",
    "x-slack-signature": "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
  },
  body: slBody,
  expect: { ok: false },
});

// ── linear ── https://linear.app/developers/webhooks (scheme: hex HMAC-SHA256 of the body; webhookTimestamp within 60 s)
const liSecret = "lin_wh_00hooks_vector_secret";
const liBody = `{"action":"create","type":"Issue","data":{"id":"i1"},"webhookTimestamp":${T * 1000},"webhookId":"wh1"}`;
const liSig = hmac("sha256", liSecret, liBody, "hex");
add({
  name: "linear: within 60 s",
  source: "computed (Linear's documented scheme)",
  verify: { preset: "linear" },
  secrets: [liSecret],
  now: T * 1000 + 59_000,
  headers: { "linear-signature": liSig, "linear-delivery": "d-1", "linear-event": "Issue" },
  body: liBody,
  expect: { ok: true, eventType: "Issue" },
});
add({
  name: "linear: 61 s late",
  source: "computed, late",
  verify: { preset: "linear" },
  secrets: [liSecret],
  now: T * 1000 + 61_000,
  headers: { "linear-signature": liSig },
  body: liBody,
  expect: { ok: false },
});

// ── shopify ── https://shopify.dev/docs/apps/build/webhooks/subscribe/https (scheme: base64 HMAC-SHA256 of the body)
const shSecret = "shpss_00hooks_vector_secret";
const shBody = '{"id":820982911946154508,"email":"jon@example.com"}';
add({
  name: "shopify: base64 HMAC of the body",
  source: "computed (Shopify's documented scheme)",
  verify: { preset: "shopify" },
  secrets: [shSecret],
  now: T * 1000,
  headers: { "x-shopify-hmac-sha256": hmac("sha256", shSecret, shBody, "base64"), "x-shopify-topic": "orders/create", "x-shopify-webhook-id": "b54557e4-bdd9-4b37-8a5f-bf7d70bcd043" },
  body: shBody,
  expect: { ok: true, eventType: "orders/create" },
});
add({
  name: "shopify: the hex form of the right HMAC is refused",
  source: "computed, wrong encoding",
  verify: { preset: "shopify" },
  secrets: [shSecret],
  now: T * 1000,
  headers: { "x-shopify-hmac-sha256": hmac("sha256", shSecret, shBody, "hex") },
  body: shBody,
  expect: { ok: false },
});

// ── twilio ── twilio-python tests/unit/test_request_validator.py (token "12345")
const twParams = "CallSid=CA1234567890ABCDE&Digits=1234&From=%2B14158675309&To=%2B18005551212&Caller=%2B14158675309";
const form = { "content-type": "application/x-www-form-urlencoded" };
add({
  name: "twilio: form parameters, sorted after the URL",
  source: "published (twilio-python's validator tests)",
  verify: { preset: "twilio" },
  secrets: ["12345"],
  now: T * 1000,
  url: "https://mycompany.com/myapp.php?foo=1&bar=2",
  headers: { ...form, "x-twilio-signature": "RSOYDt4T1cUTdK1PDd93/VVr8B8=" },
  body: twParams,
  expect: { ok: true, eventType: null },
});
add({
  name: "twilio: repeated parameters (values sorted, duplicates once)",
  source: "published (twilio-python's validator tests)",
  verify: { preset: "twilio" },
  secrets: ["12345"],
  now: T * 1000,
  url: "https://mycompany.com/myapp.php?foo=1&bar=2",
  headers: { ...form, "x-twilio-signature": "IK+Dwps556ElfBT0I3Rgjkr1wJU=" },
  body: "Sid=CA123&SidAccount=AC123&Digits=5678&Digits=1234&Digits=1234",
  expect: { ok: true, eventType: null },
});
add({
  name: "twilio: signed with :443 but reached without it",
  source: "published (twilio-python's validator tests)",
  verify: { preset: "twilio" },
  secrets: ["12345"],
  now: T * 1000,
  url: "https://mycompany.com/myapp.php?foo=1&bar=2",
  headers: { ...form, "x-twilio-signature": "kvajT1Ptam85bY51eRf/AJRuM3w=" },
  body: twParams,
  expect: { ok: true, eventType: null },
});
add({
  name: "twilio: a JSON body, covered by bodySHA256",
  source: "published (twilio-python's validator tests)",
  verify: { preset: "twilio" },
  secrets: ["12345"],
  now: T * 1000,
  url: "https://mycompany.com/myapp.php?foo=1&bar=2&bodySHA256=0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620",
  headers: { "content-type": "application/json", "x-twilio-signature": "a9nBmqA0ju/hNViExpshrM61xv4=" },
  body: '{"property": "value", "boolean": true}',
  expect: { ok: true, eventType: null },
});
add({
  name: "twilio: a JSON body that doesn't match bodySHA256",
  source: "published, tampered",
  verify: { preset: "twilio" },
  secrets: ["12345"],
  now: T * 1000,
  url: "https://mycompany.com/myapp.php?foo=1&bar=2&bodySHA256=0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620",
  headers: { "content-type": "application/json", "x-twilio-signature": "a9nBmqA0ju/hNViExpshrM61xv4=" },
  body: '{"property": "value", "boolean": false}',
  expect: { ok: false },
});
add({
  name: "twilio: the right signature at another URL",
  source: "published, wrong URL",
  verify: { preset: "twilio" },
  secrets: ["12345"],
  now: T * 1000,
  url: "https://mycompany.com/myapp.php?foo=1&bar=3",
  headers: { ...form, "x-twilio-signature": "RSOYDt4T1cUTdK1PDd93/VVr8B8=" },
  body: twParams,
  expect: { ok: false },
});

// ── hmac ── RFC 4231 test case 2 (SHA-256), RFC 2202 test case 2 (SHA-1)
add({
  name: "hmac: sha256 hex with a prefix (RFC 4231 case 2)",
  source: "published (RFC 4231)",
  verify: { preset: "hmac", header: "x-signature", algorithm: "sha256", encoding: "hex", prefix: "sha256=" },
  secrets: ["Jefe"],
  now: T * 1000,
  headers: { "x-signature": "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
  body: "what do ya want for nothing?",
  expect: { ok: true, eventType: null },
});
add({
  name: "hmac: sha1 base64 (RFC 2202 case 2)",
  source: "published (RFC 2202)",
  verify: { preset: "hmac", header: "x-sig", algorithm: "sha1", encoding: "base64" },
  secrets: ["Jefe"],
  now: T * 1000,
  headers: { "x-sig": "7/zfauXrL6LSdBbV8YTfnCWafHk=" },
  body: "what do ya want for nothing?",
  expect: { ok: true, eventType: null },
});

// ── token ──
add({
  name: "token: a bearer token",
  source: "computed",
  verify: { preset: "token", header: "authorization" },
  secrets: ["s3cret-token"],
  now: T * 1000,
  headers: { authorization: "Bearer s3cret-token" },
  body: "{}",
  expect: { ok: true, eventType: null },
});
add({
  name: "token: the wrong token",
  source: "computed",
  verify: { preset: "token", header: "authorization" },
  secrets: ["s3cret-token"],
  now: T * 1000,
  headers: { authorization: "Bearer s3cret-tokeN" },
  body: "{}",
  expect: { ok: false },
});

for (const v of vectors) v.bodySha256 = createHash("sha256").update(v.body).digest("hex");
const out = join(dirname(fileURLToPath(import.meta.url)), "presets.v1.json");
writeFileSync(
  out,
  JSON.stringify(
    {
      about:
        "Provider-preset vectors for 00hooks (PROTOCOL §3). Both the relay and the CLI's strict-mode verifier must give `expect` for each. `now` is Unix ms; `url` is the public URL the relay was reached at. Generated by fixtures/gen-presets.mjs.",
      vectors,
    },
    null,
    2,
  ) + "\n",
);
console.log(`wrote ${vectors.length} vectors to ${out}`);
