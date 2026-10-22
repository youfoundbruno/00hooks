// The phase 1 presets through the real Worker: creation rules, replay refusal, Slack's handshake, and
// strict mode (verify on the devices) at the edge.

import { describe, expect, it } from "vitest";
import { hmac, toHex, utf8 } from "../src/encoding.ts";
import { HttpError } from "../src/http.ts";
import { parseVerify, strictHeaders, verifyDelivery } from "../src/presets.ts";
import { accountObject, createHook, data, fetchRelay, newAccount, openEvent, openStream, signed, type StreamedEvent } from "./helpers.ts";

const STRIPE_SECRET = "whsec_relay_test_secret_0001";

function post(hookId: string, body: string, headers: Record<string, string> = {}, query = "") {
  return fetchRelay(`/h/${hookId}${query}`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body });
}

async function stripeHeader(body: string, t = Math.floor(Date.now() / 1000), secret = STRIPE_SECRET): Promise<string> {
  return `t=${t},v1=${toHex(await hmac("SHA-256", utf8(secret), utf8(`${t}.${body}`)))}`;
}

function status(fn: () => unknown): number {
  try {
    fn();
  } catch (e) {
    return e instanceof HttpError ? e.response.status : 0;
  }
  return 200;
}

describe("creating hooks for the phase 1 presets", () => {
  it("needs the provider's secret for providers that issue it, and never generates one", async () => {
    const dev = await newAccount();
    for (const preset of ["stripe", "slack", "linear", "shopify", "twilio", "paddle", "zoom", "pagerduty"]) {
      const res = await signed(dev, "POST", "/v1/hooks", { name: preset, verify: { preset } });
      expect(res.status, preset).toBe(400);
      expect(await res.json()).toMatchObject({ field: "verify.secret" });
      const ok = await signed(dev, "POST", "/v1/hooks", { name: preset, verify: { preset, secret: "provider-issued-secret" } });
      expect(ok.status).toBe(201);
      const created = (await ok.json()) as { secret?: string; hook: { id: string } };
      // A supplied secret is never echoed, and these presets can't rotate at the relay.
      expect(created).not.toHaveProperty("secret");
      expect((await signed(dev, "POST", `/v1/hooks/${created.hook.id}/rotate`)).status).toBe(409);
    }
  });

  it("takes only the sender's public key for Ed25519 Standard Webhooks, and shows it", async () => {
    expect(status(() => parseVerify({ preset: "standard-webhooks-ed25519" }))).toBe(400);
    expect(status(() => parseVerify({ preset: "standard-webhooks-ed25519", secret: "whsec_aaaaaaaaaaaaaaaaaaaaaaaa" }))).toBe(400);
    expect(status(() => parseVerify({ preset: "standard-webhooks-ed25519", publicKey: "whpk_AAAA" }))).toBe(400);
    expect(status(() => parseVerify({ preset: "github", publicKey: `whpk_${btoa("x".repeat(32))}` }))).toBe(400);
    const dev = await newAccount();
    const publicKey = `whpk_${btoa(String.fromCharCode(...new Uint8Array(32).fill(7)))}`;
    const { hook, secret } = await createHook(dev, { preset: "standard-webhooks-ed25519", publicKey });
    expect(secret).toBeUndefined();
    expect(hook.verify).toEqual({ preset: "standard-webhooks-ed25519", publicKey });
  });

  it("strict: no secret at the relay, ever", async () => {
    expect(status(() => parseVerify({ preset: "stripe", strict: true, secret: "abcdefghijkl" }))).toBe(400);
    expect(status(() => parseVerify({ preset: "unverified", strict: true }))).toBe(400);
    expect(status(() => parseVerify({ preset: "github", strict: "yes" }))).toBe(400);
    const dev = await newAccount();
    for (const preset of ["github", "stripe", "standard-webhooks"]) {
      const { hook, secret } = await createHook(dev, { preset, strict: true });
      expect(secret, preset).toBeUndefined();
      expect(hook.verify).toEqual({ preset, strict: true });
      expect((await signed(dev, "POST", `/v1/hooks/${hook.id}/rotate`)).status).toBe(409);
    }
  });
});

describe("Stripe", () => {
  it("verifies, types and dedupes on the event id; refuses a replay with a fresh t= and a stale one", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "stripe", secret: STRIPE_SECRET });
    const body = '{"id":"evt_relay_1","type":"invoice.paid","data":{}}';
    const first = await post(hook.id, body, { "Stripe-Signature": await stripeHeader(body) });
    expect(first.status).toBe(200);
    // Stripe's retry: same event, new signature and time.
    const retry = await post(hook.id, body, { "Stripe-Signature": await stripeHeader(body, Math.floor(Date.now() / 1000) - 5) });
    expect(await retry.json()).toEqual({ duplicate: true });
    // A captured header can't be given a fresh time: t= is signed.
    const captured = await stripeHeader(body, Math.floor(Date.now() / 1000) - 400);
    expect((await post(hook.id, body, { "Stripe-Signature": captured })).status).toBe(401);
    const sig = captured.split(",v1=")[1];
    expect((await post(hook.id, body, { "Stripe-Signature": `t=${Math.floor(Date.now() / 1000)},v1=${sig}` })).status).toBe(401);
    // A forged event is refused and counted.
    expect((await post(hook.id, body, { "Stripe-Signature": await stripeHeader(body, undefined, "whsec_wrong") })).status).toBe(401);

    const { sse } = await openStream(dev);
    await sse.nextEvent();
    const ev = data<StreamedEvent>(await sse.nextEvent());
    expect(ev).toMatchObject({ verified: true, strict: false, preset: "stripe", eventType: "invoice.paid" });
    const opened = await openEvent(dev, ev);
    expect(opened.text).toBe(body);
    expect(opened.headers).not.toHaveProperty("stripe-signature");
    await sse.cancel();
    expect((await accountObject(dev.accountId).stats()).events).toBe(1);
  });
});

describe("Slack", () => {
  it("answers url_verification with the challenge only after the signature verifies, and stores nothing", async () => {
    const dev = await newAccount();
    const secret = "slack-signing-secret-01";
    const { hook } = await createHook(dev, { preset: "slack", secret });
    const body = '{"token":"t","challenge":"3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P","type":"url_verification"}';
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = `v0=${toHex(await hmac("SHA-256", utf8(secret), utf8(`v0:${ts}:${body}`)))}`;
    const forged = await post(hook.id, body, { "X-Slack-Request-Timestamp": ts, "X-Slack-Signature": "v0=" + "0".repeat(64) });
    expect(forged.status).toBe(401);
    const res = await post(hook.id, body, { "X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/plain");
    expect(await res.text()).toBe("3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P");
    expect((await accountObject(dev.accountId).stats()).events).toBe(0);
  });
});

describe("Twitch", () => {
  const secret = "twitch-subscription-secret";
  async function twitchHeaders(id: string, body: string, type: string, key = secret) {
    const ts = new Date().toISOString();
    return {
      "Twitch-Eventsub-Message-Id": id,
      "Twitch-Eventsub-Message-Timestamp": ts,
      "Twitch-Eventsub-Message-Signature": `sha256=${toHex(await hmac("SHA-256", utf8(key), utf8(id + ts + body)))}`,
      "Twitch-Eventsub-Message-Type": type,
    };
  }

  it("answers webhook_callback_verification with the challenge only after the signature verifies, and stores nothing", async () => {
    const dev = await newAccount();
    const { hook, secret: generated } = await createHook(dev, { preset: "twitch", secret });
    expect(generated).toBeUndefined();
    const body = '{"challenge":"pogchamp-kappa-360noscope-vohiyo","subscription":{"type":"channel.follow","status":"webhook_callback_verification_pending"}}';
    const forged = await post(hook.id, body, await twitchHeaders("v-1", body, "webhook_callback_verification", "not-the-secret"));
    expect(forged.status).toBe(401);
    const res = await post(hook.id, body, await twitchHeaders("v-1", body, "webhook_callback_verification"));
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/plain; charset=utf-8");
    expect(await res.text()).toBe("pogchamp-kappa-360noscope-vohiyo");
    expect((await accountObject(dev.accountId).stats()).events).toBe(0);
  });

  it("stores notifications and revocations, deduped on the signed message id", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "twitch", secret });
    const body = '{"subscription":{"type":"channel.follow","status":"enabled"},"event":{"user_id":"1337"}}';
    expect((await post(hook.id, body, await twitchHeaders("n-1", body, "notification"))).status).toBe(200);
    // Twitch's resend: the same message id, signed afresh.
    expect(await (await post(hook.id, body, await twitchHeaders("n-1", body, "notification"))).json()).toEqual({ duplicate: true });
    const revoked = '{"subscription":{"type":"channel.follow","status":"authorization_revoked"}}';
    expect((await post(hook.id, revoked, await twitchHeaders("r-1", revoked, "revocation"))).status).toBe(200);

    const { sse } = await openStream(dev);
    await sse.nextEvent();
    const first = data<StreamedEvent>(await sse.nextEvent());
    expect(first).toMatchObject({ verified: true, preset: "twitch", eventType: "channel.follow" });
    const second = data<StreamedEvent>(await sse.nextEvent());
    const opened = await openEvent(dev, second);
    expect(opened.text).toBe(revoked);
    expect(opened.headers["twitch-eventsub-message-type"]).toBe("revocation");
    expect(opened.headers).not.toHaveProperty("twitch-eventsub-message-signature");
    await sse.cancel();
    expect((await accountObject(dev.accountId).stats()).events).toBe(2);
  });
});

describe("Zoom", () => {
  it("answers endpoint.url_validation with the token's HMAC, after the signature verifies, and stores nothing", async () => {
    const dev = await newAccount();
    const secret = "zoom-app-secret-token";
    const { hook } = await createHook(dev, { preset: "zoom", secret });
    const body = '{"payload":{"plainToken":"qgg8vlvZRS6UYooatFL8Aw"},"event_ts":1654503849680,"event":"endpoint.url_validation"}';
    const ts = String(Math.floor(Date.now() / 1000));
    const sign = async (key: string) => `v0=${toHex(await hmac("SHA-256", utf8(key), utf8(`v0:${ts}:${body}`)))}`;
    const forged = await post(hook.id, body, { "x-zm-request-timestamp": ts, "x-zm-signature": await sign("wrong-secret") });
    expect(forged.status).toBe(401);
    const res = await post(hook.id, body, { "x-zm-request-timestamp": ts, "x-zm-signature": await sign(secret) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      plainToken: "qgg8vlvZRS6UYooatFL8Aw",
      encryptedToken: toHex(await hmac("SHA-256", utf8(secret), utf8("qgg8vlvZRS6UYooatFL8Aw"))),
    });
    expect((await accountObject(dev.accountId).stats()).events).toBe(0);
  });

  it("can't be strict: the check needs the secret at the relay", async () => {
    const dev = await newAccount();
    const res = await signed(dev, "POST", "/v1/hooks", { name: "zoom", verify: { preset: "zoom", strict: true } });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ field: "verify.strict" });
  });
});

describe("Twilio", () => {
  it("verifies against the public URL the relay was reached at", async () => {
    const dev = await newAccount();
    const token = "twilio-auth-token-0001";
    const { hook, url } = await createHook(dev, { preset: "twilio", secret: token });
    const form = "To=%2B15005550006&From=%2B15005550001&Body=hi+there&MessageSid=SM1";
    // Twilio signs the URL, then the parameters sorted by name.
    const signedString = `${url}Bodyhi thereFrom+15005550001MessageSidSM1To+15005550006`;
    const raw = await hmac("SHA-1", utf8(token), utf8(signedString));
    const sig = btoa(String.fromCharCode(...raw));
    const ok = await post(hook.id, form, { "Content-Type": "application/x-www-form-urlencoded", "X-Twilio-Signature": sig });
    expect(ok.status).toBe(200);
    // The same signature reached through another URL (a query added) doesn't verify.
    const moved = await post(hook.id, `${form}&x=1`, { "Content-Type": "application/x-www-form-urlencoded", "X-Twilio-Signature": sig }, "?x=1");
    expect(moved.status).toBe(401);
  });
});

describe("strict mode at the edge", () => {
  it("checks only the cheap things: the header's shape and a header timestamp; dedupes on the body hash", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "stripe", strict: true });
    const body = '{"id":"evt_strict_1","type":"invoice.paid"}';
    // No signature header, or a stale t=: refused at the edge.
    expect((await post(hook.id, body)).status).toBe(401);
    expect((await post(hook.id, body, { "Stripe-Signature": await stripeHeader(body, Math.floor(Date.now() / 1000) - 400) })).status).toBe(401);
    // A well-formed header with a wrong signature passes the edge: the device is what refuses it.
    const forged = `t=${Math.floor(Date.now() / 1000)},v1=${"ab".repeat(32)}`;
    expect((await post(hook.id, body, { "Stripe-Signature": forged })).status).toBe(200);
    // The same bytes again are a duplicate (the body hash), whatever the header says.
    expect(await (await post(hook.id, body, { "Stripe-Signature": await stripeHeader(body) })).json()).toEqual({ duplicate: true });

    const { sse } = await openStream(dev);
    await sse.nextEvent();
    const ev = data<StreamedEvent>(await sse.nextEvent());
    // Not verified by the relay; no type (the relay never read the body).
    expect(ev).toMatchObject({ verified: false, strict: true, preset: "stripe", eventType: null });
    const opened = await openEvent(dev, ev);
    // Sealed for the device: the signature header and the URL it needs to verify.
    expect(opened.headers["stripe-signature"]).toBe(forged);
    expect(opened.url).toBe(`https://relay.test/h/${hook.id}`);
    expect(opened.text).toBe(body);
    await sse.cancel();
  });

  it("strictHeaders keeps what the device needs to verify, and the edge never reads the body", async () => {
    const h = new Headers({ "webhook-id": "m1", "webhook-timestamp": "1", "webhook-signature": "v1,AAAA", cookie: "c" });
    expect(strictHeaders({ preset: "standard-webhooks", strict: true }, h)).toEqual({
      "webhook-id": "m1",
      "webhook-timestamp": "1",
      "webhook-signature": "v1,AAAA",
    });
    const tokenHeaders = strictHeaders({ preset: "token", header: "x-hook-token", strict: true }, new Headers({ "x-hook-token": "s" }));
    expect(tokenHeaders).toEqual({ "x-hook-token": "s" });
    // Linear's timestamp is in the body: the strict edge doesn't look, so a stale one passes here.
    const linear = await verifyDelivery({ preset: "linear", strict: true }, [], {
      body: utf8('{"webhookTimestamp":1}'),
      headers: new Headers({ "linear-signature": "ab".repeat(32) }),
      now: Date.now(),
    });
    expect(linear).toMatchObject({ ok: true, verified: false, eventType: null });
    expect(linear.dedupeKeys).toEqual([expect.stringMatching(/^body:/)]);
  });
});
