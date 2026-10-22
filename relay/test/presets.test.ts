// Every preset's verification against known vectors: GitHub's documented example, the Standard
// Webhooks specification's vector, and RFC 4231 / RFC 2202 for the generic HMAC preset.

import { describe, expect, it } from "vitest";
import { utf8 } from "../src/encoding.ts";
import {
  EVENT_TYPE_SOURCE,
  PRESETS,
  generateSecret,
  handshakeAnswer,
  keptHeaders,
  parseVerify,
  relayGeneratesSecret,
  rfc3339Ms,
  signsTimestamp,
  strictHeaders,
  verifyDelivery,
  type VerifyConfig,
} from "../src/presets.ts";
import { hmac, toBase64, toHex } from "../src/encoding.ts";
import { HttpError } from "../src/http.ts";
import { fromBase64 } from "../src/encoding.ts";

const NOW = Date.UTC(2026, 9, 1);

function delivery(body: string, headers: Record<string, string>, now = NOW) {
  return { body: utf8(body), headers: new Headers(headers), now };
}

describe("github", () => {
  // https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#testing-the-webhook-payload-validation
  const secret = "It's a Secret to Everybody";
  const signature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
  const config: VerifyConfig = { preset: "github" };

  it("accepts GitHub's documented example", async () => {
    const v = await verifyDelivery(config, [secret], delivery("Hello, World!", {
      "X-Hub-Signature-256": signature,
      "X-GitHub-Event": "push",
      "X-GitHub-Delivery": "72d3162e-cc78-11e3-81ab-4c9367dc0958",
    }));
    expect(v).toEqual({
      ok: true,
      verified: true,
      // The delivery id isn't signed, so the body's hash is always a mark too (a replay of the same
      // body under a new delivery id is a duplicate).
      dedupeKeys: ["delivery:72d3162e-cc78-11e3-81ab-4c9367dc0958", expect.stringMatching(/^body:[0-9a-f]{64}$/)],
      eventType: "push",
    });
  });

  it("marks the same body under any delivery id with the same body key", async () => {
    const h = { "X-Hub-Signature-256": signature, "X-GitHub-Event": "push" };
    const a = await verifyDelivery(config, [secret], delivery("Hello, World!", { ...h, "X-GitHub-Delivery": "one" }));
    const b = await verifyDelivery(config, [secret], delivery("Hello, World!", { ...h, "X-GitHub-Delivery": "two" }));
    expect(a.dedupeKeys[1]).toBe(b.dedupeKeys[1]);
    expect(a.dedupeKeys[0]).not.toBe(b.dedupeKeys[0]);
  });

  it("caps the (unsigned) event type", async () => {
    const v = await verifyDelivery(config, [secret], delivery("Hello, World!", {
      "X-Hub-Signature-256": signature,
      "X-GitHub-Event": "x".repeat(5000),
    }));
    expect(v.eventType).toHaveLength(200);
  });

  it("refuses a changed body, a wrong secret, a missing or malformed header", async () => {
    expect((await verifyDelivery(config, [secret], delivery("Hello, World?", { "X-Hub-Signature-256": signature }))).ok).toBe(false);
    expect((await verifyDelivery(config, ["another secret"], delivery("Hello, World!", { "X-Hub-Signature-256": signature }))).ok).toBe(false);
    expect((await verifyDelivery(config, [secret], delivery("Hello, World!", {}))).ok).toBe(false);
    expect((await verifyDelivery(config, [secret], delivery("Hello, World!", { "X-Hub-Signature-256": signature.slice(7) }))).ok).toBe(false);
    expect((await verifyDelivery(config, [secret], delivery("Hello, World!", { "X-Hub-Signature-256": "sha256=zz" }))).ok).toBe(false);
  });

  it("accepts any currently valid secret (rotation overlap)", async () => {
    const v = await verifyDelivery(config, ["the new one", secret], delivery("Hello, World!", { "X-Hub-Signature-256": signature }));
    expect(v.ok).toBe(true);
  });

  it("dedupes on the body hash when there's no delivery id", async () => {
    const v = await verifyDelivery(config, [secret], delivery("Hello, World!", { "X-Hub-Signature-256": signature }));
    expect(v.dedupeKeys).toEqual([expect.stringMatching(/^body:[0-9a-f]{64}$/)]);
  });
});

describe("standard-webhooks", () => {
  // The Standard Webhooks specification's example (also Svix's documented vector).
  const secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
  const id = "msg_p5jXN8AQM9LWM0D4loKWxJek";
  const ts = "1614265330";
  const body = '{"test": 2432232314}';
  const sig = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";
  const config: VerifyConfig = { preset: "standard-webhooks" };
  const at = Number(ts) * 1000;

  it("accepts the specification's vector", async () => {
    const v = await verifyDelivery(config, [secret], delivery(body, { "webhook-id": id, "webhook-timestamp": ts, "webhook-signature": sig }, at));
    // The id is signed (id.timestamp.body), so the id alone is the replay key.
    expect(v).toEqual({ ok: true, verified: true, dedupeKeys: [`id:${id}`], eventType: null });
  });

  it("accepts one valid signature among several, and reads the payload's type", async () => {
    const typed = '{"type":"invoice.paid"}';
    const s = await import("../src/encoding.ts");
    const key = fromBase64(secret.slice(6))!;
    const mac = await s.hmac("SHA-256", key, utf8(`${id}.${ts}.${typed}`));
    const header = `v1,AAAA v1a,whatever v1,${s.toBase64(mac)}`;
    const v = await verifyDelivery(config, [secret], delivery(typed, { "webhook-id": id, "webhook-timestamp": ts, "webhook-signature": header }, at));
    expect(v.ok).toBe(true);
    expect(v.eventType).toBe("invoice.paid");
  });

  it("refuses timestamps outside 300 s, either way", async () => {
    const h = { "webhook-id": id, "webhook-timestamp": ts, "webhook-signature": sig };
    expect((await verifyDelivery(config, [secret], delivery(body, h, at + 301_000))).ok).toBe(false);
    expect((await verifyDelivery(config, [secret], delivery(body, h, at - 301_000))).ok).toBe(false);
    expect((await verifyDelivery(config, [secret], delivery(body, h, at + 299_000))).ok).toBe(true);
  });

  it("refuses a changed id, body or secret", async () => {
    const h = { "webhook-id": id, "webhook-timestamp": ts, "webhook-signature": sig };
    expect((await verifyDelivery(config, [secret], delivery(body, { ...h, "webhook-id": "msg_other" }, at))).ok).toBe(false);
    expect((await verifyDelivery(config, [secret], delivery(body + " ", h, at))).ok).toBe(false);
    expect((await verifyDelivery(config, [generateSecret("standard-webhooks")], delivery(body, h, at))).ok).toBe(false);
  });
});

describe("hmac", () => {
  // RFC 4231 test case 2 (SHA-256) and RFC 2202 test case 2 (SHA-1).
  const key = "Jefe";
  const body = "what do ya want for nothing?";

  it("sha256 / hex with a prefix", async () => {
    const config: VerifyConfig = { preset: "hmac", header: "x-signature", algorithm: "sha256", encoding: "hex", prefix: "sha256=" };
    const good = "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    const v = await verifyDelivery(config, [key], delivery(body, { "X-Signature": good }));
    expect(v.ok).toBe(true);
    expect(v.dedupeKeys).toEqual([expect.stringMatching(/^body:[0-9a-f]{64}$/)]);
    expect((await verifyDelivery(config, [key], delivery(body, { "X-Signature": good.slice(7) }))).ok).toBe(false);
    expect((await verifyDelivery(config, [key], delivery(body, { "X-Signature": good.replace("5b", "5c") }))).ok).toBe(false);
  });

  it("sha1 / base64 and sha1 / hex", async () => {
    const b64: VerifyConfig = { preset: "hmac", header: "x-sig", algorithm: "sha1", encoding: "base64" };
    expect((await verifyDelivery(b64, [key], delivery(body, { "x-sig": "7/zfauXrL6LSdBbV8YTfnCWafHk=" }))).ok).toBe(true);
    const hex: VerifyConfig = { preset: "hmac", header: "x-sig", algorithm: "sha1", encoding: "hex" };
    expect((await verifyDelivery(hex, [key], delivery(body, { "x-sig": "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" }))).ok).toBe(true);
    expect((await verifyDelivery(hex, [key], delivery(body, { "x-sig": "7/zfauXrL6LSdBbV8YTfnCWafHk=" }))).ok).toBe(false);
  });
});

describe("token", () => {
  it("compares a bearer token, or a custom header's raw value", async () => {
    const bearer: VerifyConfig = { preset: "token", header: "authorization" };
    expect((await verifyDelivery(bearer, ["s3cret-token"], delivery("{}", { Authorization: "Bearer s3cret-token" }))).ok).toBe(true);
    expect((await verifyDelivery(bearer, ["s3cret-token"], delivery("{}", { Authorization: "bearer s3cret-token" }))).ok).toBe(true);
    expect((await verifyDelivery(bearer, ["s3cret-token"], delivery("{}", { Authorization: "s3cret-token" }))).ok).toBe(false);
    expect((await verifyDelivery(bearer, ["s3cret-token"], delivery("{}", { Authorization: "Bearer s3cret-tokeN" }))).ok).toBe(false);
    const custom: VerifyConfig = { preset: "token", header: "x-hook-token" };
    expect((await verifyDelivery(custom, ["abcdefgh"], delivery("{}", { "x-hook-token": "abcdefgh" }))).ok).toBe(true);
    expect((await verifyDelivery(custom, ["abcdefgh"], delivery("{}", { "x-hook-token": "abcdefg" }))).ok).toBe(false);
  });
});

describe("unverified", () => {
  it("accepts anything, marked unverified", async () => {
    const v = await verifyDelivery({ preset: "unverified" }, [], delivery("anything", {}));
    expect(v).toEqual({ ok: true, verified: false, dedupeKeys: [], eventType: null });
  });
});

describe("parseVerify", () => {
  it("validates fields and applies the hmac defaults", () => {
    expect(parseVerify({ preset: "hmac", header: "X-Sig" }).config).toEqual({
      preset: "hmac",
      header: "x-sig",
      algorithm: "sha256",
      encoding: "hex",
    });
    expect(parseVerify({ preset: "token" }).config).toEqual({ preset: "token", header: "authorization" });
    const bad = (v: unknown) => {
      try {
        parseVerify(v);
      } catch (e) {
        return e instanceof HttpError ? e.response.status : 0;
      }
      return 200;
    };
    expect(bad({ preset: "stripe" })).toBe(400);
    expect(bad({ preset: "hmac" })).toBe(400);
    expect(bad({ preset: "hmac", header: "x", algorithm: "md5" })).toBe(400);
    expect(bad({ preset: "standard-webhooks", secret: "not-whsec" })).toBe(400);
    expect(bad({ preset: "unverified", secret: "abcdefghij" })).toBe(400);
    expect(bad({ preset: "github", secret: "short" })).toBe(400);
  });

  it("generates 32-byte secrets in the provider's form", () => {
    const sw = generateSecret("standard-webhooks");
    expect(sw.startsWith("whsec_")).toBe(true);
    expect(fromBase64(sw.slice(6))!.byteLength).toBe(32);
    const gh = generateSecret("github");
    expect(fromBase64(gh)!.byteLength).toBe(32);
    expect(generateSecret("github")).not.toBe(gh);
  });
});

describe("keptHeaders", () => {
  it("keeps the preset's allowlist and never cookies or credentials", () => {
    const h = new Headers({
      "Content-Type": "application/json",
      "User-Agent": "GitHub-Hookshot/abc",
      "X-GitHub-Event": "push",
      "X-GitHub-Delivery": "d1",
      "X-Hub-Signature-256": "sha256=00",
      Cookie: "session=1",
      Authorization: "Bearer x",
      "X-Forwarded-For": "1.2.3.4",
    });
    expect(keptHeaders({ preset: "github" }, h)).toEqual({
      "content-type": "application/json",
      "user-agent": "GitHub-Hookshot/abc",
      "x-github-event": "push",
      "x-github-delivery": "d1",
    });
    expect(keptHeaders({ preset: "token", header: "authorization" }, h)).toEqual({
      "content-type": "application/json",
      "user-agent": "GitHub-Hookshot/abc",
    });
    // Even an hmac hook whose signature header is `authorization` doesn't keep it.
    expect(keptHeaders({ preset: "hmac", header: "authorization", algorithm: "sha256", encoding: "hex" }, h)).not.toHaveProperty(
      "authorization",
    );
  });

  it("keeps the runner's loop-prevention headers for every preset", () => {
    const h = new Headers({ "00hooks-origin": "dev_abc", "00hooks-hop": "2", "X-Other": "x" });
    for (const config of [
      { preset: "github" },
      { preset: "standard-webhooks" },
      { preset: "hmac", header: "x-sig", algorithm: "sha256", encoding: "hex" },
      { preset: "token", header: "x-token" },
      { preset: "unverified" },
    ] as const) {
      expect(keptHeaders(config, h)).toEqual({ "00hooks-origin": "dev_abc", "00hooks-hop": "2" });
    }
  });

  it("never keeps a signature header, whatever the preset calls it", () => {
    const h = new Headers({
      "Content-Type": "application/json",
      "X-Hub-Signature-256": "sha256=00",
      "X-Hub-Signature": "sha1=00",
      "webhook-id": "msg_1",
      "webhook-timestamp": "1",
      "webhook-signature": "v1,AAAA",
      "X-Custom-Sig": "abcd",
      "X-Hook-Token": "secret",
    });
    const all = [
      keptHeaders({ preset: "github" }, h),
      keptHeaders({ preset: "standard-webhooks" }, h),
      keptHeaders({ preset: "hmac", header: "x-custom-sig", algorithm: "sha256", encoding: "hex" }, h),
      keptHeaders({ preset: "token", header: "x-hook-token" }, h),
      keptHeaders({ preset: "unverified" }, h),
    ];
    for (const kept of all) {
      for (const name of ["x-hub-signature-256", "x-hub-signature", "webhook-signature", "x-custom-sig", "x-hook-token"]) {
        expect(kept).not.toHaveProperty(name);
      }
    }
    expect(all[1]).toEqual({ "content-type": "application/json", "webhook-id": "msg_1", "webhook-timestamp": "1" });
  });
});

describe("what each preset signs", () => {
  it("says for every preset whether eventType is covered by the signature", () => {
    expect(Object.keys(EVENT_TYPE_SOURCE).sort()).toEqual([...PRESETS].sort());
    expect(EVENT_TYPE_SOURCE).toEqual({
      github: "claimed",
      "standard-webhooks": "signed",
      "standard-webhooks-ed25519": "signed",
      stripe: "signed",
      slack: "signed",
      linear: "signed",
      shopify: "claimed",
      twilio: "none",
      meta: "signed",
      calendly: "signed",
      typeform: "signed",
      paddle: "signed",
      twitch: "signed",
      zoom: "signed",
      pagerduty: "signed",
      hmac: "none",
      token: "none",
      unverified: "none",
    });
  });
});

// The presets added from the providers' documented schemes (PLAN §4.2). Their known-answer vectors
// are in fixtures/presets.v1.json; these pin what the vectors can't: marks, types, kept headers,
// the strict edge and the endpoint checks.
describe("calendly, typeform, paddle, twitch, zoom, pagerduty", () => {
  const T = 1_792_233_600;
  const hex = async (key: string, msg: string) => toHex(await hmac("SHA-256", utf8(key), utf8(msg)));
  const b64 = async (key: string, msg: string) => toBase64(await hmac("SHA-256", utf8(key), utf8(msg)));

  it("signs a timestamp where the provider does; Zoom's isn't checked (no documented window)", () => {
    for (const p of ["calendly", "paddle", "twitch"] as const) expect(signsTimestamp({ preset: p }), p).toBe(true);
    // No checked timestamp: their body-hash marks are kept REPLAY_MARK_DAYS (receive.ts).
    for (const p of ["typeform", "zoom", "pagerduty"] as const) expect(signsTimestamp({ preset: p }), p).toBe(false);
  });

  it("generates the secret only where the receiver chooses it", () => {
    expect(["calendly", "typeform", "twitch"].every((p) => relayGeneratesSecret(p as never))).toBe(true);
    expect(["paddle", "zoom", "pagerduty"].some((p) => relayGeneratesSecret(p as never))).toBe(false);
    const bad = (v: unknown) => {
      try {
        parseVerify(v);
      } catch (e) {
        return e instanceof HttpError ? (e.response.status as number) : 0;
      }
      return 200;
    };
    for (const p of ["paddle", "zoom", "pagerduty"]) expect(bad({ preset: p }), p).toBe(400);
    for (const p of ["calendly", "typeform", "twitch"]) expect(bad({ preset: p }), p).toBe(200);
    // Zoom's endpoint check needs the secret at the relay, so a strict zoom hook could never pass it.
    expect(bad({ preset: "zoom", strict: true })).toBe(400);
    expect(bad({ preset: "twitch", strict: true })).toBe(200);
  });

  it("calendly: dedupes on the body hash, types from the signed body", async () => {
    const body = '{"event":"invitee.canceled","payload":{}}';
    const v = await verifyDelivery({ preset: "calendly" }, ["calendly-key"], delivery(body, {
      "Calendly-Webhook-Signature": `t=${T},v1=${await hex("calendly-key", `${T}.${body}`)}`,
    }, T * 1000));
    expect(v).toEqual({ ok: true, verified: true, dedupeKeys: [expect.stringMatching(/^body:[0-9a-f]{64}$/)], eventType: "invitee.canceled" });
    // A `t` in the future beyond 3 minutes is refused too.
    const ahead = await verifyDelivery({ preset: "calendly" }, ["calendly-key"], delivery(body, {
      "Calendly-Webhook-Signature": `t=${T + 181},v1=${await hex("calendly-key", `${T + 181}.${body}`)}`,
    }, T * 1000));
    expect(ahead.ok).toBe(false);
  });

  it("typeform: the signed event_id and the body hash are the marks", async () => {
    const body = '{"event_id":"01ABC","event_type":"form_response"}';
    const v = await verifyDelivery({ preset: "typeform" }, ["tf-secret"], delivery(body, { "Typeform-Signature": `sha256=${await b64("tf-secret", body)}` }));
    expect(v.dedupeKeys).toEqual(["id:01ABC", expect.stringMatching(/^body:/)]);
    expect(v.eventType).toBe("form_response");
  });

  it("paddle: the signed event_id is the mark; a lone h1 without ts is refused", async () => {
    const body = '{"event_id":"evt_01","event_type":"subscription.created"}';
    const sig = await hex("pdl_ntfset_x", `${T}:${body}`);
    const v = await verifyDelivery({ preset: "paddle" }, ["pdl_ntfset_x"], delivery(body, { "Paddle-Signature": `ts=${T};h1=${sig}` }, T * 1000));
    expect(v).toMatchObject({ ok: true, dedupeKeys: ["id:evt_01", expect.stringMatching(/^body:/)], eventType: "subscription.created" });
    expect((await verifyDelivery({ preset: "paddle" }, ["pdl_ntfset_x"], delivery(body, { "Paddle-Signature": `h1=${sig}` }, T * 1000))).ok).toBe(false);
    // Two ts values: which one was signed is ambiguous, so neither is taken.
    const two = `ts=${T};ts=${T + 1};h1=${sig}`;
    expect((await verifyDelivery({ preset: "paddle" }, ["pdl_ntfset_x"], delivery(body, { "Paddle-Signature": two }, T * 1000))).ok).toBe(false);
  });

  it("twitch: the signed message id is the mark, a revocation is an ordinary event", async () => {
    const id = "msg-1";
    const ts = new Date(T * 1000).toISOString();
    const body = '{"subscription":{"type":"channel.follow","status":"authorization_revoked"}}';
    const headers = {
      "Twitch-Eventsub-Message-Id": id,
      "Twitch-Eventsub-Message-Timestamp": ts,
      "Twitch-Eventsub-Message-Signature": `sha256=${await hex("twitch-secret", id + ts + body)}`,
      "Twitch-Eventsub-Message-Type": "revocation",
    };
    const v = await verifyDelivery({ preset: "twitch" }, ["twitch-secret"], delivery(body, headers, T * 1000));
    expect(v).toEqual({ ok: true, verified: true, dedupeKeys: [`id:${id}`], eventType: "channel.follow" });
    expect(await handshakeAnswer({ preset: "twitch" }, ["twitch-secret"], delivery(body, headers, T * 1000))).toBeNull();
    expect(keptHeaders({ preset: "twitch" }, new Headers(headers))).toEqual({
      "twitch-eventsub-message-id": id,
      "twitch-eventsub-message-type": "revocation",
    });
  });

  it("parses RFC 3339 exactly, and nothing else", () => {
    expect(rfc3339Ms("2019-11-16T10:11:12.634234626Z")).toBe(Date.UTC(2019, 10, 16, 10, 11, 12, 634));
    expect(rfc3339Ms("2019-11-16T10:11:12Z")).toBe(Date.UTC(2019, 10, 16, 10, 11, 12));
    expect(rfc3339Ms("2019-11-16T12:11:12.5+02:00")).toBe(Date.UTC(2019, 10, 16, 10, 11, 12, 500));
    expect(rfc3339Ms("2019-11-16T05:41:12-04:30")).toBe(Date.UTC(2019, 10, 16, 10, 11, 12));
    expect(rfc3339Ms("2024-02-29T00:00:00Z")).toBe(Date.UTC(2024, 1, 29));
    for (const bad of [
      "2023-02-29T00:00:00Z",
      "2019-13-01T00:00:00Z",
      "2019-11-16T24:00:00Z",
      "2019-11-16T23:59:60Z",
      "2019-11-16 10:11:12Z",
      "2019-11-16T10:11:12",
      "2019-11-16t10:11:12z",
      "2019-11-16T10:11:12.Z",
      "2019-11-16T10:11:12.1234567890Z",
      "0050-01-01T00:00:00Z",
      "1792233600",
      " 2019-11-16T10:11:12Z",
    ]) {
      expect(rfc3339Ms(bad), bad).toBeNull();
    }
  });

  it("strict at the edge: header timestamps (Twitch's RFC 3339, Paddle's ts) are checked, nothing else", async () => {
    const now = T * 1000;
    const twitch = (ts: string) =>
      verifyDelivery({ preset: "twitch", strict: true }, [], delivery("{}", {
        "Twitch-Eventsub-Message-Id": "m",
        "Twitch-Eventsub-Message-Timestamp": ts,
        "Twitch-Eventsub-Message-Signature": `sha256=${"ab".repeat(32)}`,
      }, now));
    expect((await twitch(new Date(now - 599_000).toISOString())).ok).toBe(true);
    expect((await twitch(new Date(now - 601_000).toISOString())).ok).toBe(false);
    expect((await twitch("yesterday")).ok).toBe(false);
    const paddle = (ts: number) =>
      verifyDelivery({ preset: "paddle", strict: true }, [], delivery("{}", { "Paddle-Signature": `ts=${ts};h1=${"ab".repeat(32)}` }, now));
    expect(await paddle(T)).toMatchObject({ ok: true, verified: false, eventType: null });
    expect((await paddle(T - 6)).ok).toBe(false);
    // Sealed for the device: the signature and every signed header.
    expect(
      strictHeaders({ preset: "twitch", strict: true }, new Headers({
        "Twitch-Eventsub-Message-Id": "m",
        "Twitch-Eventsub-Message-Timestamp": "t",
        "Twitch-Eventsub-Message-Signature": "sha256=00",
      })),
    ).toEqual({ "twitch-eventsub-message-id": "m", "twitch-eventsub-message-timestamp": "t", "twitch-eventsub-message-signature": "sha256=00" });
  });

  it("never keeps the new presets' signature headers", () => {
    const h = new Headers({
      "Calendly-Webhook-Signature": "t=1,v1=00",
      "Typeform-Signature": "sha256=AA==",
      "Paddle-Signature": "ts=1;h1=00",
      "Twitch-Eventsub-Message-Signature": "sha256=00",
      "x-zm-signature": "v0=00",
      "X-PagerDuty-Signature": "v1=00",
      "x-zm-request-timestamp": "1",
      "X-Webhook-Id": "w1",
    });
    for (const preset of ["calendly", "typeform", "paddle", "twitch", "zoom", "pagerduty"] as const) {
      const kept = keptHeaders({ preset }, h);
      for (const name of Object.keys(kept)) expect(name, preset).not.toMatch(/signature/);
    }
    expect(keptHeaders({ preset: "zoom" }, h)).toEqual({ "x-zm-request-timestamp": "1" });
    expect(keptHeaders({ preset: "pagerduty" }, h)).toEqual({ "x-webhook-id": "w1" });
  });

  it("pagerduty: the signed event.id is the mark", async () => {
    const body = '{"event":{"id":"e-1","event_type":"incident.triggered"}}';
    const v = await verifyDelivery({ preset: "pagerduty" }, ["pd"], delivery(body, { "X-PagerDuty-Signature": `v1=${await hex("pd", body)}` }));
    expect(v).toMatchObject({ ok: true, dedupeKeys: ["id:e-1", expect.stringMatching(/^body:/)], eventType: "incident.triggered" });
  });
});

describe("endpoint checks (handshakeAnswer)", () => {
  const T = 1_792_233_600;
  const hex = async (key: string, msg: string) => toHex(await hmac("SHA-256", utf8(key), utf8(msg)));

  it("slack: echoes a safe challenge, ignores anything else", async () => {
    const ok = await handshakeAnswer({ preset: "slack" }, [], delivery('{"type":"url_verification","challenge":"abc-123"}', {}));
    expect(ok?.headers.get("Content-Type")).toContain("text/plain");
    expect(await ok?.text()).toBe("abc-123");
    expect(await handshakeAnswer({ preset: "slack" }, [], delivery('{"type":"url_verification","challenge":"<b>"}', {}))).toBeNull();
    expect(await handshakeAnswer({ preset: "slack" }, [], delivery('{"type":"event_callback","challenge":"abc"}', {}))).toBeNull();
    expect(await handshakeAnswer({ preset: "github" }, [], delivery('{"type":"url_verification","challenge":"abc"}', {}))).toBeNull();
  });

  it("twitch: only a webhook_callback_verification with a safe challenge", async () => {
    const body = '{"challenge":"pogchamp-kappa-360noscope-vohiyo","subscription":{"type":"channel.follow"}}';
    const verification = { "Twitch-Eventsub-Message-Type": "webhook_callback_verification" };
    const ok = await handshakeAnswer({ preset: "twitch" }, [], delivery(body, verification));
    expect(ok?.status).toBe(200);
    expect(ok?.headers.get("Content-Type")).toBe("text/plain; charset=utf-8");
    expect(await ok?.text()).toBe("pogchamp-kappa-360noscope-vohiyo");
    expect(await handshakeAnswer({ preset: "twitch" }, [], delivery(body, { "Twitch-Eventsub-Message-Type": "notification" }))).toBeNull();
    expect(await handshakeAnswer({ preset: "twitch" }, [], delivery(body, {}))).toBeNull();
    const long = JSON.stringify({ challenge: "a".repeat(201) });
    expect(await handshakeAnswer({ preset: "twitch" }, [], delivery(long, verification))).toBeNull();
    expect(await handshakeAnswer({ preset: "twitch" }, [], delivery('{"challenge":"a\nb"}', verification))).toBeNull();
  });

  it("zoom: the token's HMAC under the secret that verified, from a signed body only", async () => {
    const secret = "zoom-secret-token";
    const body = '{"payload":{"plainToken":"qgg8vlvZRS6UYooatFL8Aw"},"event_ts":1654503849680,"event":"endpoint.url_validation"}';
    const headers = { "x-zm-request-timestamp": String(T), "x-zm-signature": `v0=${await hex(secret, `v0:${T}:${body}`)}` };
    // The previous secret first: the answer uses the one that verified.
    const res = await handshakeAnswer({ preset: "zoom" }, ["an-older-secret", secret], delivery(body, headers));
    expect(res?.headers.get("Content-Type")).toContain("application/json");
    expect(await res?.json()).toEqual({ plainToken: "qgg8vlvZRS6UYooatFL8Aw", encryptedToken: await hex(secret, "qgg8vlvZRS6UYooatFL8Aw") });
    // Signed with another secret: no answer (receive.ts has refused it already; this is the backstop).
    expect(await handshakeAnswer({ preset: "zoom" }, ["another"], delivery(body, headers))).toBeNull();
    // A token that could make the answer a signature over "v0:…" is never answered.
    const colon = '{"payload":{"plainToken":"v0:1:{}"},"event":"endpoint.url_validation"}';
    const colonHeaders = { "x-zm-request-timestamp": String(T), "x-zm-signature": `v0=${await hex(secret, `v0:${T}:${colon}`)}` };
    expect(await handshakeAnswer({ preset: "zoom" }, [secret], delivery(colon, colonHeaders))).toBeNull();
    // An ordinary event isn't a check.
    const event = '{"event":"meeting.started","payload":{"plainToken":"x"}}';
    const eventHeaders = { "x-zm-request-timestamp": String(T), "x-zm-signature": `v0=${await hex(secret, `v0:${T}:${event}`)}` };
    expect(await handshakeAnswer({ preset: "zoom" }, [secret], delivery(event, eventHeaders))).toBeNull();
  });
});
