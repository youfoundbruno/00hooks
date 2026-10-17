// Every preset's verification against known vectors: GitHub's documented example, the Standard
// Webhooks specification's vector, and RFC 4231 / RFC 2202 for the generic HMAC preset.

import { describe, expect, it } from "vitest";
import { utf8 } from "../src/encoding.ts";
import {
  EVENT_TYPE_SOURCE,
  PRESETS,
  generateSecret,
  keptHeaders,
  parseVerify,
  verifyDelivery,
  type VerifyConfig,
} from "../src/presets.ts";
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
      hmac: "none",
      token: "none",
      unverified: "none",
    });
  });
});
