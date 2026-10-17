// Signed requests (PROTOCOL §1).

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../src/index.ts";
import { canonicalString, generateDeviceKey, newNonce, signRequest } from "../src/canonical.ts";
import { utf8 } from "../src/encoding.ts";
import { BASE, fetchRelay, newAccount, signed } from "./helpers.ts";

describe("canonical string", () => {
  it("is the seven lines of PROTOCOL §1, joined with \\n", () => {
    expect(
      canonicalString({
        host: "Relay.Example:8443",
        method: "post",
        pathAndQuery: "/v1/hooks?x=1",
        time: "1792233600000",
        nonce: "AAAAAAAAAAAAAAAAAAAAAA",
        bodySha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      }),
    ).toBe(
      "00hooks-v1\nrelay.example:8443\nPOST\n/v1/hooks?x=1\n1792233600000\nAAAAAAAAAAAAAAAAAAAAAA\n" +
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("makes 22-character base64url nonces", () => {
    expect(newNonce()).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });
});

describe("signed requests", () => {
  it("accepts a correctly signed request", async () => {
    const dev = await newAccount();
    const res = await signed(dev, "GET", "/v1/devices");
    expect(res.status).toBe(200);
  });

  it("signs the host with a non-default port and the query string", async () => {
    const dev = await newAccount();
    const url = "https://relay.test:8443/v1/hooks?page=1";
    const call = async (target: string, signedFor: string) => {
      const ctx = createExecutionContext();
      const res = await worker.fetch(new Request(target, { headers: await signRequest(dev, "GET", signedFor) }), env, ctx);
      await waitOnExecutionContext(ctx);
      return res.status;
    };
    expect(await call(url, url)).toBe(200);
    expect(await call("https://relay.test/v1/hooks?page=1", url)).toBe(401);
    expect(await call("https://relay.test:8443/v1/hooks?page=2", url)).toBe(401);
  });

  it("refuses a signature from another key, without saying which check failed", async () => {
    const dev = await newAccount();
    const other = await generateDeviceKey();
    const res = await signed({ deviceId: dev.deviceId, privateKey: other.privateKey }, "GET", "/v1/devices");
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized", message: "The request isn't signed by a known device." });
  });

  it("refuses a body, method or path other than the one signed", async () => {
    const dev = await newAccount();
    const body = utf8(JSON.stringify({ name: "a", verify: { preset: "unverified" } }));
    const headers = await signRequest(dev, "POST", `${BASE}/v1/hooks`, body);
    const tampered = await fetchRelay("/v1/hooks", {
      method: "POST",
      headers,
      body: JSON.stringify({ name: "b", verify: { preset: "unverified" } }),
    });
    expect(tampered.status).toBe(401);
    const otherPath = await fetchRelay("/v1/devices", { headers: await signRequest(dev, "GET", `${BASE}/v1/hooks`) });
    expect(otherPath.status).toBe(401);
    const otherMethod = await fetchRelay("/v1/hooks", { method: "GET", headers: await signRequest(dev, "POST", `${BASE}/v1/hooks`) });
    expect(otherMethod.status).toBe(401);
  });

  it("refuses a stale or future time with clock_skew and the server's time", async () => {
    const dev = await newAccount();
    for (const skew of [-301_000, 301_000]) {
      const before = Date.now();
      const res = await signed(dev, "GET", "/v1/devices", undefined, { time: Date.now() + skew });
      expect(res.status).toBe(401);
      const body = (await res.json()) as { error: string; serverTime: number; message: string };
      expect(body.error).toBe("clock_skew");
      expect(body.serverTime).toBeGreaterThanOrEqual(before);
      expect(body.message).toBeTypeOf("string");
    }
    // Inside the window is fine.
    expect((await signed(dev, "GET", "/v1/devices", undefined, { time: Date.now() - 290_000 })).status).toBe(200);
  });

  it("refuses a reused nonce, on GET requests too", async () => {
    const dev = await newAccount();
    const nonce = newNonce();
    expect((await signed(dev, "GET", "/v1/devices", undefined, { nonce })).status).toBe(200);
    expect((await signed(dev, "GET", "/v1/devices", undefined, { nonce })).status).toBe(401);
    // A replay of the exact same request (same time too) is refused.
    const headers = await signRequest(dev, "GET", `${BASE}/v1/hooks`);
    expect((await fetchRelay("/v1/hooks", { headers })).status).toBe(200);
    expect((await fetchRelay("/v1/hooks", { headers })).status).toBe(401);
  });

  it("refuses a revoked device", async () => {
    const dev = await newAccount();
    expect((await signed(dev, "DELETE", `/v1/devices/${dev.deviceId}`)).status).toBe(204);
    expect((await signed(dev, "GET", "/v1/devices")).status).toBe(401);
  });

  it("refuses missing or malformed headers", async () => {
    const dev = await newAccount();
    const headers = await signRequest(dev, "GET", `${BASE}/v1/devices`);
    for (const drop of Object.keys(headers)) {
      const h = { ...headers };
      delete h[drop];
      expect((await fetchRelay("/v1/devices", { headers: h })).status).toBe(401);
    }
    expect((await fetchRelay("/v1/devices", { headers: { ...headers, "X-00h-Nonce": "short" } })).status).toBe(401);
    expect((await fetchRelay("/v1/devices", { headers: { ...headers, "X-00h-Device": "dev_nope" } })).status).toBe(401);
  });
});

describe("/v1/info and signups", () => {
  it("reports the version, protocol and whether signups are open", async () => {
    const res = await fetchRelay("/v1/info");
    const info = (await res.json()) as Record<string, unknown>;
    expect(info).toMatchObject({ protocol: 1, signupOpen: true });
    expect(info.version).toBeTypeOf("string");
    expect(info.serverTime).toBeTypeOf("number");
  });

  it("gates account creation behind SIGNUP_TOKEN when it's set", async () => {
    const gated = { ...env, SIGNUP_TOKEN: "test-signup-token" };
    const call = async (auth?: string) => {
      const { publicKey } = await generateDeviceKey();
      const ctx = createExecutionContext();
      const res = await worker.fetch(
        new Request(`${BASE}/v1/accounts`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...(auth ? { Authorization: auth } : {}) },
          body: JSON.stringify({ deviceName: "x", publicKey }),
        }),
        gated,
        ctx,
      );
      await waitOnExecutionContext(ctx);
      return res;
    };
    expect((await call()).status).toBe(401);
    expect((await call("Bearer wrong-token")).status).toBe(401);
    expect((await call("Bearer test-signup-token")).status).toBe(201);
    const info = await worker.fetch(new Request(`${BASE}/v1/info`), gated, createExecutionContext());
    expect(((await info.json()) as { signupOpen: boolean }).signupOpen).toBe(false);
  });
});
