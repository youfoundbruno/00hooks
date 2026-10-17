// Signed requests (PROTOCOL §1).

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../src/index.ts";
import { bodyHash, canonicalString, generateDeviceKey, importPublicKey, newNonce, signRequest } from "../src/canonical.ts";
import { fromBase64, fromHex, toBase64, utf8 } from "../src/encoding.ts";
import { BASE, RELAY_PUBLIC_KEY, enrolDevice, fetchRelay, newAccount, signed } from "./helpers.ts";

describe("canonical string", () => {
  // PROTOCOL §1's example: both the relay and the CLI test against it.
  const vector = {
    seedHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    publicKey: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
    deviceId: "dev_0123456789abcdefghjkmnpq",
    url: "https://relay.example.com/v1/hooks?limit=10",
    time: "1792233600000",
    nonce: "AAECAwQFBgcICQoLDA0ODw",
    body: '{"name":"ci","verify":{"preset":"github"}}',
    bodySha256: "871ec9aaacf62bacee0fb97ada9c29fed342cd0d7a3a07731570385a03c17a4c",
    canonical:
      "00hooks-v1\ndev_0123456789abcdefghjkmnpq\nrelay.example.com\nPOST\n/v1/hooks?limit=10\n1792233600000\n" +
      "AAECAwQFBgcICQoLDA0ODw\n871ec9aaacf62bacee0fb97ada9c29fed342cd0d7a3a07731570385a03c17a4c",
    signature: "_nBVrNWhRGN_JWnxbDBmQjNFDXz5APg0zqD6eCXe7EeJptiP0-Xb1czIn-r0p9faavla1rF7dhbtotQ3OTR1DA",
  };

  async function vectorKey(): Promise<CryptoKey> {
    // PKCS#8 wrapping of a raw Ed25519 seed (RFC 8410).
    const pkcs8 = fromHex(`302e020100300506032b657004220420${vector.seedHex}`)!;
    return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  }

  it("matches the protocol's test vector exactly", async () => {
    const body = utf8(vector.body);
    expect(await bodyHash(body)).toBe(vector.bodySha256);
    const u = new URL(vector.url);
    expect(
      canonicalString({
        deviceId: vector.deviceId,
        host: u.host,
        method: "POST",
        pathAndQuery: u.pathname + u.search,
        time: vector.time,
        nonce: vector.nonce,
        bodySha256: vector.bodySha256,
      }),
    ).toBe(vector.canonical);
    const privateKey = await vectorKey();
    const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
    expect(jwk.x).toBe(vector.publicKey);
    const headers = await signRequest({ deviceId: vector.deviceId, privateKey }, "POST", vector.url, body, {
      time: Number(vector.time),
      nonce: vector.nonce,
    });
    expect(headers).toEqual({
      "X-00h-Device": vector.deviceId,
      "X-00h-Time": vector.time,
      "X-00h-Nonce": vector.nonce,
      "X-00h-Signature": vector.signature,
    });
    // And the relay's verification accepts it.
    const pub = (await importPublicKey(vector.publicKey))!;
    expect(await crypto.subtle.verify("Ed25519", pub, fromBase64(vector.signature)!, utf8(vector.canonical))).toBe(true);
  });

  it("hashes the empty string when there's no body", async () => {
    expect(await bodyHash(undefined)).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("uses the URL's host: lowercase, IPv6 in brackets, no default port", () => {
    expect(new URL("https://Relay.Example.COM:443/x").host).toBe("relay.example.com");
    expect(new URL("https://relay.example.com:8443/x").host).toBe("relay.example.com:8443");
    expect(new URL("http://[::1]:8787/x").host).toBe("[::1]:8787");
  });

  it("makes 22-character base64url nonces", () => {
    expect(newNonce()).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it("accepts public keys only as canonical unpadded base64url", async () => {
    expect(await importPublicKey(vector.publicKey)).not.toBeNull();
    expect(await importPublicKey(`${vector.publicKey}=`)).toBeNull();
    // Same bytes, but the last character's unused bits set: another spelling of the same key.
    expect(await importPublicKey(`${vector.publicKey.slice(0, 42)}h`)).toBeNull();
    expect(await importPublicKey(toBase64(fromBase64(vector.publicKey)!))).toBeNull();
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

  it("signs the device id: a signature can't be presented under another device's id", async () => {
    const dev = await newAccount();
    const other = await enrolDevice(dev);
    const headers = await signRequest(dev, "GET", `${BASE}/v1/devices`);
    expect((await fetchRelay("/v1/devices", { headers: { ...headers, "X-00h-Device": other.deviceId } })).status).toBe(401);
    expect((await fetchRelay("/v1/devices", { headers })).status).toBe(200);
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
    // Padded base64url isn't the protocol's encoding.
    expect((await fetchRelay("/v1/devices", { headers: { ...headers, "X-00h-Signature": `${headers["X-00h-Signature"]}==` } })).status).toBe(401);
    expect((await fetchRelay("/v1/devices", { headers: { ...headers, "X-00h-Device": "dev_nope" } })).status).toBe(401);
  });
});

describe("/v1/info and signups", () => {
  it("reports the version, protocol and whether signups are open", async () => {
    const res = await fetchRelay("/v1/info");
    const info = (await res.json()) as Record<string, unknown>;
    expect(info).toMatchObject({ protocol: 2, protocols: [2], signupOpen: true, relayKey: RELAY_PUBLIC_KEY });
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
