// Hooks (PROTOCOL §3) and receiving (PROTOCOL §4), end to end through the Worker and the object.

import { createExecutionContext, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { AccountObject } from "../src/account-object.ts";
import { receive } from "../src/receive.ts";
import { hmac, toBase64, toHex, utf8, fromBase64 } from "../src/encoding.ts";
import { BASE, accountObject, createHook, deliver, fetchRelay, newAccount, openEvent, openStream, data, signed, type StreamedEvent } from "./helpers.ts";

async function githubSign(secret: string, body: string): Promise<string> {
  return `sha256=${toHex(await hmac("SHA-256", utf8(secret), utf8(body)))}`;
}

async function standardSign(secret: string, id: string, ts: string, body: string): Promise<string> {
  const key = fromBase64(secret.slice("whsec_".length))!;
  return `v1,${toBase64(await hmac("SHA-256", key, utf8(`${id}.${ts}.${body}`)))}`;
}

function post(hookId: string, body: string, headers: Record<string, string> = {}) {
  return fetchRelay(`/h/${hookId}`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body });
}

/** Everything an account can read back after creation, concatenated. */
async function everythingVisible(dev: Awaited<ReturnType<typeof newAccount>>, hookId: string): Promise<string> {
  const parts = [
    await (await signed(dev, "GET", "/v1/hooks")).text(),
    await (await signed(dev, "GET", `/v1/hooks/${hookId}`)).text(),
    await (await signed(dev, "PATCH", `/v1/hooks/${hookId}`, { name: "renamed" })).text(),
  ];
  return parts.join("\n");
}

describe("hooks", () => {
  it("creates each preset; returns a generated secret once, never a supplied one", async () => {
    const dev = await newAccount();
    const gh = await createHook(dev, { preset: "github" });
    expect(gh.hook.id).toMatch(/^hk_[0-9a-z]{26}$/);
    expect(gh.url).toBe(`${BASE}/h/${gh.hook.id}`);
    expect(gh.hook.url).toBe(gh.url);
    expect(fromBase64(gh.secret!)!.byteLength).toBe(32);
    expect(gh.hook).toMatchObject({ name: "test", enabled: true, verify: { preset: "github" }, maxBodyBytes: 1048576, lastEventAt: null });

    const sw = await createHook(dev, { preset: "standard-webhooks" });
    expect(sw.secret).toMatch(/^whsec_/);
    const hm = await createHook(dev, { preset: "hmac", header: "X-Signature", algorithm: "sha1", encoding: "base64", prefix: "sha1=" });
    expect(hm.hook.verify).toEqual({ preset: "hmac", header: "x-signature", algorithm: "sha1", encoding: "base64", prefix: "sha1=" });
    expect(hm.secret).toBeDefined();
    const tk = await createHook(dev, { preset: "token" });
    expect(tk.hook.verify).toEqual({ preset: "token", header: "authorization" });
    const un = await createHook(dev, { preset: "unverified" });
    expect(un.secret).toBeUndefined();

    const supplied = await createHook(dev, { preset: "github", secret: "my own secret value" });
    expect(supplied.secret).toBeUndefined();
    expect(JSON.stringify(supplied)).not.toContain("my own secret value");
  });

  it("never shows a secret after creation, and stores it only sealed", async () => {
    const dev = await newAccount();
    const { hook, secret } = await createHook(dev, { preset: "github" });
    const supplied = await createHook(dev, { preset: "token", secret: "supplied-token-value" });
    const visible = (await everythingVisible(dev, hook.id)) + (await everythingVisible(dev, supplied.hook.id));
    expect(visible).not.toContain(secret!);
    expect(visible).not.toContain("supplied-token-value");
    const rows = await env.DB.prepare("SELECT * FROM hooks WHERE account_id = ?").bind(dev.accountId).all();
    expect(JSON.stringify(rows.results)).not.toContain(secret!);
    expect(JSON.stringify(rows.results)).not.toContain("supplied-token-value");
  });

  it("lists, gets, patches and deletes; other accounts see nothing", async () => {
    const dev = await newAccount();
    const stranger = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" }, "first");
    const list = (await (await signed(dev, "GET", "/v1/hooks")).json()) as { hooks: { id: string }[] };
    expect(list.hooks.map((h) => h.id)).toEqual([hook.id]);
    expect((await signed(stranger, "GET", `/v1/hooks/${hook.id}`)).status).toBe(404);
    expect((await signed(stranger, "PATCH", `/v1/hooks/${hook.id}`, { enabled: false })).status).toBe(404);
    expect((await signed(stranger, "DELETE", `/v1/hooks/${hook.id}`)).status).toBe(404);

    const patched = await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { name: "second", enabled: false, maxBodyBytes: 10 });
    expect(await patched.json()).toMatchObject({ name: "second", enabled: false, maxBodyBytes: 10 });
    const bad = await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { maxBodyBytes: 100_000_000 });
    expect(await bad.json()).toMatchObject({ error: "invalid", field: "maxBodyBytes" });
    expect((await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { enabled: "yes" })).status).toBe(400);

    // Disabled hooks answer 404.
    expect((await post(hook.id, "{}")).status).toBe(404);
    await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { enabled: true, maxBodyBytes: 1024 });
    expect((await post(hook.id, "{}")).status).toBe(200);

    expect((await signed(dev, "DELETE", `/v1/hooks/${hook.id}`)).status).toBe(204);
    expect((await signed(dev, "GET", `/v1/hooks/${hook.id}`)).status).toBe(404);
    expect((await post(hook.id, "{}")).status).toBe(404);
  });

  it("keeps a deleted hook's events in the log until they're acknowledged", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const id = await deliver(hook.id, { n: 1 });
    await signed(dev, "DELETE", `/v1/hooks/${hook.id}`);
    const { sse } = await openStream(dev);
    await sse.nextEvent(); // ready
    expect(data(await sse.nextEvent()).id).toBe(id);
    await sse.cancel();
  });

  it("rotates: the new secret works, the previous one for 24 hours", async () => {
    const dev = await newAccount();
    const { hook, secret: first } = await createHook(dev, { preset: "github" });
    const rotated = await signed(dev, "POST", `/v1/hooks/${hook.id}/rotate`);
    expect(rotated.status).toBe(200);
    const { secret: second } = (await rotated.json()) as { secret: string };
    expect(second).not.toBe(first);
    const send = async (secret: string, n: number) => {
      const body = JSON.stringify({ n });
      return (await post(hook.id, body, { "X-Hub-Signature-256": await githubSign(secret, body), "X-GitHub-Event": "push" })).status;
    };
    expect(await send(second, 1)).toBe(200);
    expect(await send(first!, 2)).toBe(200);
    await env.DB.prepare("UPDATE hooks SET previous_secret_until = ? WHERE id = ?").bind(Date.now() - 1, hook.id).run();
    expect(await send(first!, 3)).toBe(401);
    expect(await send(second, 4)).toBe(200);

    const un = await createHook(dev, { preset: "unverified" });
    const refused = await signed(dev, "POST", `/v1/hooks/${un.hook.id}/rotate`);
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ error: "conflict" });
  });
});

describe("receiving", () => {
  it("verifies GitHub deliveries over the raw bytes, dedupes on the delivery id, and stores ping", async () => {
    const dev = await newAccount();
    const { hook, secret } = await createHook(dev, { preset: "github" });
    const body = '{"zen":"Keep it logically awesome.","hook_id":1}';
    const headers = {
      "X-Hub-Signature-256": await githubSign(secret!, body),
      "X-GitHub-Event": "ping",
      "X-GitHub-Delivery": "11111111-2222-3333-4444-555555555555",
      Cookie: "session=should-not-be-kept",
    };
    const res = await post(hook.id, body, headers);
    expect(res.status).toBe(200);
    const { received } = (await res.json()) as { received: string };
    expect(received).toMatch(/^evt_[0-9a-z]{26}$/);

    const dup = await post(hook.id, body, headers);
    expect(dup.status).toBe(200);
    expect(await dup.json()).toEqual({ duplicate: true });

    // A single byte of difference (here, whitespace) fails: verification is over the raw bytes.
    const bad = await post(hook.id, body.replace(":", ": "), { ...headers, "X-GitHub-Delivery": "other" });
    expect(bad.status).toBe(401);
    const badBody = await bad.json();
    expect(badBody).toEqual({ error: "signature", message: "The delivery's signature doesn't verify." });

    const { sse } = await openStream(dev);
    await sse.nextEvent(); // ready
    const ev = data<StreamedEvent>(await sse.nextEvent());
    expect(ev).toMatchObject({ seq: 1, id: received, hookId: hook.id, verified: true, strict: false, preset: "github", eventType: "ping" });
    // Content is sealed: no body, headers or content type in the clear.
    expect(ev).not.toHaveProperty("body");
    expect(ev).not.toHaveProperty("headers");
    expect(ev).not.toHaveProperty("contentType");
    const opened = await openEvent(dev, ev);
    expect(opened.text).toBe(body);
    expect(opened.contentType).toBe("application/json");
    // The signature is never kept: next to its body it would be a ready-made replay.
    expect(opened.headers).toEqual({
      "content-type": "application/json",
      "x-github-event": "ping",
      "x-github-delivery": "11111111-2222-3333-4444-555555555555",
    });
    await sse.cancel();
    const stats = await accountObject(dev.accountId).stats();
    expect(stats.events).toBe(1);
  });

  it("refuses a captured GitHub delivery replayed under a new X-GitHub-Delivery (the id isn't signed)", async () => {
    const dev = await newAccount();
    const { hook, secret } = await createHook(dev, { preset: "github" });
    const body = '{"action":"opened","number":7}';
    const sig = await githubSign(secret!, body);
    const first = await post(hook.id, body, { "X-Hub-Signature-256": sig, "X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "d-1" });
    expect(await first.json()).toHaveProperty("received");
    // Same signed body, new delivery id and even a different (unsigned) event type: a replay.
    const replay = await post(hook.id, body, { "X-Hub-Signature-256": sig, "X-GitHub-Event": "push", "X-GitHub-Delivery": "d-2" });
    expect(await replay.json()).toEqual({ duplicate: true });
    const noId = await post(hook.id, body, { "X-Hub-Signature-256": sig });
    expect(await noId.json()).toEqual({ duplicate: true });
    // A different body is a different event.
    const other = '{"action":"closed","number":7}';
    const next = await post(hook.id, other, { "X-Hub-Signature-256": await githubSign(secret!, other), "X-GitHub-Delivery": "d-3" });
    expect(await next.json()).toHaveProperty("received");
    expect((await accountObject(dev.accountId).stats()).events).toBe(2);
  });

  it("verifies Standard Webhooks with a fresh timestamp and dedupes on webhook-id", async () => {
    const dev = await newAccount();
    const { hook, secret } = await createHook(dev, { preset: "standard-webhooks" });
    const body = '{"type":"user.created","data":{}}';
    const ts = String(Math.floor(Date.now() / 1000));
    const h = { "webhook-id": "msg_1", "webhook-timestamp": ts, "webhook-signature": await standardSign(secret!, "msg_1", ts, body) };
    expect((await post(hook.id, body, h)).status).toBe(200);
    expect(await (await post(hook.id, body, h)).json()).toEqual({ duplicate: true });
    const old = String(Math.floor(Date.now() / 1000) - 400);
    const stale = { "webhook-id": "msg_2", "webhook-timestamp": old, "webhook-signature": await standardSign(secret!, "msg_2", old, body) };
    expect((await post(hook.id, body, stale)).status).toBe(401);
  });

  it("dedupes hmac deliveries on the body hash; token and unverified aren't deduped", async () => {
    const dev = await newAccount();
    const hm = await createHook(dev, { preset: "hmac", header: "X-Sig" });
    const body = '{"a":1}';
    const sig = toHex(await hmac("SHA-256", utf8(hm.secret!), utf8(body)));
    expect(await (await post(hm.hook.id, body, { "X-Sig": sig })).json()).toHaveProperty("received");
    expect(await (await post(hm.hook.id, body, { "X-Sig": sig })).json()).toEqual({ duplicate: true });

    const tk = await createHook(dev, { preset: "token" });
    const auth = { Authorization: `Bearer ${tk.secret}` };
    expect(await (await post(tk.hook.id, body, auth)).json()).toHaveProperty("received");
    expect(await (await post(tk.hook.id, body, auth)).json()).toHaveProperty("received");
    expect((await post(tk.hook.id, body, { Authorization: "Bearer nope" })).status).toBe(401);
  });

  it("refuses bodies over the limit, from Content-Length and while reading", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { maxBodyBytes: 100 });
    const declared = await post(hook.id, "x".repeat(101));
    expect(declared.status).toBe(413);
    expect(await declared.json()).toMatchObject({ error: "too_large" });
    expect((await post(hook.id, "x".repeat(100))).status).toBe(200);

    // A chunked body with no Content-Length is cut off while it's read.
    const chunks = [utf8("x".repeat(60)), utf8("x".repeat(60))];
    const stream = new ReadableStream<Uint8Array>({
      pull(c) {
        const next = chunks.shift();
        if (next) c.enqueue(next);
        else c.close();
      },
    });
    const streamed = await fetchRelay(`/h/${hook.id}`, { method: "POST", body: stream });
    expect(streamed.status).toBe(413);
    expect((await accountObject(dev.accountId).stats()).events).toBe(1);
  });

  it("rate limits each hook (60 per 10 s) with Retry-After", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const other = await createHook(dev, { preset: "unverified" });
    // The limiter counts in wall-clock-aligned 10 s windows: start early in one, so all 61
    // requests land in the same window.
    const intoWindow = Date.now() % 10_000;
    if (intoWindow > 6_000) await new Promise((r) => setTimeout(r, 10_000 - intoWindow + 50));
    const statuses: number[] = [];
    for (let i = 0; i < 61; i++) statuses.push((await post(hook.id, `{"i":${i}}`)).status);
    expect(statuses.slice(0, 60).every((s) => s === 200)).toBe(true);
    expect(statuses[60]).toBe(429);
    const limited = await post(hook.id, "{}");
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBe("10");
    expect(await limited.json()).toMatchObject({ error: "rate_limited" });
    // Per hook: another hook on the same account is unaffected.
    expect((await post(other.hook.id, "{}")).status).toBe(200);
  });

  it("answers unknown hooks and other methods with 404, and accepts PUT and PATCH", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    expect((await fetchRelay("/h/hk_00000000000000000000000000", { method: "POST", body: "{}" })).status).toBe(404);
    expect((await fetchRelay("/h/not-an-id", { method: "POST", body: "{}" })).status).toBe(404);
    expect((await fetchRelay(`/h/${hook.id}`)).status).toBe(404);
    expect((await fetchRelay(`/h/${hook.id}`, { method: "PUT", body: "{}" })).status).toBe(200);
    expect((await fetchRelay(`/h/${hook.id}`, { method: "PATCH", body: "{}" })).status).toBe(200);
    const notFound = await fetchRelay("/nowhere");
    expect(await notFound.json()).toEqual({ error: "not_found", message: "Nothing is here." });
  });

  it("never puts a secret, a signature or payload content in an error", async () => {
    const dev = await newAccount();
    const { hook, secret } = await createHook(dev, { preset: "github" });
    const body = '{"private":"payload-content-marker"}';
    const sig = await githubSign("wrong-secret-value", body);
    const responses = [
      await post(hook.id, body, { "X-Hub-Signature-256": sig }),
      await post(hook.id, body, { "X-Hub-Signature-256": `sha256=${secret}` }),
      await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { name: secret!.repeat(5) }),
      await signed(dev, "POST", "/v1/hooks", { name: "x", verify: { preset: "standard-webhooks", secret: `not-${secret}` } }),
    ];
    for (const r of responses) {
      expect(r.status).toBeGreaterThanOrEqual(400);
      const text = await r.text();
      expect(text).not.toContain(secret!);
      expect(text).not.toContain("payload-content-marker");
      expect(text).not.toContain(sig.slice(7));
      expect(Object.keys(JSON.parse(text) as object)).toContain("message");
    }
  });

  it("refuses with 429 quota when the account's log is full, and accepts again once acknowledged", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const stub = accountObject(dev.accountId);
    await runInDurableObject(stub, (o: AccountObject) => {
      o.quotaOverride = { events: 2, bytes: 1_000_000 };
    });
    expect((await post(hook.id, '{"n":1}')).status).toBe(200);
    expect((await post(hook.id, '{"n":2}')).status).toBe(200);
    const full = await post(hook.id, '{"n":3}');
    expect(full.status).toBe(429);
    expect(full.headers.get("Retry-After")).toBe("60");
    expect(await full.json()).toMatchObject({ error: "quota" });
    expect((await stub.stats()).usage.events).toBe(2);
    // Acknowledged events are deleted, which frees the quota.
    expect((await signed(dev, "POST", "/v1/ack", { through: 2 })).status).toBe(200);
    expect((await stub.stats()).usage).toEqual({ events: 0, bytes: 0 });
    expect((await post(hook.id, '{"n":3}')).status).toBe(200);

    // Bytes count too.
    await runInDurableObject(stub, (o: AccountObject) => {
      o.quotaOverride = { events: 100, bytes: 1000 };
    });
    // Bytes are what is stored: the sealed envelope (content plus headers, sealed) and its overhead.
    expect((await post(hook.id, "x".repeat(1000))).status).toBe(429);
    expect((await post(hook.id, "x".repeat(50))).status).toBe(200);
  });
});

/** A Rate Limiting binding that answers `success` and records its keys. */
function fakeLimit(success: boolean, keys: string[] = []): RateLimit {
  return {
    limit: async ({ key }: { key: string }) => {
      keys.push(key);
      return { success };
    },
  } as RateLimit;
}

describe("receiving: limits before any lookup", () => {
  const untouchedDb = new Proxy({} as D1Database, {
    get() {
      throw new Error("the database was read");
    },
  });

  it("fails closed with 503 when a rate limit binding is missing", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (const missing of ["HOOK_LIMIT", "RECEIVE_IP_LIMIT"] as const) {
      const res = await receive(
        new Request(`${BASE}/h/${hook.id}`, { method: "POST", body: "{}" }),
        { ...env, [missing]: undefined } as unknown as Env,
        createExecutionContext(),
        hook.id,
      );
      expect(res.status).toBe(503);
      expect(await res.json()).toMatchObject({ error: "unavailable" });
    }
  });

  it("limits each client address (IPv6 by /64) before the hook lookup", async () => {
    const keys: string[] = [];
    const res = await receive(
      new Request(`${BASE}/h/hk_00000000000000000000000000`, {
        method: "POST",
        body: "{}",
        headers: { "CF-Connecting-IP": "2001:db8:aa:bb:1:2:3:4" },
      }),
      { ...env, DB: untouchedDb, RECEIVE_IP_LIMIT: fakeLimit(false, keys) } as unknown as Env,
      createExecutionContext(),
      "hk_00000000000000000000000000",
    );
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("10");
    expect(keys).toEqual(["2001:db8:aa:bb::/64"]);
  });
});
