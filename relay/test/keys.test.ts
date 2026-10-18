// API keys (PROTOCOL §9) and the audit log (PROTOCOL §9): scopes, expiry, storage, the routes a key
// can never use, and what the audit records.

import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { hmac, toHex, utf8 } from "../src/encoding.ts";
import { createHook, deliver, enrolDevice, fetchRelay, newAccount, signed, type TestDevice } from "./helpers.ts";

interface CreatedKey {
  key: { id: string; name: string; scopes: string[]; expiresAt: number; createdBy: string };
  token: string;
}

async function newKey(dev: TestDevice, scopes: string[], extra: Record<string, unknown> = {}): Promise<CreatedKey> {
  const res = await signed(dev, "POST", "/v1/keys", { name: "ci", scopes, ...extra });
  expect(res.status).toBe(201);
  return (await res.json()) as CreatedKey;
}

function withKey(token: string, method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  return fetchRelay(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

describe("API keys", () => {
  it("are shown once, stored only as a salted hash, and listed without any secret", async () => {
    const dev = await newAccount();
    const { key, token } = await newKey(dev, ["hooks:read"]);
    expect(token).toMatch(/^hk_[0-9a-hjkmnp-tv-z]{26}_[A-Za-z0-9_-]{43}$/);
    expect(key.id).toBe(`key_${token.slice(3, 29)}`);
    expect(key).toMatchObject({ name: "ci", scopes: ["hooks:read"], createdBy: dev.deviceId });
    // 90 days by default.
    expect(key.expiresAt - Date.now()).toBeGreaterThan(89 * 86_400_000);

    const row = await env.DB.prepare("SELECT * FROM api_keys WHERE id = ?").bind(key.id).first<Record<string, unknown>>();
    const secret = token.slice(30);
    expect(JSON.stringify(row)).not.toContain(secret);
    expect(row!.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(row!.salt).toBeTypeOf("string");

    const list = (await (await signed(dev, "GET", "/v1/keys")).json()) as { keys: Record<string, unknown>[] };
    expect(list.keys).toHaveLength(1);
    expect(JSON.stringify(list)).not.toContain(secret);
    expect(list.keys[0]).not.toHaveProperty("token");
    expect(list.keys[0]).not.toHaveProperty("hash");
  });

  it("can do what their scopes allow and nothing else", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "github" }, "existing");
    const reader = (await newKey(dev, ["hooks:read"])).token;
    const writer = (await newKey(dev, ["hooks:write", "hooks:read"])).token;

    expect((await withKey(reader, "GET", "/v1/hooks")).status).toBe(200);
    expect((await withKey(reader, "GET", `/v1/hooks/${hook.id}`)).status).toBe(200);
    const denied = await withKey(reader, "POST", "/v1/hooks", { name: "x", verify: { preset: "github" } });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ error: "forbidden" });
    expect((await withKey(reader, "DELETE", `/v1/hooks/${hook.id}`)).status).toBe(403);
    expect((await withKey(reader, "GET", "/v1/events")).status).toBe(403);
    expect((await withKey(reader, "GET", "/v1/audit")).status).toBe(403);
    expect((await withKey(reader, "GET", "/v1/devices")).status).toBe(403);

    // hooks:write is never shown a secret: a hook whose secret the relay generates needs hooks:secrets,
    // and so does rotating one (PROTOCOL §9).
    const generated = await withKey(writer, "POST", "/v1/hooks", { name: "from ci", verify: { preset: "github" } });
    expect(generated.status).toBe(403);
    expect(await generated.json()).toMatchObject({ error: "forbidden" });
    expect((await withKey(writer, "POST", `/v1/hooks/${hook.id}/rotate`)).status).toBe(403);
    const created = await withKey(writer, "POST", "/v1/hooks", { name: "from ci", verify: { preset: "github", secret: "a supplied github secret" } });
    expect(created.status).toBe(201);
    expect(await created.clone().json()).not.toHaveProperty("secret");
    const { hook: h2 } = (await created.json()) as { hook: { id: string } };
    expect((await withKey(writer, "PATCH", `/v1/hooks/${h2.id}`, { enabled: false })).status).toBe(200);
    expect((await withKey(writer, "DELETE", `/v1/hooks/${h2.id}`)).status).toBe(204);

    const ops = (await newKey(dev, ["devices:write", "events:read", "audit:read"])).token;
    const other = await enrolDevice(dev);
    expect((await withKey(ops, "GET", "/v1/devices")).status).toBe(200);
    expect((await withKey(ops, "GET", "/v1/events")).status).toBe(200);
    expect((await withKey(ops, "GET", "/v1/audit")).status).toBe(200);
    expect((await withKey(ops, "DELETE", `/v1/devices/${other.deviceId}`)).status).toBe(204);
  });

  it("can never stream, acknowledge, enrol a device, set a sealing key or manage keys", async () => {
    const dev = await newAccount();
    const all = (await newKey(dev, ["hooks:read", "hooks:write", "events:read", "devices:write", "audit:read"])).token;
    const tries: [string, string, unknown?][] = [
      ["GET", "/v1/stream"],
      ["POST", "/v1/ack", { through: 1 }],
      ["POST", "/v1/enrolments"],
      ["PUT", `/v1/devices/${dev.deviceId}/seal-key`, { sealKey: dev.seal!.text }],
      ["POST", "/v1/keys", { name: "more", scopes: ["hooks:read"] }],
      ["GET", "/v1/keys"],
    ];
    for (const [method, path, body] of tries) {
      const res = await withKey(all, method, path, body, { Accept: "text/event-stream", "X-00h-Protocol": "2" });
      expect(res.status, `${method} ${path}`).toBe(403);
      expect(await res.json()).toMatchObject({ error: "forbidden" });
    }
  });

  it("stop working when revoked or expired, and a wrong or unknown token says nothing more", async () => {
    const dev = await newAccount();
    const a = await newKey(dev, ["hooks:read"]);
    const b = await newKey(dev, ["hooks:read"], { expiresInDays: 1 });
    expect((await withKey(a.token, "GET", "/v1/hooks")).status).toBe(200);
    expect((await signed(dev, "DELETE", `/v1/keys/${a.key.id}`)).status).toBe(204);
    expect((await signed(dev, "DELETE", `/v1/keys/${a.key.id}`)).status).toBe(204);
    const revoked = await withKey(a.token, "GET", "/v1/hooks");
    expect(revoked.status).toBe(401);
    await env.DB.prepare("UPDATE api_keys SET expires_at = ? WHERE id = ?").bind(Date.now() - 1, b.key.id).run();
    const expired = await withKey(b.token, "GET", "/v1/hooks");
    expect(expired.status).toBe(401);
    expect(await expired.json()).toEqual(await revoked.json());
    const wrong = `${b.token.slice(0, -4)}AAAA`;
    expect((await withKey(wrong, "GET", "/v1/hooks")).status).toBe(401);
    expect((await withKey("hk_nonsense", "GET", "/v1/hooks")).status).toBe(401);
    // Another account's device can't revoke it.
    const stranger = await newAccount();
    expect((await signed(stranger, "DELETE", `/v1/keys/${b.key.id}`)).status).toBe(404);
  });

  it("validates scopes and expiry", async () => {
    const dev = await newAccount();
    for (const body of [
      { name: "x", scopes: [] },
      { name: "x", scopes: ["stream"] },
      { name: "x", scopes: ["hooks:read"], expiresInDays: 366 },
      { name: "", scopes: ["hooks:read"] },
    ]) {
      expect((await signed(dev, "POST", "/v1/keys", body)).status).toBe(400);
    }
  });
});

describe("audit", () => {
  it("records hooks, devices and keys with names and ids only, and counts key uses and verification failures per hour", async () => {
    const dev = await newAccount("laptop");
    const { hook, secret } = await createHook(dev, { preset: "github" }, "ci hook");
    expect((await signed(dev, "POST", `/v1/hooks/${hook.id}/rotate`)).status).toBe(200);
    const other = await enrolDevice(dev, "desktop");
    const { key, token } = await newKey(dev, ["hooks:read"]);
    for (let i = 0; i < 3; i++) expect((await withKey(token, "GET", "/v1/hooks")).status).toBe(200);
    for (let i = 0; i < 2; i++) {
      const bad = await fetchRelay(`/h/${hook.id}`, { method: "POST", headers: { "X-Hub-Signature-256": "sha256=" + "0".repeat(64) }, body: "{}" });
      expect(bad.status).toBe(401);
    }
    const good = await fetchRelay(`/h/${hook.id}`, {
      method: "POST",
      headers: { "X-Hub-Signature-256": `sha256=${toHex(await hmac("SHA-256", utf8(secret!), utf8("{}")))}` },
      body: "{}",
    });
    expect(good.status).toBe(200);
    expect((await signed(dev, "DELETE", `/v1/devices/${other.deviceId}`)).status).toBe(204);
    expect((await signed(dev, "DELETE", `/v1/keys/${key.id}`)).status).toBe(204);
    expect((await signed(dev, "DELETE", `/v1/hooks/${hook.id}`)).status).toBe(204);

    const res = await signed(dev, "GET", "/v1/audit");
    expect(res.status).toBe(200);
    const { entries } = (await res.json()) as { entries: Record<string, unknown>[] };
    const find = (kind: string) => entries.filter((e) => e.kind === kind);
    expect(find("device.added").map((e) => [e.subject, e.name, e.actor])).toEqual(
      expect.arrayContaining([
        [dev.deviceId, "laptop", dev.deviceId],
        // The device that issued the enrolment code added the new one.
        [other.deviceId, "desktop", dev.deviceId],
      ]),
    );
    expect(find("hook.created")[0]).toMatchObject({ subject: hook.id, name: "ci hook", actor: dev.deviceId });
    expect(find("hook.rotated")[0]).toMatchObject({ subject: hook.id, name: "ci hook" });
    expect(find("hook.deleted")[0]).toMatchObject({ subject: hook.id, name: "ci hook" });
    expect(find("device.revoked")[0]).toMatchObject({ subject: other.deviceId, name: "desktop", actor: dev.deviceId });
    expect(find("key.created")[0]).toMatchObject({ subject: key.id, name: "ci" });
    expect(find("key.revoked")[0]).toMatchObject({ subject: key.id, name: "ci" });
    expect(find("key.used")[0]).toMatchObject({ subject: key.id, name: "ci", count: 3 });
    // Counted per hour (the hook is gone, so its name is too).
    expect(find("verify.failed")[0]).toMatchObject({ subject: hook.id, count: 2 });
    expect((find("verify.failed")[0]!.at as number) % 3_600_000).toBe(0);
    // Newest first.
    const ats = entries.map((e) => e.at as number);
    expect([...ats].sort((x, y) => y - x)).toEqual(ats);
    // Never a secret, a token or a payload.
    const text = JSON.stringify(entries);
    expect(text).not.toContain(secret!);
    expect(text).not.toContain(token.slice(30));
  });

  it("lists recent deliveries as metadata only (events:read)", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    await deliver(hook.id, { private: "do-not-show-me" });
    const res = await signed(dev, "GET", "/v1/events?limit=10");
    const { events } = (await res.json()) as { events: Record<string, unknown>[] };
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ seq: 1, hookId: hook.id, verified: false, strict: false, preset: "unverified", deliveredTo: [], pendingFor: [dev.deviceId] });
    expect(JSON.stringify(events)).not.toContain("do-not-show-me");
    expect((await signed(dev, "GET", "/v1/events?limit=0")).status).toBe(400);
  });
});
