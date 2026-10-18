// The audit fixes to the relay core, each pinned: hook secrets behind `hooks:secrets`, unique hook
// names, hook changes on the stream, per-hook quotas and the hold's own quota, appends that don't
// block the object while they seal, failures counted at the edge, long replay marks, closed signups
// and the management rate limit, retention by `stored_at`, and the smaller lows.

import { createExecutionContext, evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";

// These tests make many requests each (floods, device caps, streams): give them room on a busy machine.
vi.setConfig({ testTimeout: 30_000 });
import type { AccountObject } from "../src/account-object.ts";
import { NONCE_TTL_MS } from "../src/account-object.ts";
import { createAccount, revokeDevice } from "../src/accounts.ts";
import { generateDeviceKey } from "../src/canonical.ts";
import { resetEdgeCounts } from "../src/edge-counts.ts";
import { hmac, newId, toHex, utf8 } from "../src/encoding.ts";
import { UNCHECKED_MAX_BODY_BYTES } from "../src/hooks.ts";
import worker from "../src/index.ts";
import { pruneD1 } from "../src/prune.ts";
import wranglerConfig from "../wrangler.jsonc?raw";
import {
  BASE,
  accountObject,
  createHook,
  data,
  deliver,
  enrolDevice,
  fetchRelay,
  newAccount,
  openEvent,
  openStream,
  signed,
  type SseReader,
  type StreamedEvent,
  type TestDevice,
} from "./helpers.ts";

function withKey(token: string, method: string, path: string, body?: unknown): Promise<Response> {
  return fetchRelay(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function newKey(dev: TestDevice, scopes: string[]): Promise<string> {
  const res = await signed(dev, "POST", "/v1/keys", { name: `ci ${scopes.join(" ")}`, scopes });
  expect(res.status).toBe(201);
  return ((await res.json()) as { token: string }).token;
}

async function ready(sse: SseReader) {
  expect((await sse.next())?.retry).toBe(5000);
  const f = await sse.nextEvent();
  expect(f?.event).toBe("ready");
  return data<{ after: number; head: number }>(f);
}

function post(hookId: string, body: string, headers: Record<string, string> = {}) {
  return fetchRelay(`/h/${hookId}`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body });
}

async function githubSig(secret: string, body: string): Promise<string> {
  return `sha256=${toHex(await hmac("SHA-256", utf8(secret), utf8(body)))}`;
}

function sql<T extends Record<string, SqlStorageValue>>(dev: TestDevice, query: string, ...args: SqlStorageValue[]): Promise<T[]> {
  return runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) => state.storage.sql.exec<T>(query, ...args).toArray());
}

function fakeLimit(success: boolean): RateLimit {
  return { limit: async () => ({ success }) } as RateLimit;
}

const untouchedDb = new Proxy({} as D1Database, {
  get() {
    throw new Error("the database was read");
  },
});

describe("hook secrets and names", () => {
  it("a hooks:write key can't create a relay-generated secret or rotate one; hooks:secrets can", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "github" }, "payments");
    const writer = await newKey(dev, ["hooks:write"]);
    const secrets = await newKey(dev, ["hooks:secrets", "hooks:write"]);

    expect((await withKey(writer, "POST", `/v1/hooks/${hook.id}/rotate`)).status).toBe(403);
    for (const verify of [{ preset: "github" }, { preset: "standard-webhooks" }, { preset: "token" }, { preset: "meta", secret: "app-secret-0001" }]) {
      const res = await withKey(writer, "POST", "/v1/hooks", { name: `ci ${verify.preset}`, verify });
      expect(res.status, verify.preset).toBe(403);
    }
    // Nothing was made by the refused attempts.
    const listed = (await (await signed(dev, "GET", "/v1/hooks")).json()) as { hooks: unknown[] };
    expect(listed.hooks).toHaveLength(1);

    const rotated = await withKey(secrets, "POST", `/v1/hooks/${hook.id}/rotate`);
    expect(rotated.status).toBe(200);
    expect(await rotated.json()).toHaveProperty("secret");
    const created = await withKey(secrets, "POST", "/v1/hooks", { name: "ci github", verify: { preset: "github" } });
    expect(created.status).toBe(201);
    expect(await created.json()).toHaveProperty("secret");
  });

  it("refuses a strict token hook (devices refuse to verify one)", async () => {
    const dev = await newAccount();
    const res = await signed(dev, "POST", "/v1/hooks", { name: "t", verify: { preset: "token", strict: true } });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid", field: "verify.strict" });
  });

  it("hook names are unique per account: create and rename answer 409, other accounts are free", async () => {
    const dev = await newAccount();
    const a = await createHook(dev, { preset: "unverified" }, "payments");
    const b = await createHook(dev, { preset: "unverified" }, "builds");
    const dup = await signed(dev, "POST", "/v1/hooks", { name: "payments", verify: { preset: "unverified" } });
    expect(dup.status).toBe(409);
    expect(await dup.json()).toMatchObject({ error: "conflict" });
    expect((await signed(dev, "PATCH", `/v1/hooks/${b.hook.id}`, { name: "payments" })).status).toBe(409);
    // Renaming a hook to its own name, or to a free one, is fine.
    expect((await signed(dev, "PATCH", `/v1/hooks/${a.hook.id}`, { name: "payments" })).status).toBe(200);
    expect((await signed(dev, "PATCH", `/v1/hooks/${b.hook.id}`, { name: "deploys" })).status).toBe(200);
    // The index holds even when the check is skipped (a race).
    await expect(
      env.DB.prepare("UPDATE hooks SET name = 'payments' WHERE id = ?").bind(b.hook.id).run(),
    ).rejects.toThrow(/UNIQUE/);
    const other = await newAccount();
    await createHook(other, { preset: "unverified" }, "payments");
  });

  it("migration 0006 renames existing duplicates instead of failing", async () => {
    const accountId = newId("acc");
    await env.DB.prepare("INSERT INTO accounts (id, created_at) VALUES (?, 0)").bind(accountId).run();
    await env.DB.exec("DROP INDEX hooks_account_name");
    try {
      for (const id of [newId("hk"), newId("hk")]) {
        await env.DB.prepare(
          "INSERT INTO hooks (id, account_id, name, enabled, verify, max_body_bytes, created_at) VALUES (?, ?, 'dup', 1, '{}', 1, 0)",
        )
          .bind(id, accountId)
          .run();
      }
      const migration = env.TEST_MIGRATIONS.find((m) => m.name.startsWith("0006"))!;
      for (const q of migration.queries) {
        if (q.includes("UPDATE hooks SET name")) await env.DB.prepare(q).run();
      }
      const { results } = await env.DB.prepare("SELECT name FROM hooks WHERE account_id = ? ORDER BY rowid").bind(accountId).all<{ name: string }>();
      expect(results[0]!.name).toBe("dup");
      expect(results[1]!.name).toMatch(/^dup \(hk_[0-9a-z]{26}\)$/);
    } finally {
      await env.DB.prepare("DELETE FROM hooks WHERE account_id = ?").bind(accountId).run();
      await env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(accountId).run();
      await env.DB.exec("CREATE UNIQUE INDEX hooks_account_name ON hooks(account_id, name)");
    }
  });

  it("devices are told on their stream when a hook is created, rotated, renamed or deleted, once, and not of their own", async () => {
    const dev = await newAccount("laptop");
    const other = await enrolDevice(dev, "desktop");
    const { hook } = await createHook(dev, { preset: "github" }, "payments");
    const key = await newKey(dev, ["hooks:secrets", "hooks:write"]);

    // `other` was offline: it is told after `ready`.
    const first = await openStream(other);
    await ready(first.sse);
    const created = await first.sse.nextEvent();
    expect(created?.event).toBe("hook-change");
    expect(created?.id).toBeUndefined();
    expect(data(created)).toMatchObject({ kind: "hook.created", hookId: hook.id, name: "payments", actor: dev.deviceId });

    // Live, while connected: a key rotates, a rename, a delete.
    expect((await withKey(key, "POST", `/v1/hooks/${hook.id}/rotate`)).status).toBe(200);
    const rotated = data(await first.sse.nextEvent());
    expect(rotated).toMatchObject({ kind: "hook.rotated", hookId: hook.id, actor: expect.stringMatching(/^key_/) });
    expect((await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { name: "billing" })).status).toBe(200);
    expect(data(await first.sse.nextEvent())).toMatchObject({ kind: "hook.renamed", name: "billing", previousName: "payments" });
    await first.sse.cancel();

    // Live ones are sent again on the next stream, once (a stream that went away unnoticed would
    // have lost them); clients dedupe by `n`. Then the delete, made while offline.
    expect((await signed(dev, "DELETE", `/v1/hooks/${hook.id}`)).status).toBe(204);
    const again = await openStream(other);
    await ready(again.sse);
    const replay = [data(await again.sse.nextEvent()), data(await again.sse.nextEvent()), data(await again.sse.nextEvent())];
    expect(replay.map((c) => c.kind)).toEqual(["hook.rotated", "hook.renamed", "hook.deleted"]);
    expect(replay[0]!.n).toBe(rotated.n);
    await deliver((await createHook(other, { preset: "unverified" }, "own")).hook.id, { n: 1 });
    // `other` made "own" itself: the next frame is the event, not a change.
    expect((await again.sse.nextEvent())?.event).toBe("hook");
    await again.sse.cancel();

    // The device that made the changes hears only the key's rotation and other's hook.
    const mine = await openStream(dev);
    await ready(mine.sse);
    expect(data(await mine.sse.nextEvent())).toMatchObject({ kind: "hook.rotated" });
    expect(data(await mine.sse.nextEvent())).toMatchObject({ kind: "hook.created", name: "own", actor: other.deviceId });
    expect((await mine.sse.nextEvent())?.event).toBe("hook");
    await mine.sse.cancel();
  });

  it("a device enrolled later isn't told of changes from before it existed", async () => {
    const dev = await newAccount();
    await createHook(dev, { preset: "unverified" }, "before");
    const later = await enrolDevice(dev);
    const { sse } = await openStream(later);
    await ready(sse);
    await createHook(dev, { preset: "unverified" }, "after");
    expect(data(await sse.nextEvent())).toMatchObject({ kind: "hook.created", name: "after" });
    await sse.cancel();
  });
});

describe("flood isolation", () => {
  it("one hook can fill only its share of the log; another hook keeps receiving", async () => {
    const dev = await newAccount();
    const junk = await createHook(dev, { preset: "unverified" }, "junk");
    const real = await createHook(dev, { preset: "github", secret: "real-github-secret-01" }, "real");
    await runInDurableObject(accountObject(dev.accountId), (o: AccountObject) => {
      o.quotaOverride = { events: 32, bytes: 10_000_000 };
    });
    // An unverified hook may hold a sixteenth of the account's events: 2 of 32.
    expect((await post(junk.hook.id, '{"n":1}')).status).toBe(200);
    expect((await post(junk.hook.id, '{"n":2}')).status).toBe(200);
    const full = await post(junk.hook.id, '{"n":3}');
    expect(full.status).toBe(429);
    expect(await full.json()).toMatchObject({ error: "quota", scope: "hook" });
    // The verified hook isn't refused; it may hold half (16).
    for (let i = 0; i < 16; i++) {
      const body = JSON.stringify({ i });
      expect((await post(real.hook.id, body, { "X-Hub-Signature-256": await githubSig("real-github-secret-01", body) })).status).toBe(200);
    }
    const body = JSON.stringify({ i: 99 });
    expect(await (await post(real.hook.id, body, { "X-Hub-Signature-256": await githubSig("real-github-secret-01", body) })).json()).toMatchObject({
      scope: "hook",
    });
    const s = await accountObject(dev.accountId).stats();
    expect(s.hooks[junk.hook.id]!.events).toBe(2);
    expect(s.hooks[real.hook.id]!.events).toBe(16);
    // Acknowledging frees the hook's share.
    expect((await signed(dev, "POST", "/v1/ack", { through: 18 })).status).toBe(200);
    expect((await accountObject(dev.accountId).stats()).hooks).toEqual({});
    expect((await post(junk.hook.id, '{"n":4}')).status).toBe(200);
  });

  it("strict and unverified hooks get a smaller default body limit", async () => {
    const dev = await newAccount();
    const un = await createHook(dev, { preset: "unverified" }, "u");
    const strict = await createHook(dev, { preset: "github", strict: true }, "s");
    const gh = await createHook(dev, { preset: "github" }, "g");
    expect(un.hook.maxBodyBytes).toBe(UNCHECKED_MAX_BODY_BYTES);
    expect(strict.hook.maxBodyBytes).toBe(UNCHECKED_MAX_BODY_BYTES);
    expect(gh.hook.maxBodyBytes).toBe(1024 * 1024);
    expect((await post(un.hook.id, "x".repeat(UNCHECKED_MAX_BODY_BYTES + 1))).status).toBe(413);
  });

  it("caps node devices per account", async () => {
    const dev = await newAccount();
    for (let i = 2; i <= 10; i++) await enrolDevice(dev, `d${i}`);
    const refused = await signed(dev, "POST", "/v1/enrolments");
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ error: "conflict" });
  });

  it("appends seal concurrently and commit in seq order", async () => {
    const dev = await newAccount();
    const other = await enrolDevice(dev);
    const { hook } = await createHook(dev, { preset: "unverified" });
    const { sse } = await openStream(dev);
    await ready(sse);
    const ids = await Promise.all(Array.from({ length: 12 }, (_, i) => deliver(hook.id, { i, pad: "y".repeat(i * 2000) })));
    const got: StreamedEvent[] = [];
    while (got.length < 12) {
      const f = await sse.nextEvent();
      if (f?.event === "hook") got.push(data<StreamedEvent>(f));
    }
    expect(got.map((e) => e.seq)).toEqual(Array.from({ length: 12 }, (_, i) => i + 1));
    expect(new Set(got.map((e) => e.id))).toEqual(new Set(ids));
    for (const e of got) await openEvent(dev, e);
    await sse.cancel();
    const s = await accountObject(dev.accountId).stats();
    expect(s.head).toBe(12);
    expect(s.envelopes).toBe(24);
    void other;
  });

  it("a duplicate arriving while the first is still sealing is refused", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "github", secret: "dup-github-secret-01" }, "gh");
    const body = JSON.stringify({ same: true });
    const headers = { "X-Hub-Signature-256": await githubSig("dup-github-secret-01", body), "X-GitHub-Delivery": "d-same" };
    const answers = await Promise.all([post(hook.id, body, headers), post(hook.id, body, headers), post(hook.id, body, headers)]);
    const bodies = await Promise.all(answers.map((r) => r.json() as Promise<Record<string, unknown>>));
    expect(bodies.filter((b) => b.duplicate === true)).toHaveLength(2);
    expect((await accountObject(dev.accountId).stats()).events).toBe(1);
  });

  it("the appender holds no blockConcurrencyWhile while it seals", async () => {
    const source = (await import("../src/account-object.ts?raw")).default as string;
    expect(source).not.toContain("blockConcurrencyWhile(");
  });
});

describe("the hold's own quota and the bulk drop", () => {
  const quarantineAll = { rules: [{ id: "all", verdict: "quarantine", conditions: [{ on: "size", op: "gt", bytes: 0 }] }] };

  it("held events have a per-hook quota apart from the log, and DELETE /v1/held drops them in bulk", async () => {
    const dev = await newAccount();
    const flooded = await createHook(dev, { preset: "unverified" }, "flooded");
    const quiet = await createHook(dev, { preset: "unverified" }, "quiet");
    expect((await signed(dev, "PUT", `/v1/hooks/${flooded.hook.id}/screen`, { screen: quarantineAll })).status).toBe(200);
    await runInDurableObject(accountObject(dev.accountId), (o: AccountObject) => {
      const big = { events: 1000, bytes: 100_000_000 };
      o.hookQuotaOverride = { checked: big, unchecked: big, held: { events: 3, bytes: 100_000_000 } };
    });
    for (let i = 0; i < 3; i++) expect((await post(flooded.hook.id, JSON.stringify({ i }))).status).toBe(200);
    const full = await post(flooded.hook.id, '{"i":3}');
    expect(full.status).toBe(429);
    expect(await full.json()).toMatchObject({ error: "quota", scope: "held" });
    // The log isn't touched: the other hook delivers.
    expect((await post(quiet.hook.id, "{}")).status).toBe(200);
    expect((await accountObject(dev.accountId).stats()).usage.events).toBe(1);

    // Bulk drop: by a rule that held nothing, then by hook.
    const none = await signed(dev, "DELETE", `/v1/held?rule=other`);
    expect(await none.json()).toEqual({ dropped: 0 });
    const writer = await newKey(dev, ["hooks:write"]);
    const dropped = await withKey(writer, "DELETE", `/v1/held?hookId=${flooded.hook.id}&rule=all`);
    expect(dropped.status).toBe(200);
    expect(await dropped.json()).toEqual({ dropped: 3 });
    expect((await accountObject(dev.accountId).stats()).heldUsage).toEqual({ events: 0, bytes: 0 });
    expect((await post(flooded.hook.id, '{"i":4}')).status).toBe(200);
    expect((await signed(dev, "DELETE", "/v1/held?hookId=nope")).status).toBe(400);
    const reader = await newKey(dev, ["events:read"]);
    expect((await withKey(reader, "DELETE", "/v1/held")).status).toBe(403);
  });

  it("a release that doesn't fit the log answers 429 quota and stays held", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    expect((await signed(dev, "PUT", `/v1/hooks/${hook.id}/screen`, { screen: quarantineAll })).status).toBe(200);
    const id = ((await (await post(hook.id, "{}")).json()) as { received: string }).received;
    await runInDurableObject(accountObject(dev.accountId), (o: AccountObject) => {
      o.quotaOverride = { events: 1, bytes: 10 };
    });
    const res = await signed(dev, "POST", `/v1/held/${id}/release`);
    expect(res.status).toBe(429);
    expect((await accountObject(dev.accountId).stats()).held).toBe(1);
  });
});

describe("forged signatures at the edge", () => {
  it("are counted in the Worker and written at most once a minute per hook", async () => {
    resetEdgeCounts(60_000);
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "github" });
    for (let i = 0; i < 6; i++) {
      expect((await post(hook.id, "{}", { "X-Hub-Signature-256": `sha256=${"0".repeat(64)}` })).status).toBe(401);
    }
    // The first is written at once; the next five wait for the minute.
    const rows = await sql<{ count: number }>(dev, "SELECT count FROM verify_failures");
    expect(rows.reduce((n, r) => n + r.count, 0)).toBe(1);
    const audit = (await (await signed(dev, "GET", "/v1/audit")).json()) as { entries: { kind: string; count?: number }[] };
    expect(audit.entries.find((e) => e.kind === "verify.failed")).toMatchObject({ count: 1 });
    resetEdgeCounts(0);
  });

  it("the audit names failed hooks however many there are (no bound-parameter limit)", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "github" }, "named");
    await runInDurableObject(accountObject(dev.accountId), async (o: AccountObject) => {
      await o.recordFailures(hook.id, 2);
      for (let i = 0; i < 150; i++) await o.recordFailures(newId("hk"));
    });
    const res = await signed(dev, "GET", "/v1/audit?limit=500");
    expect(res.status).toBe(200);
    const { entries } = (await res.json()) as { entries: { kind: string; subject: string; name: string | null; count?: number }[] };
    expect(entries.filter((e) => e.kind === "verify.failed")).toHaveLength(151);
    expect(entries.find((e) => e.kind === "verify.failed" && e.subject === hook.id)).toMatchObject({ name: "named", count: 2 });
  });
});

describe("replay marks", () => {
  it("keeps body-hash marks of presets without a signed timestamp far past a week", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "github", secret: "replay-github-secret" }, "gh");
    const body = JSON.stringify({ action: "released" });
    const sig = await githubSig("replay-github-secret", body);
    expect((await post(hook.id, body, { "X-Hub-Signature-256": sig, "X-GitHub-Delivery": "d-1" })).status).toBe(200);
    const marks = await sql<{ long: number }>(dev, "SELECT long FROM seen ORDER BY long");
    expect(marks.map((m) => m.long)).toEqual([0, 1]);
    // Eight days on: the week's marks go, the body hash stays, and the replay is refused.
    await runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) => {
      state.storage.sql.exec("UPDATE seen SET at = at - ?", 8 * 86_400_000);
    });
    await runDurableObjectAlarm(accountObject(dev.accountId));
    expect((await sql<{ long: number }>(dev, "SELECT long FROM seen")).map((m) => m.long)).toEqual([1]);
    const replay = await post(hook.id, body, { "X-Hub-Signature-256": sig, "X-GitHub-Delivery": "d-2" });
    expect(await replay.json()).toEqual({ duplicate: true });
    // Past REPLAY_MARK_DAYS (180) it goes too.
    await runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) => {
      state.storage.sql.exec("UPDATE seen SET at = at - ?", 180 * 86_400_000);
    });
    await runDurableObjectAlarm(accountObject(dev.accountId));
    expect(await sql(dev, "SELECT * FROM seen")).toEqual([]);
  });

  it("keeps a week's marks for presets that sign a timestamp", async () => {
    const dev = await newAccount();
    const { hook, secret } = await createHook(dev, { preset: "standard-webhooks" }, "sw");
    const { fromBase64, toBase64 } = await import("../src/encoding.ts");
    const ts = String(Math.floor(Date.now() / 1000));
    const body = "{}";
    const sig = `v1,${toBase64(await hmac("SHA-256", fromBase64(secret!.slice(6))!, utf8(`msg_1.${ts}.${body}`)))}`;
    expect((await post(hook.id, body, { "webhook-id": "msg_1", "webhook-timestamp": ts, "webhook-signature": sig })).status).toBe(200);
    expect((await sql<{ long: number }>(dev, "SELECT long FROM seen")).every((m) => m.long === 0)).toBe(true);
  });
});

describe("signups and the management rate limit", () => {
  const body = async () => utf8(JSON.stringify({ deviceName: "x", publicKey: (await generateDeviceKey()).publicKey }));
  const req = () => new Request(`${BASE}/v1/accounts`, { method: "POST", headers: { "CF-Connecting-IP": "198.18.9.9" } });

  it("fail closed without a signup token unless OPEN_SIGNUP=1", async () => {
    const closed = await createAccount(req(), { ...env, SIGNUP_TOKEN: "", OPEN_SIGNUP: undefined } as unknown as Env, await body());
    expect(closed.status).toBe(403);
    expect(await closed.json()).toMatchObject({ error: "forbidden" });
    const open = await createAccount(req(), { ...env, SIGNUP_TOKEN: "", OPEN_SIGNUP: "1" } as unknown as Env, await body());
    expect(open.status).toBe(201);
    // A token wins over OPEN_SIGNUP.
    const token = await createAccount(req(), { ...env, SIGNUP_TOKEN: "s3cret", OPEN_SIGNUP: "1" } as unknown as Env, await body());
    expect(token.status).toBe(401);
    const info = (await (await fetchRelay("/v1/info")).json()) as { signupOpen: boolean };
    expect(info.signupOpen).toBe(true);
  });

  it("limits account creation per address, and refuses without the binding", async () => {
    const limited = await createAccount(req(), { ...env, SIGNUP_IP_LIMIT: fakeLimit(false) } as unknown as Env, await body());
    expect(limited.status).toBe(429);
    const missing = await createAccount(req(), { ...env, SIGNUP_IP_LIMIT: undefined } as unknown as Env, await body());
    expect(missing.status).toBe(503);
    // The real binding: 5 a minute from one address.
    const ip = "198.19.200.7";
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      const res = await fetchRelay("/v1/accounts", {
        method: "POST",
        headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip },
        body: await body(),
      });
      statuses.push(res.status);
    }
    expect(statuses.slice(0, 5)).toEqual([201, 201, 201, 201, 201]);
    expect(statuses[5]).toBe(429);
  });

  it("creates an account and its device in one transaction, and a key race answers 409, not 500", async () => {
    const { publicKey } = await generateDeviceKey();
    const make = () =>
      fetchRelay("/v1/accounts", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ deviceName: "x", publicKey }) });
    const answers = await Promise.all([make(), make(), make()]);
    const statuses = answers.map((r) => r.status).sort();
    expect(statuses).toEqual([201, 409, 409]);
    const orphans = await env.DB.prepare("SELECT count(*) AS n FROM accounts a WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.account_id = a.id)").first<{
      n: number;
    }>();
    expect(orphans?.n).toBe(0);
  });

  it("rate-limits /v1/* per address before reading the database", async () => {
    const ctx = createExecutionContext();
    const call = (e: Partial<Env>) =>
      worker.fetch(new Request(`${BASE}/v1/hooks`, { headers: { "CF-Connecting-IP": "198.18.1.1" } }), { ...env, DB: untouchedDb, ...e } as unknown as Env, ctx);
    const limited = await call({ API_IP_LIMIT: fakeLimit(false) });
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBe("10");
    expect((await call({ API_IP_LIMIT: undefined })).status).toBe(503);
    // /v1/info is answered without it.
    expect((await worker.fetch(new Request(`${BASE}/v1/info`), { ...env, API_IP_LIMIT: undefined } as unknown as Env, ctx)).status).toBe(200);
  });
});

describe("retention by stored_at", () => {
  const quarantineBig = { rules: [{ id: "big", verdict: "quarantine", conditions: [{ on: "size", op: "gt", bytes: 100 }] }] };

  it("hold → append → release → the clock moves: the newer event survives, and both go once they're old", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    expect((await signed(dev, "PUT", `/v1/hooks/${hook.id}/screen`, { screen: quarantineBig })).status).toBe(200);
    const heldId = ((await (await post(hook.id, JSON.stringify({ pad: "z".repeat(200) }))).json()) as { received: string }).received;
    // It was received eight days ago (past the week's retention), and is still held.
    await runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) => {
      state.storage.sql.exec("UPDATE held_events SET received_at = received_at - ?", 8 * 86_400_000);
    });
    await deliver(hook.id, { small: 1 });
    const released = await signed(dev, "POST", `/v1/held/${heldId}/release`);
    expect(await released.json()).toMatchObject({ seq: 2 });
    await runDurableObjectAlarm(accountObject(dev.accountId));
    expect((await accountObject(dev.accountId).stats()).events).toBe(2);

    // Now the clock passes the week for both.
    await runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) => {
      state.storage.sql.exec("UPDATE events SET stored_at = stored_at - ?", 8 * 86_400_000);
    });
    await runDurableObjectAlarm(accountObject(dev.accountId));
    expect((await accountObject(dev.accountId).stats()).events).toBe(0);
    expect(await sql(dev, "SELECT from_seq, to_seq, reason FROM pruned")).toEqual([{ from_seq: 1, to_seq: 2, reason: "retention" }]);
  });

  it("deletes only events that are old, with a gap per contiguous range", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (let i = 1; i <= 5; i++) await deliver(hook.id, { i });
    await runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) => {
      state.storage.sql.exec("UPDATE events SET stored_at = stored_at - ? WHERE seq IN (1, 2, 4)", 8 * 86_400_000);
    });
    await runDurableObjectAlarm(accountObject(dev.accountId));
    expect((await sql<{ seq: number }>(dev, "SELECT seq FROM events ORDER BY seq")).map((r) => r.seq)).toEqual([3, 5]);
    expect(await sql(dev, "SELECT from_seq, to_seq FROM pruned ORDER BY from_seq")).toEqual([
      { from_seq: 1, to_seq: 2 },
      { from_seq: 4, to_seq: 4 },
    ]);
    const { sse } = await openStream(dev, 0);
    await ready(sse);
    const frames: string[] = [];
    for (let i = 0; i < 4; i++) {
      const f = await sse.nextEvent();
      frames.push(f?.event === "gap" ? `gap ${data<{ from: number; to: number }>(f).from}-${data<{ to: number }>(f).to}` : `hook ${f?.id}`);
    }
    expect(frames).toEqual(["gap 1-2", "hook 3", "gap 4-4", "hook 5"]);
    await sse.cancel();
  });
});

describe("the lows", () => {
  it("a nonce stays spent for longer than twice the clock window", async () => {
    const dev = await newAccount();
    const stub = accountObject(dev.accountId);
    expect(NONCE_TTL_MS).toBeGreaterThan(2 * 300_000);
    expect(await stub.spendNonce(dev.deviceId, "n-edge")).toBe(true);
    // Exactly 600 s later (a request timed 300 s ahead, replayed at the far edge): still refused.
    await runInDurableObject(stub, (_o: AccountObject, state) => {
      state.storage.sql.exec("UPDATE nonces SET at = ? WHERE nonce = 'n-edge'", Date.now() - 600_000);
    });
    expect(await stub.spendNonce(dev.deviceId, "n-edge")).toBe(false);
    await runInDurableObject(stub, (_o: AccountObject, state) => {
      state.storage.sql.exec("UPDATE nonces SET at = ? WHERE nonce = 'n-edge'", Date.now() - NONCE_TTL_MS + 1000);
    });
    expect(await stub.spendNonce(dev.deviceId, "n-edge")).toBe(false);
    // Past the TTL it may be used again (the clock window refuses the old request long before).
    await runInDurableObject(stub, (_o: AccountObject, state) => {
      state.storage.sql.exec("UPDATE nonces SET at = ? WHERE nonce = 'n-edge'", Date.now() - NONCE_TTL_MS - 1000);
    });
    expect(await stub.spendNonce(dev.deviceId, "n-edge")).toBe(true);
  });

  it("a wake of an object whose schema is current runs no DDL", async () => {
    const dev = await newAccount();
    const stub = accountObject(dev.accountId);
    expect(await runInDurableObject(stub, (o: AccountObject) => o.schemaRuns)).toBe(1);
    await evictDurableObject(stub);
    expect(await runInDurableObject(stub, (o: AccountObject) => o.schemaRuns)).toBe(0);
  });

  it("alarms are rounded to the hour", async () => {
    const dev = await newAccount();
    await signed(dev, "GET", "/v1/hooks");
    const alarm = await runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) => state.storage.getAlarm());
    expect(alarm! % 3_600_000).toBe(0);
  });

  it("invocation logs are off (Meta's verify token travels in the query string) and a daily cron prunes D1", () => {
    const cfg = wranglerConfig as string;
    expect(cfg).toMatch(/"invocation_logs":\s*false/);
    expect(cfg).toMatch(/"crons":\s*\[\s*"[^"]+"\s*\]/);
    for (const name of ["SIGNUP_IP_LIMIT", "API_IP_LIMIT"]) expect(cfg).toContain(`"name": "${name}"`);
  });

  it("the daily cleanup deletes only D1 rows past their use", async () => {
    const dev = await newAccount();
    const now = Date.now();
    const old = now - 3 * 86_400_000;
    await env.DB.batch([
      env.DB.prepare("INSERT INTO enrolments (id, account_id, code_hash, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)").bind(
        "enr_old", dev.accountId, "h-old", dev.deviceId, old, old),
      env.DB.prepare("INSERT INTO enrolments (id, account_id, code_hash, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)").bind(
        "enr_new", dev.accountId, "h-new", dev.deviceId, now, now + 600_000),
      env.DB.prepare("INSERT INTO enrolment_failures (ip_hash, window_start, failures, blocked_until) VALUES ('ip-old', ?, 3, NULL)").bind(old),
      env.DB.prepare("INSERT INTO enrolment_failures (ip_hash, window_start, failures, blocked_until) VALUES ('ip-new', ?, 3, NULL)").bind(now),
      env.DB.prepare("INSERT INTO phone_pairings (id, account_id, device_id, verifier, created_at, expires_at) VALUES ('p-old', ?, ?, 'v', ?, ?)").bind(
        dev.accountId, dev.deviceId, old, old),
    ]);
    await pruneD1(env, now);
    const ids = async (q: string) => (await env.DB.prepare(q).all<{ id: string }>()).results.map((r) => r.id);
    expect(await ids("SELECT id FROM enrolments WHERE id IN ('enr_old', 'enr_new')")).toEqual(["enr_new"]);
    expect(await ids("SELECT ip_hash AS id FROM enrolment_failures WHERE ip_hash IN ('ip-old', 'ip-new')")).toEqual(["ip-new"]);
    expect(await ids("SELECT id FROM phone_pairings WHERE id = 'p-old'")).toEqual([]);
  });

  it("revoking a device works on a relay deployed without phone links", async () => {
    const dev = await newAccount();
    const other = await enrolDevice(dev);
    const res = await revokeDevice({ ...env, PHONE: undefined } as unknown as Env, { accountId: dev.accountId, deviceId: dev.deviceId, keyId: null, actor: dev.deviceId, scopes: null }, other.deviceId);
    expect(res.status).toBe(204);
    const row = await env.DB.prepare("SELECT revoked_at FROM devices WHERE id = ?").bind(other.deviceId).first<{ revoked_at: number | null }>();
    expect(row?.revoked_at).not.toBeNull();
  });
});
