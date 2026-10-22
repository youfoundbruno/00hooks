// Plans (PROTOCOL §2a): limits from configuration, counted exactly in the account's object; the
// hook cap and daily creations; pauses; the `limit` stream event; `GET /v1/account`. A relay
// without `PLANS` behaves as it did before plans.

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { AccountObject } from "../src/account-object.ts";
import { defaultLimits, parseLimits, planLimits, resolvePlan } from "../src/plans.ts";
import planExample from "../../docs/plans.example.json?raw";
import { call, post, signedWith, withVars } from "./plan-helpers.ts";
import {
  accountObject,
  createHook,
  data,
  enrolDevice,
  newAccount,
  openStream,
  signed,
  type SseReader,
  type TestDevice,
} from "./helpers.ts";

async function setPlan(accountId: string, plan: string | null, until: number | null = null): Promise<void> {
  await env.DB.prepare("UPDATE accounts SET plan = ?, plan_until = ? WHERE id = ?").bind(plan, until, accountId).run();
}

async function nextOf(sse: SseReader, event: string): Promise<Record<string, unknown>> {
  for (;;) {
    const f = await sse.nextEvent();
    if (f === null) throw new Error("stream ended");
    if (f.event === event) return data(f);
  }
}

describe("plans from configuration", () => {
  it("without PLANS, the one plan is `default`, equal to the settings", async () => {
    const limits = defaultLimits(env);
    expect(limits).toEqual({
      hooks: null,
      devices: 10,
      eventsPerDay: null,
      hookRatePerMin: null,
      hookBurst: null,
      accountRatePerMin: null,
      accountBurst: null,
      retentionHours: 168,
      maxBodyBytes: null,
      backlogEvents: 10_000,
      backlogBytes: 268_435_456,
      hookCreatesPerDay: null,
    });
    expect(resolvePlan(env, null, Date.now())).toEqual({ name: "default", limits, until: null, expired: false });
    // An unknown plan name keeps the default's limits; `suspended` is built in.
    expect(resolvePlan(env, { plan: "gone", plan_until: null, limits: null }, Date.now()).limits).toEqual(limits);
    expect(planLimits(env, "suspended")).toMatchObject({ eventsPerDay: 0, hooks: 0, hookCreatesPerDay: 0, backlogEvents: 10_000 });
  });

  it("parses the example config, and a plan's missing keys take the default's", () => {
    const e = withVars({ PLANS: planExample });
    const overblast = planLimits(e, "overblast")!;
    expect(overblast).toEqual({
      hooks: 50,
      devices: 10,
      eventsPerDay: 50_000,
      hookRatePerMin: 120,
      hookBurst: 300,
      accountRatePerMin: 600,
      accountBurst: 1200,
      retentionHours: 168,
      maxBodyBytes: 1_048_576,
      backlogEvents: 10_000,
      backlogBytes: 268_435_456,
      hookCreatesPerDay: 100,
    });
    expect(planLimits(withVars({ PLANS: '{"p":{"eventsPerDay":5}}' }), "p")).toEqual({ ...defaultLimits(env), eventsPerDay: 5 });
    expect(parseLimits({ hooks: -1 })).toBeNull();
    expect(parseLimits({ hooks: 1.5 })).toBeNull();
    expect(parseLimits({ unknown: 1 })).toBeNull();
    expect(parseLimits({ hookRatePerMin: 0.5, hooks: null })).toEqual({ hookRatePerMin: 0.5, hooks: null });
  });

  it("a relay without PLANS changes nothing: no daily cap, no account rate, info and account say so", async () => {
    const e = withVars({});
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (let i = 0; i < 40; i++) expect((await post(e, hook.id, { i })).status).toBe(200);
    const info = (await (await call(e, "/v1/info")).json()) as Record<string, unknown>;
    expect(info.plans).toBe(true);
    expect(info.entitlements).toBe(false);
    expect(info.hostedPlan).toBeUndefined();
    const account = (await (await signed(dev, "GET", "/v1/account")).json()) as Record<string, any>;
    expect(account).toMatchObject({ accountId: dev.accountId, plan: "default", planUntil: null, expired: false, paused: [] });
    expect(account.limits).toEqual(defaultLimits(env));
    expect(account.usage.today).toEqual({ events: 40, refused: 0, dropped: 0 });
    expect(account.usage.perHook[hook.id]).toMatchObject({ today: 40, refused: 0, backlog: { events: 40 } });
    expect(account.usage.backlog.events).toBe(40);
    expect(account.usage).toMatchObject({ hooks: 1, devices: 1, hookCreatesToday: 1 });
    expect(account.upgrade).toBeUndefined();
    // No entitlement keys: no plan route.
    expect((await signed(dev, "PUT", "/v1/account/plan", { entitlement: "ent1.x.y" })).status).toBe(404);
  });

  it("refuses deliveries with 503 when PLANS is malformed, rather than guess", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (const bad of ["{", "[]", '{"p":{"hooks":-1}}', '{"Bad Name":{}}']) {
      expect((await post(withVars({ PLANS: bad }), hook.id)).status).toBe(503);
    }
  });

  it("the hosted plan is announced as data when the operator configures it", async () => {
    const e = withVars({ HOSTED_PLAN: JSON.stringify({ plan: "overblast", title: "Overblast Plan", url: "https://overblast.example/plan", extra: "x" }) });
    const info = (await (await call(e, "/v1/info")).json()) as Record<string, unknown>;
    expect(info.hostedPlan).toEqual({ plan: "overblast", title: "Overblast Plan", url: "https://overblast.example/plan" });
    const dev = await newAccount();
    const account = (await (await signedWith(e, dev, "GET", "/v1/account")).json()) as Record<string, unknown>;
    expect(account.upgrade).toEqual(info.hostedPlan);
    // Malformed (or a non-https URL) is left out.
    expect(((await (await call(withVars({ HOSTED_PLAN: "{" }), "/v1/info")).json()) as Record<string, unknown>).hostedPlan).toBeUndefined();
    const http = (await (await call(withVars({ HOSTED_PLAN: '{"plan":"p","title":"t","url":"http://x"}' }), "/v1/info")).json()) as Record<string, unknown>;
    expect(http.hostedPlan).toEqual({ plan: "p", title: "t" });
  });
});

describe("exact limits in the account's object", () => {
  it("a hook's token bucket refuses past its burst with an exact Retry-After", async () => {
    const e = withVars({ PLANS: '{"p":{"hookRatePerMin":60,"hookBurst":3}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (let i = 0; i < 3; i++) expect((await post(e, hook.id)).status).toBe(200);
    const res = await post(e, hook.id);
    expect(res.status).toBe(429);
    // 60 a minute is one a second: the next token is at most a second away.
    expect(res.headers.get("Retry-After")).toBe("1");
    expect(await res.json()).toMatchObject({ error: "rate_limited", scope: "hook_rate" });
    // Another hook of the account has a bucket of its own.
    const { hook: other } = await createHook(dev, { preset: "unverified" });
    expect((await post(e, other.id)).status).toBe(200);
    await new Promise((r) => setTimeout(r, 1100));
    expect((await post(e, hook.id)).status).toBe(200);
  });

  it("the account's bucket spans its hooks", async () => {
    const e = withVars({ PLANS: '{"p":{"accountRatePerMin":6,"accountBurst":2}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook: a } = await createHook(dev, { preset: "unverified" });
    const { hook: b } = await createHook(dev, { preset: "unverified" });
    expect((await post(e, a.id)).status).toBe(200);
    expect((await post(e, b.id)).status).toBe(200);
    const res = await post(e, a.id);
    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({ error: "rate_limited", scope: "account_rate" });
    // Six a minute: ten seconds a token.
    expect(Number(res.headers.get("Retry-After"))).toBeGreaterThanOrEqual(9);
    expect(Number(res.headers.get("Retry-After"))).toBeLessThanOrEqual(10);
  });

  it("the daily cap refuses until midnight UTC, and counts only what was taken", async () => {
    const e = withVars({ PLANS: '{"p":{"eventsPerDay":2}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    expect((await post(e, hook.id, { a: 1 })).status).toBe(200);
    // A duplicate isn't counted.
    expect((await post(e, hook.id, { a: 2 })).status).toBe(200);
    const res = await post(e, hook.id, { a: 3 });
    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({ error: "quota", scope: "daily" });
    const now = Date.now();
    const midnight = Math.ceil((Math.floor(now / 86_400_000 + 1) * 86_400_000 - now) / 1000);
    expect(Math.abs(Number(res.headers.get("Retry-After")) - midnight)).toBeLessThanOrEqual(2);
    expect((await accountObject(dev.accountId).stats()).events).toBe(2);
    const usage = await accountObject(dev.accountId).accountUsage();
    expect(usage.today).toEqual({ events: 2, refused: 1, dropped: 0 });
  });

  it("a backlog-full refusal doesn't spend a token or a daily count", async () => {
    const e = withVars({ PLANS: '{"p":{"eventsPerDay":3,"backlogEvents":1}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    await runInDurableObject(accountObject(dev.accountId), (o: AccountObject) => {
      const all = { events: 1_000_000, bytes: 1_000_000_000 };
      o.hookQuotaOverride = { checked: all, unchecked: all, held: all };
    });
    expect((await post(e, hook.id)).status).toBe(200);
    const full = await post(e, hook.id);
    expect(full.status).toBe(429);
    expect(await full.json()).toMatchObject({ error: "quota", scope: "account" });
    expect((await accountObject(dev.accountId).accountUsage()).today.events).toBe(1);
  });

  it("an `accept_and_drop` hook answers 200 past the cap, stores nothing, and says `over_limit` as a gap", async () => {
    const e = withVars({ PLANS: '{"p":{"eventsPerDay":1}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const res = await signed(dev, "POST", "/v1/hooks", { name: "drop", verify: { preset: "unverified" }, onLimit: "accept_and_drop" });
    expect(res.status).toBe(201);
    const { hook } = (await res.json()) as { hook: { id: string; onLimit: string } };
    expect(hook.onLimit).toBe("accept_and_drop");
    expect((await post(e, hook.id, { n: 1 })).status).toBe(200);
    const dropped = await post(e, hook.id, { n: 2 });
    expect(dropped.status).toBe(200);
    expect((await dropped.json()) as Record<string, unknown>).toHaveProperty("received");
    expect((await post(e, hook.id, { n: 3 })).status).toBe(200);
    const stub = accountObject(dev.accountId);
    expect((await stub.stats()).events).toBe(1);
    expect((await stub.stats()).head).toBe(3);
    expect((await stub.accountUsage()).today).toEqual({ events: 1, refused: 0, dropped: 2 });
    // The two dropped seqs are one gap, after the stored event.
    const { sse } = await openStream(dev);
    expect((await sse.nextEvent())?.event).toBe("ready");
    const frames: { event?: string; data?: string; id?: string }[] = [];
    for (;;) {
      const f = await sse.nextEvent();
      if (f === null) break;
      if (f.event === "hook" || f.event === "gap") frames.push(f);
      if (f.event === "gap") break;
    }
    expect(frames.map((f) => f.event)).toEqual(["hook", "gap"]);
    expect(data(frames[1]!)).toEqual({ from: 2, to: 3, reason: "over_limit" });
    await sse.cancel();
    // PATCH switches it back; a bad policy is refused.
    expect((await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { onLimit: "refuse" })).status).toBe(200);
    expect((await post(e, hook.id)).status).toBe(429);
    expect((await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { onLimit: "maybe" })).status).toBe(400);
  });

  it("a live stream hears of dropped seqs after the next event", async () => {
    const e = withVars({ PLANS: '{"p":{"eventsPerDay":1}}' });
    const dev = await newAccount();
    const res = await signed(dev, "POST", "/v1/hooks", { name: "drop", verify: { preset: "unverified" }, onLimit: "accept_and_drop" });
    const { hook } = (await res.json()) as { hook: { id: string } };
    const { sse } = await openStream(dev);
    expect((await sse.nextEvent())?.event).toBe("ready");
    expect((await post(e, hook.id, { n: 1 })).status).toBe(200); // default plan: no cap yet
    expect((await nextOf(sse, "hook")).seq).toBe(1);
    await setPlan(dev.accountId, "p");
    expect((await post(e, hook.id, { n: 2 })).status).toBe(200); // dropped
    await setPlan(dev.accountId, null);
    expect((await post(e, hook.id, { n: 3 })).status).toBe(200);
    expect((await nextOf(sse, "hook")).seq).toBe(3);
    expect(await nextOf(sse, "gap")).toEqual({ from: 2, to: 2, reason: "over_limit" });
    await sse.cancel();
  });

  it("the plan's body limit lowers a hook's, and its backlog replaces the settings'", async () => {
    const e = withVars({ PLANS: '{"p":{"maxBodyBytes":100,"backlogEvents":2}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    expect((await post(e, hook.id, { pad: "x".repeat(200) })).status).toBe(413);
    await runInDurableObject(accountObject(dev.accountId), (o: AccountObject) => {
      const all = { events: 1_000_000, bytes: 1_000_000_000 };
      o.hookQuotaOverride = { checked: all, unchecked: all, held: all };
    });
    expect((await post(e, hook.id)).status).toBe(200);
    expect((await post(e, hook.id)).status).toBe(200);
    expect(await (await post(e, hook.id)).json()).toMatchObject({ error: "quota", scope: "account" });
  });

  it("the plan's retention reaches the object, which prunes by it", async () => {
    const e = withVars({ PLANS: '{"p":{"retentionHours":2}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    expect((await post(e, hook.id)).status).toBe(200);
    const meta = await runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) =>
      state.storage.sql.exec<{ key: string; value: number }>("SELECT key, value FROM meta WHERE key LIKE 'plan_%' ORDER BY key").toArray(),
    );
    expect(meta).toEqual([
      { key: "plan_backlog_bytes", value: 268_435_456 },
      { key: "plan_backlog_events", value: 10_000 },
      { key: "plan_retention_ms", value: 2 * 3600_000 },
    ]);
  });

  it("GET /v1/account is a device's route", async () => {
    const dev = await newAccount();
    const created = await signed(dev, "POST", "/v1/keys", { name: "ci", scopes: ["hooks:read"] });
    const { token } = (await created.json()) as { token: string };
    const res = await call(withVars({}), "/v1/account", { headers: { Authorization: `Bearer ${token}` } });
    expect(res.status).toBe(403);
  });
});

describe("pausing a flooding hook", () => {
  it("pauses after the refusals, answers from D1 without waking the object, and unpauses", async () => {
    const e = withVars({ PLANS: '{"p":{"eventsPerDay":1}}', PAUSE_AFTER_REFUSALS: "3" });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    expect((await post(e, hook.id)).status).toBe(200);
    expect(await (await post(e, hook.id)).json()).toMatchObject({ scope: "daily" });
    expect(await (await post(e, hook.id)).json()).toMatchObject({ scope: "daily" });
    const third = await post(e, hook.id);
    expect(third.status).toBe(429);
    const body = (await third.json()) as { scope: string; until: number };
    expect(body.scope).toBe("paused");
    expect(body.until - Date.now()).toBeGreaterThan(3590_000);
    expect(body.until - Date.now()).toBeLessThanOrEqual(3600_000);
    expect(Number(third.headers.get("Retry-After"))).toBeGreaterThan(3590);
    const row = await env.DB.prepare("SELECT paused_until FROM hooks WHERE id = ?").bind(hook.id).first<{ paused_until: number }>();
    expect(row?.paused_until).toBe(body.until);

    // From here the Worker answers from the row: the object counts no more refusals.
    const before = (await accountObject(dev.accountId).accountUsage()).today.refused;
    for (let i = 0; i < 5; i++) expect(await (await post(e, hook.id)).json()).toMatchObject({ error: "rate_limited", scope: "paused" });
    expect((await accountObject(dev.accountId).accountUsage()).today.refused).toBe(before);

    const account = (await (await signedWith(e, dev, "GET", "/v1/account")).json()) as { paused: unknown[] };
    expect(account.paused).toEqual([{ hookId: hook.id, until: body.until }]);
    const listed = (await (await signed(dev, "GET", `/v1/hooks/${hook.id}`)).json()) as { pausedUntil: number };
    expect(listed.pausedUntil).toBe(body.until);
    const audit = (await (await signed(dev, "GET", "/v1/audit")).json()) as { entries: { kind: string; subject: string }[] };
    expect(audit.entries.some((a) => a.kind === "hook.paused" && a.subject === hook.id)).toBe(true);

    // The explicit unpause: deliveries reach the object again (and meet the daily cap).
    const up = await signed(dev, "POST", `/v1/hooks/${hook.id}/unpause`);
    expect(up.status).toBe(200);
    expect(((await up.json()) as { pausedUntil: unknown }).pausedUntil).toBeNull();
    expect(await (await post(e, hook.id)).json()).toMatchObject({ scope: "daily" });
    const audit2 = (await (await signed(dev, "GET", "/v1/audit")).json()) as { entries: { kind: string }[] };
    expect(audit2.entries.some((a) => a.kind === "hook.unpaused")).toBe(true);

    // Paused again soon after: twice as long.
    await post(e, hook.id);
    const again = (await (await post(e, hook.id)).json()) as { scope: string; until: number };
    expect(again.scope).toBe("paused");
    expect(again.until - Date.now()).toBeGreaterThan(7190_000);

    // `PATCH enabled: true` lifts it too.
    const patched = await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { enabled: true });
    expect(((await patched.json()) as { pausedUntil: unknown }).pausedUntil).toBeNull();
    expect(await (await post(e, hook.id)).json()).toMatchObject({ scope: "daily" });
  });

  it("never pauses with PAUSE_AFTER_REFUSALS=0", async () => {
    const e = withVars({ PLANS: '{"p":{"eventsPerDay":0}}', PAUSE_AFTER_REFUSALS: "0" });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (let i = 0; i < 10; i++) expect(await (await post(e, hook.id)).json()).toMatchObject({ scope: "daily" });
  });
});

describe("hook caps", () => {
  it("the plan's hook cap holds atomically, even for creations racing", async () => {
    const e = withVars({ PLANS: '{"p":{"hooks":2}}', HOOK_CREATE_IP_LIMIT: undefined });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const results = await Promise.all(
      [1, 2, 3, 4, 5].map((i) => signedWith(e, dev, "POST", "/v1/hooks", { name: `race ${i}`, verify: { preset: "unverified" } })),
    );
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual([201, 201, 409, 409, 409]);
    const refused = results.find((r) => r.status === 409)!;
    expect(await refused.json()).toMatchObject({ error: "conflict", scope: "hooks", limit: 2 });
    const n = await env.DB.prepare("SELECT count(*) AS n FROM hooks WHERE account_id = ?").bind(dev.accountId).first<{ n: number }>();
    expect(n?.n).toBe(2);
  });

  it("counts hook creations per UTC day", async () => {
    const e = withVars({ PLANS: '{"p":{"hookCreatesPerDay":2}}', HOOK_CREATE_IP_LIMIT: undefined });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const make = (name: string) => signedWith(e, dev, "POST", "/v1/hooks", { name, verify: { preset: "unverified" } });
    const first = (await (await make("a")).json()) as { hook: { id: string } };
    expect((await make("b")).status).toBe(201);
    // Deleting doesn't give a creation back.
    expect((await signedWith(e, dev, "DELETE", `/v1/hooks/${first.hook.id}`)).status).toBe(204);
    const third = await make("c");
    expect(third.status).toBe(429);
    expect(await third.json()).toMatchObject({ error: "rate_limited", scope: "hook_creates" });
    expect(Number(third.headers.get("Retry-After"))).toBeGreaterThan(0);
    // A name taken is still a 409 for the name, and costs no creation.
    const dup = await signedWith(withVars({ HOOK_CREATE_IP_LIMIT: undefined }), dev, "POST", "/v1/hooks", { name: "b", verify: { preset: "unverified" } });
    expect(dup.status).toBe(409);
  });

  it("limits hook creations per address with HOOK_CREATE_IP_LIMIT", async () => {
    const dev = await newAccount();
    const closed = { limit: async () => ({ success: false }) } as unknown as RateLimit;
    const res = await signedWith(withVars({ HOOK_CREATE_IP_LIMIT: closed as unknown as string }), dev, "POST", "/v1/hooks", {
      name: "x",
      verify: { preset: "unverified" },
    });
    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({ error: "rate_limited", scope: "hook_create_ip" });
  });

  it("the plan's device cap applies to enrolment", async () => {
    const e = withVars({ PLANS: '{"p":{"devices":1}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    expect((await signedWith(e, dev, "POST", "/v1/enrolments")).status).toBe(409);
    // On the default plan the settings' cap (10) applies.
    await setPlan(dev.accountId, null);
    await enrolDevice(dev);
  });
});

describe("last_event_at", () => {
  it("is written to D1 at most once a minute per hook; the object keeps the exact time", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const e = withVars({});
    expect((await post(e, hook.id)).status).toBe(200);
    const first = await env.DB.prepare("SELECT last_event_at FROM hooks WHERE id = ?").bind(hook.id).first<{ last_event_at: number }>();
    expect(first?.last_event_at).toBeTypeOf("number");
    await new Promise((r) => setTimeout(r, 20));
    expect((await post(e, hook.id)).status).toBe(200);
    expect((await post(e, hook.id)).status).toBe(200);
    const after = await env.DB.prepare("SELECT last_event_at FROM hooks WHERE id = ?").bind(hook.id).first<{ last_event_at: number }>();
    expect(after?.last_event_at).toBe(first!.last_event_at);
    const usage = await accountObject(dev.accountId).accountUsage();
    expect(usage.perHook[hook.id]!.lastEventAt).toBeGreaterThan(first!.last_event_at);
  });
});

describe("the `limit` stream event", () => {
  it("is sent once per scope and hook per hour, and replayed after `ready`", async () => {
    const e = withVars({ PLANS: '{"p":{"hookRatePerMin":1,"hookBurst":1}}', PAUSE_AFTER_REFUSALS: "0" });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    const { sse } = await openStream(dev);
    expect((await sse.nextEvent())?.event).toBe("ready");
    expect((await post(e, hook.id)).status).toBe(200);
    expect((await nextOf(sse, "hook")).seq).toBe(1);
    expect((await post(e, hook.id)).status).toBe(429);
    const limit = await nextOf(sse, "limit");
    expect(limit).toMatchObject({ scope: "hook_rate", hookId: hook.id, refused: 1, plan: "p" });
    expect(limit.until).toBeGreaterThan(Date.now());
    expect(limit.since).toBeTypeOf("number");
    // More refusals within the hour: counted, not sent.
    expect((await post(e, hook.id)).status).toBe(429);
    expect((await post(e, hook.id)).status).toBe(429);
    await expect(sse.nextEvent(300).then((f) => f?.event)).rejects.toThrow(/timed out/);
    await sse.cancel();
    // A device that reconnects hears of it again, with the count so far.
    const again = await openStream(dev);
    expect((await again.sse.nextEvent())?.event).toBe("ready");
    const replayed = await nextOf(again.sse, "limit");
    expect(replayed).toMatchObject({ scope: "hook_rate", hookId: hook.id, refused: 3 });
    await again.sse.cancel();
  });
});
