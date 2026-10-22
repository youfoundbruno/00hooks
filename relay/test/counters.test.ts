// The account object's schema 8 (relay/docs/COSTS.md): counters written with each commit in one row
// for the account and one per hook, the plan's limits still exact for deliveries in flight and after
// an eviction, the alarm scheduled without an index on nonces, and the upgrade from schemas 4 to 7.

import { evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { SCHEMA_VERSION, utcDay, type AccountObject } from "../src/account-object.ts";
import { call, post, signedWith, withVars } from "./plan-helpers.ts";
import { accountObject, createHook, enrolDevice, newAccount, signed } from "./helpers.ts";

async function setPlan(accountId: string, plan: string | null): Promise<void> {
  await env.DB.prepare("UPDATE accounts SET plan = ? WHERE id = ?").bind(plan, accountId).run();
}

const statuses = (rs: Response[]) => rs.map((r) => r.status).sort((a, b) => a - b);

describe("the plan's limits, counted with the commit", () => {
  // Sealing runs outside any critical section, so a delivery is taken (its seq, its counts) before
  // it commits. These put deliveries "in flight" directly: the limits must count them, and one lost
  // before its commit (an eviction mid-seal) must never have been counted.
  const inFlight = (accountId: string, hookId: string, n: number, rate: { hook?: boolean; account?: boolean }) =>
    runInDurableObject(accountObject(accountId), (o: AccountObject) => {
      const self = o as unknown as { reservations: Set<unknown> };
      const now = Date.now();
      for (let i = 0; i < n; i++) {
        self.reservations.add({
          hookId,
          held: true,
          bytes: 0,
          marks: [],
          at: now,
          count: { day: utcDay(now), hook: rate.hook ? { perMin: 1, burst: 3 } : null, account: rate.account ? { perMin: 1, burst: 2 } : null },
        });
      }
    });
  const forgetInFlight = (accountId: string) =>
    runInDurableObject(accountObject(accountId), (o: AccountObject) => {
      (o as unknown as { reservations: Set<unknown> }).reservations.clear();
    });

  it("deliveries in flight count against the daily cap; one lost before its commit was never taken", async () => {
    const e = withVars({ PLANS: '{"p":{"eventsPerDay":3}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    await inFlight(dev.accountId, hook.id, 2, {});
    expect((await post(e, hook.id)).status).toBe(200);
    const refused = await post(e, hook.id);
    expect(refused.status).toBe(429);
    expect(await refused.json()).toMatchObject({ scope: "daily" });
    await forgetInFlight(dev.accountId);
    expect((await post(e, hook.id)).status).toBe(200);
    expect((await post(e, hook.id)).status).toBe(200);
    expect((await post(e, hook.id)).status).toBe(429);
    const usage = await accountObject(dev.accountId).accountUsage();
    expect(usage.today).toEqual({ events: 3, refused: 2, dropped: 0 });
    expect(usage.perHook[hook.id]!.today).toBe(3);
  });

  it("deliveries in flight take their tokens from the hook's bucket", async () => {
    const e = withVars({ PLANS: '{"p":{"hookRatePerMin":1,"hookBurst":3}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    const { hook: other } = await createHook(dev, { preset: "unverified" });
    await inFlight(dev.accountId, hook.id, 2, { hook: true });
    expect((await post(e, hook.id)).status).toBe(200);
    const refused = await post(e, hook.id);
    expect(refused.status).toBe(429);
    expect(await refused.json()).toMatchObject({ scope: "hook_rate" });
    // A minute a token, and the two in flight took the last ones: the wait says a minute.
    expect(Number(refused.headers.get("Retry-After"))).toBeGreaterThanOrEqual(59);
    // Another hook's bucket is its own.
    expect((await post(e, other.id)).status).toBe(200);
    await forgetInFlight(dev.accountId);
    expect((await post(e, hook.id)).status).toBe(200);
    expect((await post(e, hook.id)).status).toBe(200);
    expect((await post(e, hook.id)).status).toBe(429);
  });

  it("deliveries in flight take their tokens from the account's bucket, across hooks", async () => {
    const e = withVars({ PLANS: '{"p":{"accountRatePerMin":1,"accountBurst":2}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook: a } = await createHook(dev, { preset: "unverified" });
    const { hook: b } = await createHook(dev, { preset: "unverified" });
    await inFlight(dev.accountId, a.id, 1, { account: true });
    expect((await post(e, b.id)).status).toBe(200);
    expect(await (await post(e, b.id)).json()).toMatchObject({ scope: "account_rate" });
    await forgetInFlight(dev.accountId);
    expect((await post(e, a.id)).status).toBe(200);
    expect((await post(e, a.id)).status).toBe(429);
  });

  it("deliveries sent at once meet the daily cap exactly", async () => {
    const e = withVars({ PLANS: '{"p":{"eventsPerDay":3}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    const answers = await Promise.all(Array.from({ length: 7 }, (_, i) => post(e, hook.id, { i })));
    expect(statuses(answers)).toEqual([200, 200, 200, 429, 429, 429, 429]);
    expect((await accountObject(dev.accountId).accountUsage()).today).toEqual({ events: 3, refused: 4, dropped: 0 });
  });

  it("the counts are storage, not memory: an eviction forgets none of them", async () => {
    const e = withVars({ PLANS: '{"p":{"eventsPerDay":3,"hookRatePerMin":1,"hookBurst":5}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    expect((await post(e, hook.id)).status).toBe(200);
    expect((await post(e, hook.id)).status).toBe(200);
    const before = await accountObject(dev.accountId).accountUsage();
    await evictDurableObject(accountObject(dev.accountId));
    expect(await accountObject(dev.accountId).accountUsage()).toEqual(before);
    expect((await post(e, hook.id)).status).toBe(200);
    const refused = await post(e, hook.id);
    expect(refused.status).toBe(429);
    expect(await refused.json()).toMatchObject({ scope: "daily" });
    expect((await accountObject(dev.accountId).stats()).head).toBe(3);
  });

  it("a held delivery counts today too, and a release moves the head without counting again", async () => {
    const e = withVars({ PLANS: '{"p":{"eventsPerDay":5}}' });
    const dev = await newAccount();
    await setPlan(dev.accountId, "p");
    const { hook } = await createHook(dev, { preset: "unverified" });
    const screen = { rules: [{ id: "hold", verdict: "quarantine", conditions: [{ on: "size", op: "gt", bytes: 0 }] }], consent: { words: false } };
    expect((await signedWith(e, dev, "PUT", `/v1/hooks/${hook.id}/screen`, { screen })).status).toBe(200);
    const held = (await (await post(e, hook.id)).json()) as { received: string };
    const usage = await accountObject(dev.accountId).accountUsage();
    expect(usage.today.events).toBe(1);
    // Held events aren't deliveries yet: no "last seen".
    expect(usage.perHook[hook.id]).toMatchObject({ today: 1, lastEventAt: null, backlog: { events: 0, bytes: 0 } });
    expect((await signedWith(e, dev, "POST", `/v1/held/${held.received}/release`)).status).toBe(200);
    const after = await accountObject(dev.accountId).accountUsage();
    expect(after.today.events).toBe(1);
    expect(after.perHook[hook.id]!.backlog.events).toBe(1);
    expect(after.perHook[hook.id]!.lastEventAt).toBeNull();
    expect((await accountObject(dev.accountId).stats()).head).toBe(1);
  });

  it("a deleted hook keeps today's count and what it holds, then its row goes once it has nothing left", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    expect((await call(withVars({}), `/h/${hook.id}`, { method: "POST", body: "{}" })).status).toBe(200);
    expect((await signed(dev, "DELETE", `/v1/hooks/${hook.id}`)).status).toBe(204);
    const usage = await accountObject(dev.accountId).accountUsage();
    expect(usage.perHook[hook.id]).toMatchObject({ today: 1, backlog: { events: 1 }, lastEventAt: null });
    expect(usage.today.events).toBe(1);
    expect((await signed(dev, "POST", "/v1/ack", { through: 1 })).status).toBe(200);
    // A day on, the alarm forgets the row: nothing held, nothing today, no bucket, no delivery.
    await runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) => {
      state.storage.sql.exec("UPDATE hook_usage SET day = day - 1");
      state.storage.sql.exec("UPDATE counters SET day = day - 1");
    });
    await runDurableObjectAlarm(accountObject(dev.accountId));
    const rows = await runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) =>
      state.storage.sql.exec("SELECT * FROM hook_usage").toArray(),
    );
    expect(rows).toEqual([]);
    expect((await accountObject(dev.accountId).accountUsage()).perHook).toEqual({});
  });
});

describe("the alarm, without an index on nonces", () => {
  it("a nonce spent moves a later alarm earlier", async () => {
    const dev = await newAccount();
    const stub = accountObject(dev.accountId);
    await runInDurableObject(stub, (_o: AccountObject, state) => state.storage.setAlarm(Date.now() + 10 * 86_400_000));
    expect((await signed(dev, "GET", "/v1/hooks")).status).toBe(200);
    const alarm = await runInDurableObject(stub, (_o: AccountObject, state) => state.storage.getAlarm());
    expect(alarm! - Date.now()).toBeLessThanOrEqual(2 * 3600_000);
  });

  it("an ack that empties the log keeps the alarm the nonces need; the alarm clears them, then itself", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    expect((await call(withVars({}), `/h/${hook.id}`, { method: "POST", body: "{}" })).status).toBe(200);
    const stub = accountObject(dev.accountId);
    // No replay marks for an unverified hook: once acknowledged, only the nonces are left.
    expect((await signed(dev, "POST", "/v1/ack", { through: 1 })).status).toBe(200);
    expect((await stub.stats()).events).toBe(0);
    expect(await runInDurableObject(stub, (_o: AccountObject, state) => state.storage.getAlarm())).not.toBeNull();
    await runInDurableObject(stub, (_o: AccountObject, state) => {
      state.storage.sql.exec("UPDATE nonces SET at = at - ?", 3600_000);
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const left = await runInDurableObject(stub, async (_o: AccountObject, state) => ({
      nonces: state.storage.sql.exec("SELECT * FROM nonces").toArray().length,
      alarm: await state.storage.getAlarm(),
    }));
    expect(left).toEqual({ nonces: 0, alarm: null });
  });

  it("with no alarm set, the earliest nonce is read again", async () => {
    const dev = await newAccount();
    const stub = accountObject(dev.accountId);
    expect((await signed(dev, "GET", "/v1/hooks")).status).toBe(200);
    // The alarm lost (it can't be, but nothing may depend on it): the next request finds the nonce.
    await runInDurableObject(stub, async (_o: AccountObject, state) => {
      await state.storage.deleteAlarm();
      state.storage.sql.exec("UPDATE nonces SET at = at - ?", 3 * 3600_000);
    });
    const { hook } = await createHook(dev, { preset: "unverified" });
    void hook;
    const alarm = await runInDurableObject(stub, (_o: AccountObject, state) => state.storage.getAlarm());
    expect(alarm! - Date.now()).toBeLessThanOrEqual(61_000 + 3600_000);
  });
});

/** Indexes schema 8 dropped, and the ones it keeps. */
const DROPPED = ["events_received", "events_hook", "events_route", "seen_at", "envelopes_device", "held_hook", "nonces_at"];
const KEPT = ["events_stored", "seen_long_at", "envelopes_seq_device", "held_received"];

describe("schema 8", () => {
  it("is the object's schema", () => {
    expect(SCHEMA_VERSION).toBe(8);
  });

  for (const from of [4, 5, 6, 7]) {
    it(`moves an object at schema ${from} to one counter row for the account and one per hook, keeping every count`, async () => {
      const e = withVars({ PLANS: '{"p":{"eventsPerDay":100,"hookRatePerMin":60,"hookBurst":10,"accountRatePerMin":120,"accountBurst":20}}' });
      const a = await newAccount();
      const b = await enrolDevice(a, "desktop");
      await setPlan(a.accountId, "p");
      const { hook: one } = await createHook(a, { preset: "unverified" });
      const { hook: two } = await createHook(a, { preset: "github" });
      for (let i = 0; i < 3; i++) expect((await post(e, one.id, { i })).status).toBe(200);
      expect((await post(e, one.id, { i: 0 })).status).toBe(200);
      // The second hook took nothing (its signature fails): no row for it.
      expect((await post(e, two.id, { n: 1 })).status).toBe(401);
      // One device has some of them: its envelopes went, the other's stay.
      expect((await signedWith(e, a, "POST", "/v1/ack", { through: 2 })).status).toBe(200);
      void b;
      const stub = accountObject(a.accountId);
      const before = { stats: await stub.stats(), usage: await stub.accountUsage() };
      expect(before.stats).toMatchObject({ head: 4, events: 4, envelopes: 6 });

      await runInDurableObject(stub, (_o: AccountObject, state) => {
        const sql = state.storage.sql;
        // Back to how schema `from` kept its counters: the head and the log's in `meta`, today's
        // counts in `daily` (with yesterday's, not yet pruned), the buckets and "last seen" in
        // tables of their own (schemas 5 to 7), and rows only for hooks holding something.
        const c = sql.exec<{ head: number; day: number; taken: number; tokens: number; tokens_at: number }>("SELECT * FROM counters").one();
        const hooks = sql
          .exec<{ hook_id: string; events: number; bytes: number; day: number; taken: number; last_at: number; written_at: number; tokens: number | null; tokens_at: number }>(
            "SELECT * FROM hook_usage",
          )
          .toArray();
        const sum = (k: "events" | "bytes") => hooks.reduce((n, h) => n + h[k], 0);
        sql.exec("INSERT INTO meta (key, value) VALUES ('head', ?), ('log_events', ?), ('log_bytes', ?)", c.head, sum("events"), sum("bytes"));
        if (from >= 5) {
          sql.exec("CREATE TABLE buckets (key TEXT PRIMARY KEY, tokens REAL NOT NULL, at INTEGER NOT NULL) WITHOUT ROWID");
          sql.exec("CREATE TABLE hook_seen (hook_id TEXT PRIMARY KEY, last_at INTEGER NOT NULL, written_at INTEGER NOT NULL) WITHOUT ROWID");
          sql.exec("INSERT INTO daily (key, day, count) VALUES ('a', ?, ?), ('a', ?, 99)", c.day, c.taken, c.day - 1);
          sql.exec("INSERT INTO buckets (key, tokens, at) VALUES ('a', ?, ?)", c.tokens, c.tokens_at);
          for (const h of hooks) {
            sql.exec("INSERT INTO daily (key, day, count) VALUES (?, ?, ?), (?, ?, 98)", `h:${h.hook_id}`, h.day, h.taken, `h:${h.hook_id}`, h.day - 1);
            if (h.tokens !== null) sql.exec("INSERT INTO buckets (key, tokens, at) VALUES (?, ?, ?)", `h:${h.hook_id}`, h.tokens, h.tokens_at);
            if (h.last_at !== null) sql.exec("INSERT INTO hook_seen (hook_id, last_at, written_at) VALUES (?, ?, ?)", h.hook_id, h.last_at, h.written_at);
          }
        } else {
          // Schema 4 had no plans.
          for (const t of ["daily", "refusals", "limit_notices"]) sql.exec(`DROP TABLE ${t}`);
        }
        sql.exec("DROP TABLE counters");
        sql.exec("DELETE FROM hook_usage WHERE events = 0 AND bytes = 0");
        for (const col of ["day", "taken", "last_at", "written_at", "tokens", "tokens_at"]) sql.exec(`ALTER TABLE hook_usage DROP COLUMN ${col}`);
        if (from < 7) {
          sql.exec("ALTER TABLE events DROP COLUMN recipients");
          sql.exec("ALTER TABLE held_events DROP COLUMN recipients");
          sql.exec("ALTER TABLE devices DROP COLUMN tags");
        }
        if (from < 6) {
          sql.exec("ALTER TABLE events DROP COLUMN route");
          sql.exec("ALTER TABLE held_events DROP COLUMN route");
        }
        sql.exec("CREATE INDEX events_received ON events(received_at)");
        sql.exec("CREATE INDEX events_hook ON events(hook_id)");
        if (from >= 6) sql.exec("CREATE INDEX events_route ON events(route, seq)");
        sql.exec("CREATE INDEX seen_at ON seen(at)");
        sql.exec("CREATE INDEX envelopes_device ON envelopes(device_id, seq)");
        sql.exec("CREATE INDEX held_hook ON held_events(hook_id, rule)");
        sql.exec("CREATE INDEX nonces_at ON nonces(at)");
        // An envelope whose event is gone, as no schema should have left: it can never be streamed.
        sql.exec("INSERT INTO envelopes (seq, device_id, kid, enc, ct, sig) VALUES (999, 'dev_x', 'k', 'e', x'00', 's')");
        sql.exec("UPDATE meta SET value = ? WHERE key = 'schema'", from);
      });
      // The next wake upgrades it.
      await evictDurableObject(stub);
      const after = await runInDurableObject(stub, (o: AccountObject, state) => {
        const sql = state.storage.sql;
        const names = (type: string) => sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = ?", type).toArray().map((r) => r.name);
        return {
          runs: o.schemaRuns,
          schema: sql.exec<{ value: number }>("SELECT value FROM meta WHERE key = 'schema'").one().value,
          meta: sql.exec("SELECT key FROM meta WHERE key IN ('head', 'log_events', 'log_bytes')").toArray(),
          daily: sql.exec("SELECT key FROM daily WHERE key = 'a' OR key LIKE 'h:%'").toArray(),
          dropped: names("index").filter((n) => DROPPED.includes(n)),
          kept: KEPT.filter((n) => names("index").includes(n)),
          tables: ["buckets", "hook_seen", "counters"].filter((t) => names("table").includes(t)),
          orphans: sql.exec("SELECT seq FROM envelopes WHERE seq = 999").toArray(),
          buckets: sql.exec("SELECT tokens IS NOT NULL AS hook FROM hook_usage WHERE hook_id = ?", one.id).toArray(),
        };
      });
      expect(after).toEqual({
        runs: 1,
        schema: 8,
        meta: [],
        daily: [],
        dropped: [],
        kept: KEPT,
        tables: ["counters"],
        orphans: [],
        // Schema 4 had no buckets: the hook's starts full.
        buckets: [{ hook: from >= 5 ? 1 : 0 }],
      });
      expect(await stub.stats()).toEqual(before.stats);
      const usage = await stub.accountUsage();
      if (from >= 5) expect(usage).toEqual(before.usage);
      else {
        // Schema 4 counted nothing for the day, and kept no "last seen".
        expect(usage.today.events).toBe(0);
        expect(usage.perHook[one.id]).toEqual({ ...before.usage.perHook[one.id], today: 0, lastEventAt: null });
        expect(usage.backlog).toEqual(before.usage.backlog);
      }
      // It works on: the next delivery takes the next seq, and is counted.
      expect((await post(e, one.id, { i: 9 })).status).toBe(200);
      const next = await stub.stats();
      expect(next.head).toBe(5);
      expect((await stub.accountUsage()).today.events).toBe(from >= 5 ? before.usage.today.events + 1 : 1);
      // And acknowledging everything leaves nothing counted.
      expect((await signedWith(e, a, "POST", "/v1/ack", { through: 5 })).status).toBe(200);
      expect((await signedWith(e, b, "POST", "/v1/ack", { through: 5 })).status).toBe(200);
      expect(await stub.stats()).toMatchObject({ events: 0, envelopes: 0, usage: { events: 0, bytes: 0 }, hooks: {} });
    });
  }
});
