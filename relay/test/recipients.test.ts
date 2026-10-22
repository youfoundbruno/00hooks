// A hook's recipients (PROTOCOL §3): a list of devices, devices by tag, or both; device tags (§2);
// sealing and acknowledgement per recipient; removed devices; the `no_recipient` pause; the
// one-device `deliverTo` kept as it was; and the object's schema 7.

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { AccountObject } from "../src/account-object.ts";
import {
  accountObject,
  createHook,
  data,
  deliver,
  enrolDevice,
  fetchRelay,
  newAccount,
  newNode,
  openEvent,
  openStream,
  pairPhone,
  signed,
  type SseReader,
  type StreamedEvent,
  type TestDevice,
} from "./helpers.ts";

interface HookJson {
  id: string;
  deliverTo: string | null;
  recipients: { devices: string[]; tags: string[] } | null;
  pausedReason: string | null;
}

async function patch(dev: TestDevice, hookId: string, body: unknown): Promise<Response> {
  return signed(dev, "PATCH", `/v1/hooks/${hookId}`, body);
}

async function target(dev: TestDevice, hookId: string, body: unknown): Promise<HookJson> {
  const res = await patch(dev, hookId, body);
  expect(res.status, await res.clone().text()).toBe(200);
  return (await res.json()) as HookJson;
}

async function tag(dev: TestDevice, deviceId: string, tags: string[]): Promise<Response> {
  return signed(dev, "PATCH", `/v1/devices/${deviceId}`, { tags });
}

async function hookOf(dev: TestDevice, hookId: string): Promise<HookJson> {
  return (await (await signed(dev, "GET", `/v1/hooks/${hookId}`)).json()) as HookJson;
}

/** The devices each event in the log has an envelope for, by event id. */
async function sealedFor(accountId: string): Promise<Record<string, string[]>> {
  return runInDurableObject(accountObject(accountId), (_o: AccountObject, state) => {
    const out: Record<string, string[]> = {};
    for (const r of state.storage.sql
      .exec<{ id: string; device_id: string }>("SELECT ev.id, e.device_id FROM envelopes e JOIN events ev ON ev.seq = e.seq ORDER BY e.device_id")
      .toArray()) {
      (out[r.id] ??= []).push(r.device_id);
    }
    return out;
  });
}

/** The next frame of `event`, past others. */
async function nextOf(sse: SseReader, event: string, timeoutMs?: number) {
  for (;;) {
    const f = await sse.nextEvent(timeoutMs);
    if (f === null || f.event === event) return f;
  }
}

/** Every `hook` event a device's stream sends from the start, until it goes quiet. */
async function streamed(dev: TestDevice): Promise<StreamedEvent[]> {
  const s = await openStream(dev, 0);
  expect((await s.sse.nextEvent())?.event).toBe("ready");
  const out: StreamedEvent[] = [];
  for (;;) {
    const f = await nextOf(s.sse, "hook", 300).catch(() => null);
    if (!f) break;
    out.push(data<StreamedEvent>(f));
  }
  await s.sse.cancel();
  return out;
}

async function threeDevices(): Promise<[TestDevice, TestDevice, TestDevice]> {
  const a = await newAccount("a");
  return [a, await enrolDevice(a, "b"), await enrolDevice(a, "c")];
}

describe("a list of devices", () => {
  it("seals only to the listed devices; the others pass it by and hold nothing for it", async () => {
    const [a, b, c] = await threeDevices();
    const { hook } = await createHook(a, { preset: "unverified" });
    const h = await target(a, hook.id, { recipients: { devices: [b.deviceId, c.deviceId] } });
    expect(h.recipients).toEqual({ devices: [b.deviceId, c.deviceId], tags: [] });
    // Old clients read `deliverTo` as one device or every device: a list is neither, so it's null.
    expect(h.deliverTo).toBeNull();
    expect(h.pausedReason).toBeNull();
    const id = await deliver(hook.id, { n: 1 });
    expect((await sealedFor(a.accountId))[id]).toEqual([b.deviceId, c.deviceId].sort());
    expect(await streamed(a)).toEqual([]);
    for (const dev of [b, c]) {
      const got = await streamed(dev);
      expect(got.map((e) => e.id)).toEqual([id]);
      expect((await openEvent(dev, got[0]!)).text).toBe('{"n":1}');
    }
    const audit = (await (await signed(a, "GET", "/v1/audit")).json()) as { entries: { kind: string; name: string }[] };
    expect(audit.entries.find((e) => e.kind === "hook.delivery")?.name).toBe(`${b.deviceId},${c.deviceId}`);
  });

  it("keeps an event until every recipient has acknowledged it: one acknowledging takes it from nobody else", async () => {
    const [a, b, c] = await threeDevices();
    const { hook } = await createHook(a, { preset: "unverified" });
    await target(a, hook.id, { recipients: { devices: [b.deviceId, c.deviceId] } });
    await deliver(hook.id, { n: 1 });
    const [ev] = await streamed(b);
    expect((await signed(b, "POST", "/v1/ack", { through: ev!.seq })).status).toBe(200);
    let stats = await accountObject(a.accountId).stats();
    expect(stats.events).toBe(1);
    expect(stats.envelopes).toBe(1);
    // c still gets it, and can open it.
    const [forC] = await streamed(c);
    expect(forC?.id).toBe(ev!.id);
    expect((await openEvent(c, forC!)).text).toBe('{"n":1}');
    // The events list says who it is for and who has it.
    const listed = (await (await signed(a, "GET", "/v1/events")).json()) as {
      events: { id: string; recipients: string[] | null; deliveredTo: string[]; pendingFor: string[] }[];
    };
    expect(listed.events[0]).toMatchObject({ recipients: [b.deviceId, c.deviceId].sort(), deliveredTo: [b.deviceId], pendingFor: [c.deviceId] });
    // The last recipient acknowledges: gone, whatever a (never a recipient) has acknowledged.
    expect((await signed(c, "POST", "/v1/ack", { through: ev!.seq })).status).toBe(200);
    stats = await accountObject(a.accountId).stats();
    expect(stats.events).toBe(0);
    expect(stats.usage.events).toBe(0);
  });

  it("drops a revoked device from the list, and lets the others' acknowledgements finish an event it held", async () => {
    const [a, b, c] = await threeDevices();
    const { hook } = await createHook(a, { preset: "unverified" });
    await target(a, hook.id, { recipients: { devices: [b.deviceId, c.deviceId] } });
    await deliver(hook.id, { n: 1 });
    const [ev] = await streamed(c);
    await signed(c, "POST", "/v1/ack", { through: ev!.seq });
    expect((await accountObject(a.accountId).stats()).events).toBe(1);
    expect((await signed(a, "DELETE", `/v1/devices/${b.deviceId}`)).status).toBe(204);
    // b held the event back; revoked, it no longer does.
    expect((await accountObject(a.accountId).stats()).events).toBe(0);
    const h = await hookOf(a, hook.id);
    expect(h.recipients).toEqual({ devices: [c.deviceId], tags: [] });
    // One device left: old clients see it as `deliverTo` again.
    expect(h.deliverTo).toBe(c.deviceId);
    expect(h.pausedReason).toBeNull();
  });

  it("refuses devices that aren't the account's active computers with a key, too many, duplicates folded", async () => {
    const a = await newAccount("a");
    const keyless = await enrolDevice(a, "keyless", { seal: false });
    const stranger = await newAccount("stranger");
    const { hook } = await createHook(a, { preset: "unverified" });
    const bad: [unknown, string][] = [
      [{ recipients: { devices: [stranger.deviceId] } }, "recipients.devices"],
      [{ recipients: { devices: [keyless.deviceId] } }, "recipients.devices"],
      [{ recipients: { devices: ["dev_nope"] } }, "recipients.devices"],
      [{ recipients: { devices: a.deviceId } }, "recipients.devices"],
      [{ recipients: { devices: Array.from({ length: 11 }, (_, i) => `dev_${"0".repeat(25)}${i.toString(16)}`) } }, "recipients.devices"],
      [{ recipients: {} }, "recipients"],
      [{ recipients: { devices: [], tags: [] } }, "recipients"],
      [{ recipients: { devices: [a.deviceId], who: 1 } }, "recipients"],
      [{ recipients: [a.deviceId] }, "recipients"],
      [{ recipients: { tags: ["Office"] } }, "recipients.tags"],
      [{ recipients: { tags: ["-x"] } }, "recipients.tags"],
      [{ recipients: { tags: ["x".repeat(33)] } }, "recipients.tags"],
      [{ recipients: { tags: Array.from({ length: 11 }, (_, i) => `t${i}`) } }, "recipients.tags"],
      [{ deliverTo: a.deviceId, recipients: null }, "recipients"],
    ];
    for (const [body, field] of bad) {
      const res = await patch(a, hook.id, body);
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(((await res.json()) as { field: string }).field, JSON.stringify(body)).toBe(field);
    }
    const h = await target(a, hook.id, { recipients: { devices: [a.deviceId, a.deviceId] } });
    expect(h.recipients).toEqual({ devices: [a.deviceId], tags: [] });
  });
});

describe("a single deliverTo, as before", () => {
  it("still sets one device and reads back the same way, with recipients as a one-device list", async () => {
    const [a, b] = await threeDevices();
    const { hook } = await createHook(a, { preset: "unverified" });
    const h = await target(a, hook.id, { deliverTo: b.deviceId });
    expect(h).toMatchObject({ deliverTo: b.deviceId, recipients: { devices: [b.deviceId], tags: [] } });
    const id = await deliver(hook.id, { n: 1 });
    expect((await sealedFor(a.accountId))[id]).toEqual([b.deviceId]);
    expect(await target(a, hook.id, { deliverTo: null })).toMatchObject({ deliverTo: null, recipients: null });
  });

  it("reads a hook row from before recipients (deliver_to alone) as that device", async () => {
    const [a, b] = await threeDevices();
    const { hook } = await createHook(a, { preset: "unverified" });
    await env.DB.prepare("UPDATE hooks SET deliver_to = ?, recipients = NULL WHERE id = ?").bind(b.deviceId, hook.id).run();
    expect(await hookOf(a, hook.id)).toMatchObject({ deliverTo: b.deviceId, recipients: { devices: [b.deviceId], tags: [] } });
    const id = await deliver(hook.id, { n: 1 });
    expect((await sealedFor(a.accountId))[id]).toEqual([b.deviceId]);
  });
});

describe("device tags", () => {
  it("are set on a computer, listed, audited and validated; a phone takes none", async () => {
    const node = await newNode("mac");
    const res = await tag(node, node.deviceId, ["office-macs", "build.1", "office-macs"]);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { device: { tags: string[] } }).device.tags).toEqual(["office-macs", "build.1"]);
    const listed = (await (await signed(node, "GET", "/v1/devices")).json()) as { devices: { id: string; tags: string[] }[] };
    expect(listed.devices.find((d) => d.id === node.deviceId)?.tags).toEqual(["office-macs", "build.1"]);
    for (const tags of [["UPPER"], ["a b"], [""], ["x".repeat(33)], ["ok."], Array.from({ length: 11 }, (_, i) => `t${i}`), "office"]) {
      const r = await tag(node, node.deviceId, tags as string[]);
      expect(r.status, JSON.stringify(tags)).toBe(400);
      expect(((await r.json()) as { field: string }).field).toBe("tags");
    }
    const phone = await pairPhone(node);
    const p = await tag(node, phone.deviceId, ["pocket"]);
    expect(p.status).toBe(400);
    expect(((await p.json()) as { field: string }).field).toBe("tags");
    // Cleared with an empty list.
    expect(((await (await tag(node, node.deviceId, [])).json()) as { device: { tags: string[] } }).device.tags).toEqual([]);
    const audit = (await (await signed(node, "GET", "/v1/audit")).json()) as { entries: { kind: string; name: string }[] };
    expect(audit.entries.filter((e) => e.kind === "device.tagged").map((e) => e.name)).toEqual(["-", "office-macs,build.1"]);
    const stranger = await newAccount("stranger");
    expect((await tag(stranger, node.deviceId, ["mine"])).status).toBe(404);
  });

  it("route a hook to the devices carrying them; a device tagged later gets new events only", async () => {
    const [a, b, c] = await threeDevices();
    await tag(a, b.deviceId, ["office-macs"]);
    const { hook } = await createHook(a, { preset: "unverified" });
    const h = await target(a, hook.id, { recipients: { tags: ["office-macs"] } });
    expect(h).toMatchObject({ deliverTo: null, recipients: { devices: [], tags: ["office-macs"] }, pausedReason: null });
    const first = await deliver(hook.id, { n: 1 });
    expect((await sealedFor(a.accountId))[first]).toEqual([b.deviceId]);
    // c joins the tag: from the next event on (the first was sealed before; no backfill).
    expect((await tag(a, c.deviceId, ["other", "office-macs"])).status).toBe(200);
    const second = await deliver(hook.id, { n: 2 });
    const sealed = await sealedFor(a.accountId);
    expect(sealed[first]).toEqual([b.deviceId]);
    expect(sealed[second]).toEqual([b.deviceId, c.deviceId].sort());
    expect((await streamed(c)).map((e) => e.id)).toEqual([second]);
    expect(await streamed(a)).toEqual([]);
    // b leaves the tag: new events skip it.
    await tag(a, b.deviceId, []);
    const third = await deliver(hook.id, { n: 3 });
    expect((await sealedFor(a.accountId))[third]).toEqual([c.deviceId]);
  });

  it("combine with a list as a union", async () => {
    const [a, b, c] = await threeDevices();
    await tag(a, c.deviceId, ["ci"]);
    const { hook } = await createHook(a, { preset: "unverified" });
    await target(a, hook.id, { recipients: { devices: [b.deviceId], tags: ["ci"] } });
    const id = await deliver(hook.id, { n: 1 });
    expect((await sealedFor(a.accountId))[id]).toEqual([b.deviceId, c.deviceId].sort());
    const audit = (await (await signed(a, "GET", "/v1/audit")).json()) as { entries: { kind: string; name: string }[] };
    expect(audit.entries.find((e) => e.kind === "hook.delivery")?.name).toBe(`${b.deviceId},#ci`);
  });
});

describe("a hook with no recipient left", () => {
  it("pauses with a clear reason when its tag matches nobody, says so on the stream, and resumes when a device is tagged", async () => {
    const [a, b] = await threeDevices();
    const { hook } = await createHook(a, { preset: "unverified" });
    const s = await openStream(a, 0);
    expect((await s.sse.nextEvent())?.event).toBe("ready");
    const h = await target(a, hook.id, { recipients: { tags: ["nobody-yet"] } });
    expect(h.pausedReason).toBe("no_recipient");
    const limit = data<{ scope: string; hookId: string; until: number | null }>(await nextOf(s.sse, "limit"));
    expect(limit).toMatchObject({ scope: "no_recipient", hookId: hook.id, until: null });
    await s.sse.cancel();
    // Refused, never stored or dropped in silence: the provider keeps it and retries.
    const res = await fetchRelay(`/h/${hook.id}`, { method: "POST", body: "{}" });
    expect(res.status).toBe(503);
    expect(res.headers.get("retry-after")).toBe("300");
    expect(await res.json()).toMatchObject({ error: "unavailable", scope: "no_recipient" });
    expect((await accountObject(a.accountId).stats()).events).toBe(0);
    // A reconnecting device hears of it after `ready`.
    const again = await openStream(b, 0);
    expect(data<{ scope: string }>(await nextOf(again.sse, "limit")).scope).toBe("no_recipient");
    await again.sse.cancel();

    await tag(a, b.deviceId, ["nobody-yet"]);
    expect((await hookOf(a, hook.id)).pausedReason).toBeNull();
    const id = await deliver(hook.id, { n: 1 });
    expect((await sealedFor(a.accountId))[id]).toEqual([b.deviceId]);
    expect(await accountObject(a.accountId).limitNotices()).toEqual([]);
    // Untagged again: paused again.
    await tag(a, b.deviceId, []);
    expect((await hookOf(a, hook.id)).pausedReason).toBe("no_recipient");
    const audit = (await (await signed(a, "GET", "/v1/audit")).json()) as { entries: { kind: string; name: string | null }[] };
    expect(audit.entries.filter((e) => e.kind === "hook.paused" || e.kind === "hook.unpaused").map((e) => `${e.kind}:${e.name}`)).toEqual([
      "hook.paused:no_recipient",
      "hook.unpaused:no_recipient",
      "hook.paused:no_recipient",
    ]);
  });

  it("pauses when its last listed device is revoked, and resumes when the target changes", async () => {
    const [a, b] = await threeDevices();
    const { hook } = await createHook(a, { preset: "unverified" });
    await target(a, hook.id, { recipients: { devices: [b.deviceId] } });
    await signed(a, "DELETE", `/v1/devices/${b.deviceId}`);
    expect(await hookOf(a, hook.id)).toMatchObject({ recipients: { devices: [], tags: [] }, pausedReason: "no_recipient" });
    expect((await fetchRelay(`/h/${hook.id}`, { method: "POST", body: "{}" })).status).toBe(503);
    // Unpausing alone can't help: nobody matches yet.
    const un = (await (await signed(a, "POST", `/v1/hooks/${hook.id}/unpause`)).json()) as HookJson;
    expect(un.pausedReason).toBe("no_recipient");
    const h = await target(a, hook.id, { recipients: { devices: [a.deviceId] } });
    expect(h.pausedReason).toBeNull();
    const id = await deliver(hook.id, { n: 1 });
    expect((await sealedFor(a.accountId))[id]).toEqual([a.deviceId]);
  });

  it("is noticed by the account's object too when D1 hasn't paused it yet, and pauses then", async () => {
    const [a] = await threeDevices();
    const { hook } = await createHook(a, { preset: "unverified" });
    // A target written behind the API's back: the object, which seals, finds nobody.
    await env.DB.prepare("UPDATE hooks SET recipients = ? WHERE id = ?").bind(JSON.stringify({ devices: [], tags: ["ghost"] }), hook.id).run();
    const res = await fetchRelay(`/h/${hook.id}`, { method: "POST", body: "{}" });
    expect(res.status).toBe(503);
    expect((await env.DB.prepare("SELECT paused_reason FROM hooks WHERE id = ?").bind(hook.id).first<{ paused_reason: string }>())?.paused_reason).toBe(
      "no_recipient",
    );
    const notices = await accountObject(a.accountId).limitNotices();
    expect(notices).toMatchObject([{ scope: "no_recipient", hookId: hook.id, refused: 1, until: null }]);
    const stats = await accountObject(a.accountId).stats();
    expect(stats.events).toBe(0);
    expect(stats.head).toBe(0);
  });

  it("refuses a held delivery too, and a held event whose recipients are all gone is never released to anyone else", async () => {
    const [a, b] = await threeDevices();
    const { hook } = await createHook(a, { preset: "unverified" });
    await target(a, hook.id, { recipients: { devices: [b.deviceId] } });
    const screen = { rules: [{ id: "hold", verdict: "quarantine", conditions: [{ on: "size", op: "gt", bytes: 0 }] }], consent: { words: false } };
    await signed(a, "PUT", `/v1/hooks/${hook.id}/screen`, { screen });
    const id = await deliver(hook.id, { n: 1 });
    await signed(a, "DELETE", `/v1/devices/${b.deviceId}`);
    expect((await signed(a, "POST", `/v1/held/${id}/release`)).status).toBe(404);
    const stats = await accountObject(a.accountId).stats();
    expect(stats.held).toBe(0);
    expect(stats.events).toBe(0);
    expect((await fetchRelay(`/h/${hook.id}`, { method: "POST", body: "{}" })).status).toBe(503);
  });
});

describe("schema 7", () => {
  for (const from of [4, 5, 6]) {
    it(`moves an object at schema ${from} to recipients and tags, keeping its events and their routes`, async () => {
      const [a, b] = await threeDevices();
      const { hook } = await createHook(a, { preset: "unverified" });
      await target(a, hook.id, { deliverTo: b.deviceId });
      await deliver(hook.id, { n: 1 });
      const { hook: other } = await createHook(a, { preset: "unverified" });
      await deliver(other.id, { n: 2 });
      const after = await runInDurableObject(accountObject(a.accountId), (o: AccountObject, state) => {
        const sql = state.storage.sql;
        // Back to how schema `from` stored it: a routed event named its device in `route` (6), or
        // had no route column at all (4 and 5, whose objects predate one-device delivery).
        sql.exec("UPDATE events SET route = json_extract(recipients, '$[0]') WHERE recipients IS NOT NULL");
        sql.exec("ALTER TABLE events DROP COLUMN recipients");
        sql.exec("ALTER TABLE held_events DROP COLUMN recipients");
        sql.exec("ALTER TABLE devices DROP COLUMN tags");
        if (from < 6) {
          sql.exec("UPDATE events SET route = NULL");
          sql.exec("DROP INDEX IF EXISTS events_route");
          sql.exec("ALTER TABLE events DROP COLUMN route");
          sql.exec("ALTER TABLE held_events DROP COLUMN route");
        }
        sql.exec("UPDATE meta SET value = ? WHERE key = 'schema'", from);
        (o as unknown as { migrate(): void }).migrate();
        return {
          schema: sql.exec<{ value: number }>("SELECT value FROM meta WHERE key = 'schema'").one().value,
          events: sql.exec<{ recipients: string | null }>("SELECT recipients FROM events ORDER BY seq").toArray(),
          tags: sql.exec("SELECT tags FROM devices").toArray().length,
          index: sql.exec("SELECT name FROM sqlite_master WHERE name = 'events_route'").toArray().length,
        };
      });
      expect(after).toEqual({
        // Through 7 to 8, which drops the route index nothing reads any more.
        schema: 8,
        events: [{ recipients: from === 6 ? JSON.stringify([b.deviceId]) : null }, { recipients: null }],
        tags: 3,
        index: 0,
      });
      // The object works on: tags route, the migrated event is acknowledged per recipient.
      await tag(a, a.deviceId, ["t"]);
      await target(a, hook.id, { recipients: { tags: ["t"] } });
      const id = await deliver(hook.id, { n: 3 });
      expect((await sealedFor(a.accountId))[id]).toEqual([a.deviceId]);
    });
  }
});
