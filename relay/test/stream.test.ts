// The log and the stream (PROTOCOL §5–§7), through the real Worker ⇄ Durable Object WebSocket bridge.

import { evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { MAX_FRAME_BYTES, type AccountObject } from "../src/account-object.ts";
import { MAX_BODY_BYTES_LIMIT } from "../src/hooks.ts";
import { signRequest } from "../src/canonical.ts";
import { utf8 } from "../src/encoding.ts";
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
} from "./helpers.ts";

async function ready(sse: SseReader) {
  expect((await sse.next())?.retry).toBe(5000);
  const f = await sse.nextEvent();
  expect(f?.event).toBe("ready");
  return data<{ accountId: string; deviceId: string; after: number; head: number }>(f);
}

async function hooks(sse: SseReader, n: number) {
  const out: { seq: number; id: string; frameId: string }[] = [];
  for (let i = 0; i < n; i++) {
    const f = await sse.nextEvent();
    expect(f?.event).toBe("hook");
    const ev = data<{ seq: number; id: string }>(f);
    out.push({ seq: ev.seq, id: ev.id, frameId: f!.id! });
  }
  return out;
}

async function ack(dev: Parameters<typeof signed>[0], through: number): Promise<number> {
  const res = await signed(dev, "POST", "/v1/ack", { through });
  expect(res.status).toBe(200);
  return ((await res.json()) as { acked: number }).acked;
}

describe("stream", () => {
  it("answers with the SSE headers, retry and ready", async () => {
    const dev = await newAccount();
    const { res, sse } = await openStream(dev);
    expect(res.headers.get("Content-Type")).toBe("text/event-stream");
    expect(res.headers.get("Cache-Control")).toBe("no-cache, no-transform");
    expect(res.headers.get("X-Accel-Buffering")).toBe("no");
    expect(await ready(sse)).toEqual({ protocol: 2, sealKid: dev.seal!.kid, accountId: dev.accountId, deviceId: dev.deviceId, after: 0, head: 0 });
    await sse.cancel();
  });

  it("delivers live events, in order, with id = seq", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const { sse } = await openStream(dev);
    await ready(sse);
    const ids = [await deliver(hook.id, { n: 1 }), await deliver(hook.id, { n: 2 })];
    const got = await hooks(sse, 2);
    expect(got.map((g) => g.id)).toEqual(ids);
    expect(got.map((g) => [g.seq, g.frameId])).toEqual([
      [1, "1"],
      [2, "2"],
    ]);
    await sse.cancel();
  });

  it("sends the backlog after Last-Event-ID, then goes live", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (let i = 1; i <= 5; i++) await deliver(hook.id, { i });
    const { sse } = await openStream(dev, 2);
    expect(await ready(sse)).toMatchObject({ after: 2, head: 5 });
    expect((await hooks(sse, 3)).map((h) => h.seq)).toEqual([3, 4, 5]);
    await deliver(hook.id, { i: 6 });
    expect((await hooks(sse, 1))[0]!.seq).toBe(6);
    await sse.cancel();
  });

  it("starts after max(Last-Event-ID, acked) and never past the head", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (let i = 1; i <= 4; i++) await deliver(hook.id, { i });
    expect(await ack(dev, 3)).toBe(3);
    let s = await openStream(dev, 1);
    expect(await ready(s.sse)).toMatchObject({ after: 3, head: 4 });
    expect((await hooks(s.sse, 1))[0]!.seq).toBe(4);
    await s.sse.cancel();
    s = await openStream(dev, 999);
    expect(await ready(s.sse)).toMatchObject({ after: 4, head: 4 });
    await deliver(hook.id, { i: 5 });
    expect((await hooks(s.sse, 1))[0]!.seq).toBe(5);
    await s.sse.cancel();
  });

  it("pages a large backlog out in order (the object waits for the Worker to drain)", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    // Appended straight to the object: 150 deliveries would trip the hook's rate limit.
    const stub = accountObject(dev.accountId);
    const big = utf8("y".repeat(10_000));
    for (let i = 1; i <= 150; i++) {
      const r = await stub.append({
        hookId: hook.id,
        dedupeKeys: [],
        verified: false,
        strict: false,
        preset: "unverified",
        eventType: null,
        content: { contentType: null, headers: {} },
        body: big,
        receivedAt: Date.now(),
      });
      expect(r.duplicate).toBe(false);
    }
    const { sse } = await openStream(dev);
    await ready(sse);
    const got = await hooks(sse, 150);
    expect(got.map((g) => g.seq)).toEqual(Array.from({ length: 150 }, (_, i) => i + 1));
    await deliver(hook.id, { live: true });
    expect((await hooks(sse, 1))[0]!.seq).toBe(151);
    await sse.cancel();
    // 150 seals and 1.5 MB through the bridge: about 4 s alone, more beside the other files.
  }, 20_000);

  it("refuses a replayed stream request (GET spends the nonce)", async () => {
    const dev = await newAccount();
    const headers = { ...(await signRequest(dev, "GET", `${BASE}/v1/stream`)), "X-00h-Protocol": "2" };
    const first = await fetchRelay("/v1/stream", { headers });
    expect(first.status).toBe(200);
    await first.body!.cancel();
    expect((await fetchRelay("/v1/stream", { headers })).status).toBe(401);
  });

  it("replaces an older stream of the same device with 4409", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const a = await openStream(dev);
    await ready(a.sse);
    const b = await openStream(dev);
    await ready(b.sse);
    const closed = await a.sse.nextEvent();
    expect(closed?.event).toBe("closed");
    expect(data(closed)).toEqual({ code: 4409, reason: "replaced by a newer stream" });
    expect(await a.sse.next()).toBeNull(); // the response ends
    await deliver(hook.id, { to: "b" });
    expect((await hooks(b.sse, 1))[0]!.seq).toBe(1);
    await b.sse.cancel();
  });

  it("closes a revoked device's stream at once with 4401", async () => {
    const dev = await newAccount();
    const other = await enrolDevice(dev);
    const { sse } = await openStream(other);
    await ready(sse);
    expect((await signed(dev, "DELETE", `/v1/devices/${other.deviceId}`)).status).toBe(204);
    const closed = await sse.nextEvent();
    expect(closed?.event).toBe("closed");
    expect(data(closed)).toEqual({ code: 4401, reason: "device revoked" });
    expect(await sse.next()).toBeNull();
  });

  it("keeps delivering after the object is evicted (hibernated sockets survive)", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const { sse } = await openStream(dev);
    await ready(sse);
    await deliver(hook.id, { n: 1 });
    expect((await hooks(sse, 1))[0]!.seq).toBe(1);
    await evictDurableObject(accountObject(dev.accountId));
    await deliver(hook.id, { n: 2 });
    expect((await hooks(sse, 1))[0]!.seq).toBe(2);
    await sse.cancel();
  });
});

describe("large events", () => {
  it("streams a maximum-size event (1,835,008 bytes, base64 in JSON) whole", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    expect((await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { maxBodyBytes: MAX_BODY_BYTES_LIMIT })).status).toBe(200);
    // Random bytes: base64 expands them fully, and nothing compresses.
    const body = new Uint8Array(MAX_BODY_BYTES_LIMIT);
    for (let i = 0; i < body.length; i += 65_536) crypto.getRandomValues(body.subarray(i, i + 65_536));
    const { sse } = await openStream(dev);
    await ready(sse);
    const res = await fetchRelay(`/h/${hook.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream", "User-Agent": "u".repeat(5000) },
      body,
    });
    expect(res.status).toBe(200);
    const f = await sse.nextEvent(10_000);
    expect(f?.event).toBe("hook");
    // The whole frame is far under Cloudflare's 32 MiB WebSocket message limit.
    expect(f!.data!.length).toBeGreaterThan(2_446_000);
    expect(f!.data!.length).toBeLessThan(MAX_FRAME_BYTES / 10);
    const ev = data<StreamedEvent>(f);
    const got = (await openEvent(dev, ev)).body;
    expect(got.byteLength).toBe(MAX_BODY_BYTES_LIMIT);
    expect(got.slice(0, 64)).toEqual(body.slice(0, 64));
    expect(got.slice(-64)).toEqual(body.slice(-64));
    // The stream keeps going after it.
    await deliver(hook.id, { after: true });
    expect((await hooks(sse, 1))[0]!.seq).toBe(ev.seq + 1);
    await sse.cancel();
  }, 30_000);

  it("reports an event over the frame limit as a one-event gap instead of wedging the stream", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const stub = accountObject(dev.accountId);
    await runInDurableObject(stub, (o: AccountObject) => {
      o.frameLimit = 4096;
    });
    const append = (bytes: number) =>
      stub.append({
        hookId: hook.id,
        dedupeKeys: [],
        verified: false,
        preset: "unverified",
        eventType: null,
        strict: false,
        content: { contentType: null, headers: {} },
        body: utf8("z".repeat(bytes)),
        receivedAt: Date.now(),
      });
    await append(10); // 1
    await append(10_000); // 2: too large for this stream
    await append(10); // 3
    // In the backlog…
    const { sse } = await openStream(dev);
    await ready(sse);
    expect((await hooks(sse, 1))[0]!.seq).toBe(1);
    const gap = await sse.nextEvent();
    expect(gap?.event).toBe("gap");
    expect(gap?.id).toBe("2");
    expect(data(gap)).toEqual({ from: 2, to: 2, reason: "too_large" });
    expect((await hooks(sse, 1))[0]!.seq).toBe(3);
    // …and live.
    await append(10_000); // 4
    await append(10); // 5
    expect(data(await sse.nextEvent())).toEqual({ from: 4, to: 4, reason: "too_large" });
    expect((await hooks(sse, 1))[0]!.seq).toBe(5);
    await sse.cancel();
  });
});

describe("acks", () => {
  it("are monotonic per device and never pass the head", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (let i = 1; i <= 5; i++) await deliver(hook.id, { i });
    expect(await ack(dev, 3)).toBe(3);
    expect(await ack(dev, 1)).toBe(3);
    expect(await ack(dev, 99)).toBe(5);
    const bad = await signed(dev, "POST", "/v1/ack", { through: -1 });
    expect(await bad.json()).toMatchObject({ error: "invalid", field: "through" });
    expect((await signed(dev, "POST", "/v1/ack", { through: "3" })).status).toBe(400);
  });

  it("delete an event once every device has acknowledged it", async () => {
    const dev = await newAccount();
    const second = await enrolDevice(dev);
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (let i = 1; i <= 4; i++) await deliver(hook.id, { i });
    const stub = accountObject(dev.accountId);
    await ack(dev, 4);
    expect((await stub.stats()).events).toBe(4);
    await ack(second, 2);
    expect((await stub.stats()).events).toBe(2);
    // Revoking the slow device releases what it held back.
    await signed(dev, "DELETE", `/v1/devices/${second.deviceId}`);
    expect((await stub.stats()).events).toBe(0);
    // seq is never reused.
    await deliver(hook.id, { i: 5 });
    expect((await stub.stats()).head).toBe(5);
  });

  it("a device enrolled later starts at the head", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    await deliver(hook.id, { i: 1 });
    const later = await enrolDevice(dev);
    const { sse } = await openStream(later);
    expect(await ready(sse)).toMatchObject({ after: 1, head: 1 });
    await sse.cancel();
  });
});

describe("retention and gaps", () => {
  async function age(accountId: string, seqs: number[], daysAgo: number) {
    await runInDurableObject(accountObject(accountId), async (_obj: AccountObject, state) => {
      for (const s of seqs) {
        const at = Date.now() - daysAgo * 86_400_000;
        state.storage.sql.exec("UPDATE events SET received_at = ?, stored_at = ? WHERE seq = ?", at, at, s);
      }
    });
  }

  it("drops unacknowledged events past retention and reports the gap on resume", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (let i = 1; i <= 6; i++) await deliver(hook.id, { i });
    await age(dev.accountId, [1, 2, 3, 4], 8);
    const stub = accountObject(dev.accountId);
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect((await stub.stats()).events).toBe(2);

    const { sse } = await openStream(dev, 1);
    expect(await ready(sse)).toMatchObject({ after: 1, head: 6 });
    const gap = await sse.nextEvent();
    expect(gap?.event).toBe("gap");
    expect(gap?.id).toBe("4");
    expect(data(gap)).toEqual({ from: 2, to: 4, reason: "retention" });
    expect((await hooks(sse, 2)).map((h) => h.seq)).toEqual([5, 6]);
    await sse.cancel();
  });

  it("reports a gap at the end of the log when everything after the cursor was dropped", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (let i = 1; i <= 3; i++) await deliver(hook.id, { i });
    await age(dev.accountId, [1, 2, 3], 8);
    await runDurableObjectAlarm(accountObject(dev.accountId));
    const { sse } = await openStream(dev);
    await ready(sse);
    expect(data(await sse.nextEvent())).toEqual({ from: 1, to: 3, reason: "retention" });
    await deliver(hook.id, { i: 4 });
    expect((await hooks(sse, 1))[0]!.seq).toBe(4);
    await sse.cancel();
  });

  it("merges adjacent pruned ranges and forgets them once every device is past them", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (let i = 1; i <= 4; i++) await deliver(hook.id, { i });
    const stub = accountObject(dev.accountId);
    await age(dev.accountId, [1, 2], 8);
    await runDurableObjectAlarm(stub);
    await age(dev.accountId, [3], 8);
    await runDurableObjectAlarm(stub);
    const ranges = () =>
      runInDurableObject(stub, async (_o: AccountObject, state) => state.storage.sql.exec("SELECT from_seq, to_seq FROM pruned").toArray());
    expect(await ranges()).toEqual([{ from_seq: 1, to_seq: 3 }]);
    await ack(dev, 4);
    expect(await ranges()).toEqual([]);
  });

  it("schedules no alarm for an idle account with nothing to expire", async () => {
    const dev = await newAccount();
    const stub = accountObject(dev.accountId);
    // The signup spends no nonce; nothing is pending.
    const alarm = await runInDurableObject(stub, (_o: AccountObject, state) => state.storage.getAlarm());
    expect(alarm).toBeNull();
    // A signed request leaves a nonce, which schedules one expiry alarm; once it runs, none is left.
    await signed(dev, "GET", "/v1/hooks");
    expect(await runInDurableObject(stub, (_o: AccountObject, state) => state.storage.getAlarm())).not.toBeNull();
    await runInDurableObject(stub, (_o: AccountObject, state) => {
      state.storage.sql.exec("UPDATE nonces SET at = ?", Date.now() - 700_000);
    });
    await runDurableObjectAlarm(stub);
    expect(await runInDurableObject(stub, (_o: AccountObject, state) => state.storage.getAlarm())).toBeNull();
  });
});
