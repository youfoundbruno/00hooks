// The SSE bridge on its own, with fake timers: heartbeats, backpressure and resync, the 4408 stall
// close, and how upstream closes map to the protocol's codes.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SseBridge } from "../src/bridge.ts";

class FakeUpstream {
  sent: string[] = [];
  closed: { code: number; reason: string } | null = null;
  send(m: string) {
    this.sent.push(m);
  }
  close(code: number, reason: string) {
    this.closed = { code, reason };
  }
}

const decoder = new TextDecoder();

/**
 * Reads whatever the bridge has ready right now, stopping at the first read that would wait (and
 * keeping that read for the next call, so no chunk is lost).
 */
class Tap {
  private pending: Promise<ReadableStreamReadResult<Uint8Array>> | null = null;
  readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  constructor(reader: ReadableStreamDefaultReader<Uint8Array>) {
    this.reader = reader;
  }
  async take(): Promise<{ text: string; done: boolean }> {
    let text = "";
    for (;;) {
      this.pending ??= this.reader.read();
      const r = await Promise.race([this.pending, new Promise<"wait">((res) => setTimeout(() => res("wait"), 0))]);
      if (r === "wait") return { text, done: false };
      this.pending = null;
      if (r.done) return { text, done: true };
      text += decoder.decode(r.value);
    }
  }
  /** Runs the fake clock forward, then takes what's ready. */
  async after(ms: number): Promise<{ text: string; done: boolean }> {
    await vi.advanceTimersByTimeAsync(ms);
    return this.take();
  }
  cancel() {
    return this.reader.cancel();
  }
}

function tap(b: SseBridge): Tap {
  return new Tap(b.readable.getReader());
}

function hook(seq: number, size = 10): string {
  return `h${seq}\n${JSON.stringify({ seq, body: "x".repeat(size) })}`;
}

describe("SseBridge", () => {
  beforeEach(() => {
    // The bridge uses setInterval and Date.now; setTimeout stays real for the Tap helper.
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("starts with retry, frames ready, hook and gap events", async () => {
    const up = new FakeUpstream();
    const b = new SseBridge(up);
    const t = tap(b);
    b.onUpstreamMessage(JSON.stringify({ t: "ready", accountId: "acc_x", deviceId: "dev_x", after: 3, head: 9 }));
    b.onUpstreamMessage(JSON.stringify({ t: "gap", from: 4, to: 6, reason: "retention" }));
    b.onUpstreamMessage(hook(7));
    const { text } = await t.take();
    expect(text).toBe(
      "retry: 5000\n\n" +
        'event: ready\ndata: {"accountId":"acc_x","deviceId":"dev_x","after":3,"head":9}\n\n' +
        'id: 6\nevent: gap\ndata: {"from":4,"to":6,"reason":"retention"}\n\n' +
        `id: 7\nevent: hook\ndata: ${JSON.stringify({ seq: 7, body: "xxxxxxxxxx" })}\n\n`,
    );
    await t.cancel();
    expect(up.closed?.code).toBe(1000);
  });

  it("writes `: hb` every 15 s", async () => {
    const up = new FakeUpstream();
    const b = new SseBridge(up);
    const t = tap(b);
    await t.take();
    expect((await t.after(14_999)).text).toBe("");
    expect((await t.after(1)).text).toBe(": hb\n\n");
    expect((await t.after(30_000)).text).toBe(": hb\n\n: hb\n\n");
    await t.cancel();
  });

  it("pings the object every 30 s and closes with 1012 when it stops answering", async () => {
    const up = new FakeUpstream();
    const b = new SseBridge(up);
    const t = tap(b);
    await t.after(30_000);
    expect(up.sent).toEqual(["ping"]);
    b.onUpstreamMessage("pong");
    // The client keeps reading (heartbeats), so this isn't a stall.
    for (let i = 0; i < 12; i++) await t.after(5_000);
    expect(b.isFinished).toBe(false);
    let text = "";
    let done = false;
    for (let i = 0; i < 4 && !done; i++) ({ text, done } = await t.after(5_000));
    expect(text).toContain('event: closed\ndata: {"code":1012,"reason":"relay restarting"}\n\n');
    expect(done).toBe(true);
  });

  it("stops queueing past 256 KiB, then sends resync {after: last written} once drained, and ends", async () => {
    const up = new FakeUpstream();
    const b = new SseBridge(up);
    const t = tap(b);
    b.onUpstreamMessage(JSON.stringify({ t: "ready", after: 0, head: 0 }));
    // 30 events of ~10 KiB: about 300 KiB, more than the queue may hold.
    for (let seq = 1; seq <= 30; seq++) b.onUpstreamMessage(hook(seq, 10_000));
    expect(b.waitingBytes).toBeGreaterThan(256 * 1024);
    expect(b.waitingBytes).toBeLessThan(256 * 1024 + 11_000);
    const { text, done } = await t.take();
    const ids = [...text.matchAll(/^id: (\d+)$/gm)].map((m) => Number(m[1]));
    const last = ids[ids.length - 1]!;
    expect(ids).toEqual(Array.from({ length: last }, (_, i) => i + 1));
    expect(last).toBeLessThan(30);
    expect(text.endsWith(`event: resync\ndata: {"after":${last}}\n\n`)).toBe(true);
    expect(done).toBe(true);
    expect(up.closed?.code).toBe(1000);
  });

  it("closes a client that reads nothing for 60 s with 4408, dropping what was queued", async () => {
    const up = new FakeUpstream();
    const b = new SseBridge(up);
    // The client never reads: the retry line and the event wait in the queue.
    b.onUpstreamMessage(hook(1, 1000));
    // The client stops reading: nothing is taken from here on.
    await vi.advanceTimersByTimeAsync(55_000);
    expect(b.isFinished).toBe(false);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(b.isFinished).toBe(true);
    const { text, done } = await tap(b).take();
    expect(text).toBe('event: closed\ndata: {"code":4408,"reason":"too slow to read"}\n\n');
    expect(done).toBe(true);
    expect(up.closed?.code).toBe(1000);
  });

  it("a client waiting with nothing queued isn't stalled", async () => {
    const b = new SseBridge(new FakeUpstream());
    const t = tap(b);
    await t.take();
    // A read is pending (the client waits) for longer than the stall limit.
    await vi.advanceTimersByTimeAsync(70_000);
    expect(b.isFinished).toBe(false);
    expect((await t.take()).text).toContain(": hb\n\n");
    await t.cancel();
  });

  it("maps upstream closes: 4401 and 4409 pass through, anything else is 1012", async () => {
    for (const [code, expected] of [
      [4401, 4401],
      [4409, 4409],
      [1006, 1012],
      [1001, 1012],
    ] as const) {
      const b = new SseBridge(new FakeUpstream());
      const t = tap(b);
      b.onUpstreamMessage(hook(1));
      b.onUpstreamClose(code);
      const { text, done } = await t.take();
      // Events already queued still go out before the close.
      expect(text).toContain("id: 1\nevent: hook");
      expect(text).toContain(`event: closed\ndata: {"code":${expected},`);
      expect(done).toBe(true);
    }
  });

  it("asks the object for the next backlog page only once the client has drained", async () => {
    const up = new FakeUpstream();
    const b = new SseBridge(up);
    const t = tap(b);
    b.onUpstreamMessage(hook(1));
    b.onUpstreamMessage(JSON.stringify({ t: "more" }));
    expect(up.sent).toEqual([]);
    await t.take();
    expect(up.sent).toEqual(["next"]);
    await t.cancel();
  });
});
