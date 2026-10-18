// The SSE bridge (PROTOCOL §6). The Worker holds the client's SSE response and talks to the account's
// Durable Object over a hibernatable WebSocket, so the object costs nothing while the stream idles.
// This class turns the object's messages into SSE, writes heartbeats, applies the backpressure rule,
// and closes with the protocol's codes.

const encoder = new TextEncoder();

export const RETRY_MS = 5000;
export const HEARTBEAT_MS = 15_000;
/** More than this many bytes waiting to be written stops the queueing (then `resync`). */
export const MAX_QUEUED_BYTES = 256 * 1024;
/** A client that reads nothing for this long, with data waiting, is closed with 4408. */
export const STALL_MS = 60_000;
/** Liveness pings to the object (answered by its auto-response, without waking it). */
export const PING_MS = 30_000;
/** No pong for this long means the object went away (a deploy): close with 1012. */
export const PONG_TIMEOUT_MS = 75_000;

export const CLOSE_REVOKED = 4401;
export const CLOSE_TOO_SLOW = 4408;
export const CLOSE_REPLACED = 4409;
export const CLOSE_RESTARTING = 1012;

const CLOSE_REASONS: Record<number, string> = {
  [CLOSE_REVOKED]: "device revoked",
  [CLOSE_TOO_SLOW]: "too slow to read",
  [CLOSE_REPLACED]: "replaced by a newer stream",
  [CLOSE_RESTARTING]: "relay restarting",
};

/** The upstream side: the WebSocket to the account's Durable Object. */
export interface Upstream {
  send(message: string): void;
  close(code: number, reason: string): void;
}

export interface BridgeOptions {
  heartbeatMs?: number;
  maxQueuedBytes?: number;
  stallMs?: number;
  pingMs?: number;
  pongTimeoutMs?: number;
}

export class SseBridge {
  readonly readable: ReadableStream<Uint8Array>;

  private readonly queue: Uint8Array[] = [];
  private queuedBytes = 0;
  /** Set when the queue passed the limit: nothing more is queued until a resync. */
  private overflowed = false;
  /** The seq of the last `hook` (or the end of the last `gap`) actually queued. */
  private lastWritten = 0;
  /** The object has more backlog and waits for `next`. */
  private awaitingMore = false;
  private finished = false;
  private wake: (() => void) | null = null;
  private lastReadAt = Date.now();
  private lastPongAt = Date.now();
  private readonly timers: ReturnType<typeof setInterval>[] = [];
  private readonly opts: Required<BridgeOptions>;

  private readonly upstream: Upstream;

  constructor(upstream: Upstream, opts: BridgeOptions = {}) {
    this.upstream = upstream;
    this.opts = {
      heartbeatMs: opts.heartbeatMs ?? HEARTBEAT_MS,
      maxQueuedBytes: opts.maxQueuedBytes ?? MAX_QUEUED_BYTES,
      stallMs: opts.stallMs ?? STALL_MS,
      pingMs: opts.pingMs ?? PING_MS,
      pongTimeoutMs: opts.pongTimeoutMs ?? PONG_TIMEOUT_MS,
    };
    this.readable = new ReadableStream<Uint8Array>(
      {
        pull: (controller) => this.pull(controller),
        cancel: () => this.stop(1000, "client went away"),
      },
      // No internal buffering: the queue above is the only one, so its size is what's waiting.
      { highWaterMark: 0 },
    );
    this.push(`retry: ${RETRY_MS}\n\n`);
    this.timers.push(setInterval(() => this.tick(), Math.min(this.opts.heartbeatMs, 5000)));
    this.timers.push(setInterval(() => this.heartbeat(), this.opts.heartbeatMs));
    this.timers.push(setInterval(() => this.ping(), this.opts.pingMs));
  }

  /** Bytes queued and not yet taken by the client. */
  get waitingBytes(): number {
    return this.queuedBytes;
  }

  get isFinished(): boolean {
    return this.finished;
  }

  // ── from the Durable Object ────────────────────────────────────────────────

  onUpstreamMessage(data: string): void {
    if (this.finished) return;
    if (data === "pong") {
      this.lastPongAt = Date.now();
      return;
    }
    this.lastPongAt = Date.now();
    if (data.startsWith("h")) {
      const nl = data.indexOf("\n");
      const seq = Number(data.slice(1, nl));
      this.pushEvent(`id: ${seq}\nevent: hook\ndata: ${data.slice(nl + 1)}\n\n`, seq);
      return;
    }
    let msg: { t?: string; [k: string]: unknown };
    try {
      msg = JSON.parse(data) as typeof msg;
    } catch {
      return;
    }
    switch (msg.t) {
      case "ready": {
        const { t: _t, ...ready } = msg;
        this.lastWritten = Number(ready.after) || 0;
        this.push(`event: ready\ndata: ${JSON.stringify(ready)}\n\n`);
        break;
      }
      case "gap": {
        const gap = { from: msg.from, to: msg.to, reason: msg.reason };
        this.pushEvent(`id: ${gap.to}\nevent: gap\ndata: ${JSON.stringify(gap)}\n\n`, Number(gap.to));
        break;
      }
      case "change": {
        // A hook change (PROTOCOL §6): no `id`, so it never moves the client's Last-Event-ID. Left
        // out while the queue overflows, like events (the stream ends with a resync anyway).
        if (this.overflowed) break;
        const { t: _t, ...change } = msg;
        this.push(`event: hook-change\ndata: ${JSON.stringify(change)}\n\n`);
        break;
      }
      case "more":
        this.awaitingMore = true;
        if (this.queue.length === 0) this.drained();
        break;
    }
  }

  onUpstreamClose(code: number): void {
    if (this.finished) return;
    const known = code === CLOSE_REVOKED || code === CLOSE_REPLACED;
    this.finish(known ? code : CLOSE_RESTARTING, { keepQueue: true });
  }

  // ── to the client ──────────────────────────────────────────────────────────

  private async pull(controller: ReadableStreamDefaultController<Uint8Array>): Promise<void> {
    this.lastReadAt = Date.now();
    if (this.queue.length === 0) {
      if (this.finished) {
        controller.close();
        return;
      }
      this.drained();
      if (this.queue.length === 0 && !this.finished) {
        await new Promise<void>((resolve) => (this.wake = resolve));
        this.lastReadAt = Date.now();
      }
    }
    const chunk = this.queue.shift();
    if (chunk) {
      this.queuedBytes -= chunk.byteLength;
      controller.enqueue(chunk);
    } else if (this.finished) {
      controller.close();
    }
  }

  /** The client has taken everything queued. */
  private drained(): void {
    if (this.finished) return;
    if (this.overflowed) {
      // PROTOCOL §6: once drained, say where to resume; the client reconnects from there.
      this.push(`event: resync\ndata: ${JSON.stringify({ after: this.lastWritten })}\n\n`);
      this.finish(null);
      return;
    }
    if (this.awaitingMore) {
      this.awaitingMore = false;
      this.send("next");
    }
  }

  private push(text: string): void {
    const bytes = encoder.encode(text);
    this.queue.push(bytes);
    this.queuedBytes += bytes.byteLength;
    const wake = this.wake;
    this.wake = null;
    wake?.();
  }

  private pushEvent(text: string, seq: number): void {
    if (this.overflowed) return;
    if (this.queuedBytes > this.opts.maxQueuedBytes) {
      this.overflowed = true;
      return;
    }
    this.push(text);
    this.lastWritten = seq;
  }

  private heartbeat(): void {
    if (!this.finished && !this.overflowed) this.push(": hb\n\n");
  }

  private tick(): void {
    if (this.finished) return;
    const now = Date.now();
    if (this.queue.length > 0 && this.wake === null && now - this.lastReadAt >= this.opts.stallMs) {
      this.finish(CLOSE_TOO_SLOW, { keepQueue: false });
    } else if (now - this.lastPongAt >= this.opts.pongTimeoutMs) {
      this.finish(CLOSE_RESTARTING, { keepQueue: true });
    }
  }

  private ping(): void {
    if (!this.finished) this.send("ping");
  }

  private send(message: string): void {
    try {
      this.upstream.send(message);
    } catch {
      this.finish(CLOSE_RESTARTING, { keepQueue: true });
    }
  }

  /**
   * Ends the stream: an `event: closed` (unless `code` is null, as after a resync), then the end of
   * the response. A stalled client's queue is dropped; otherwise what's queued still goes first.
   */
  private finish(code: number | null, o: { keepQueue: boolean } = { keepQueue: true }): void {
    if (this.finished) return;
    if (!o.keepQueue) {
      this.queue.length = 0;
      this.queuedBytes = 0;
    }
    if (code !== null) {
      this.push(`event: closed\ndata: ${JSON.stringify({ code, reason: CLOSE_REASONS[code] ?? "closed" })}\n\n`);
    }
    this.finished = true;
    this.stop(1000, "stream ended");
    const wake = this.wake;
    this.wake = null;
    wake?.();
  }

  private stop(code: number, reason: string): void {
    this.finished = true;
    for (const t of this.timers) clearInterval(t);
    this.timers.length = 0;
    try {
      this.upstream.close(code, reason);
    } catch {
      // Already closed.
    }
  }
}
