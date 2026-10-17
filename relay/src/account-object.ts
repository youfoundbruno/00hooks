// One Durable Object per account: the ordered event log, per-device ack cursors, request nonces,
// the dedupe marks, and the device streams (hibernatable WebSockets bridged to SSE by the Worker).
//
// Nothing here keeps timers or in-memory state between calls, so the object hibernates whenever no
// event is moving: an always-on stream costs (almost) nothing while idle. The per-socket state lives
// in the socket's attachment.

import { DurableObject } from "cloudflare:workers";
import { newId, toBase64 } from "./encoding.ts";

/** Nonces are remembered this long (PROTOCOL §1: 600 s; the time window is ±300 s). */
export const NONCE_TTL_MS = 600_000;
/** Dedupe marks: providers that sign no timestamp retry for hours, so keep them a week. */
export const DEDUPE_TTL_MS = 7 * 24 * 3600_000;
/** A backlog page: the Worker asks for the next one once it has written this one out. */
export const PAGE_EVENTS = 64;
export const PAGE_BYTES = 128 * 1024;

export const CLOSE_REVOKED = 4401;
export const CLOSE_REPLACED = 4409;
/** A send to a stream failed for a reason other than size: the client reconnects and resumes. */
export const CLOSE_SEND_FAILED = 1011;

/**
 * The largest WebSocket message Cloudflare carries: 32 MiB since 2025-10 (it was 1 MiB). The largest
 * event the relay accepts (a 1,835,008-byte body, base64-expanded to 2,446,680 characters, plus at
 * most a few KiB of headers and metadata) is well under it; this guard is for what can't happen.
 */
export const MAX_FRAME_BYTES = 32 * 1024 * 1024;

/** Per-account storage quota defaults (PROTOCOL §4): `ACCOUNT_MAX_EVENTS`, `ACCOUNT_MAX_BYTES`. */
export const DEFAULT_MAX_EVENTS = 10_000;
export const DEFAULT_MAX_BYTES = 256 * 1024 * 1024;

export interface Quota {
  events: number;
  bytes: number;
}

export interface AppendInput {
  hookId: string;
  /** Replay marks: a duplicate when any was seen; all are written with the event. */
  dedupeKeys: string[];
  verified: boolean;
  preset: string;
  eventType: string | null;
  contentType: string | null;
  headers: Record<string, string>;
  body: Uint8Array;
  receivedAt: number;
}

export type AppendResult =
  | { duplicate: true }
  | { duplicate: false; full: true }
  | { duplicate: false; full: false; seq: number; id: string };

/** The per-socket state, kept in the WebSocket's attachment so it survives hibernation. */
interface Attachment {
  deviceId: string;
  /** The last seq this stream has been sent (or skipped past as a gap). */
  cursor: number;
  /** True while the backlog is being paged out; live events wait for the pages. */
  catchingUp: boolean;
}

interface EventRow extends Record<string, SqlStorageValue> {
  seq: number;
  id: string;
  hook_id: string;
  received_at: number;
  verified: number;
  preset: string;
  event_type: string | null;
  content_type: string | null;
  headers: string;
  body: ArrayBuffer;
}

/**
 * Messages to the Worker. Hook events are `h<seq>\n<event json>` so the Worker can frame them
 * without re-parsing the body; everything else is a JSON object with a `t` field.
 */
export function hookFrame(seq: number, eventJson: string): string {
  return `h${seq}\n${eventJson}`;
}

export class AccountObject extends DurableObject<Env> {
  private readonly sql: SqlStorage;
  /** Tests lower these to exercise the guards; production uses the constants and the env. */
  frameLimit = MAX_FRAME_BYTES;
  quotaOverride: Quota | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    for (const stmt of SCHEMA) this.sql.exec(stmt);
    // Liveness pings from the Worker are answered without waking the object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  // ── bookkeeping ────────────────────────────────────────────────────────────

  private head(): number {
    const row = this.sql.exec<{ value: number }>("SELECT value FROM meta WHERE key = 'head'").toArray()[0];
    return row?.value ?? 0;
  }

  private quota(): Quota {
    if (this.quotaOverride) return this.quotaOverride;
    const n = (v: string | undefined, d: number) => {
      const x = Number(v);
      return Number.isFinite(x) && x > 0 ? x : d;
    };
    return { events: n(this.env.ACCOUNT_MAX_EVENTS, DEFAULT_MAX_EVENTS), bytes: n(this.env.ACCOUNT_MAX_BYTES, DEFAULT_MAX_BYTES) };
  }

  /**
   * What the log holds: events and bytes (body plus headers), kept as counters in `meta` so an
   * append doesn't scan the log. An object from before the counters existed counts once.
   */
  private usage(): Quota {
    const rows = this.sql
      .exec<{ key: string; value: number }>("SELECT key, value FROM meta WHERE key IN ('log_events', 'log_bytes')")
      .toArray();
    if (rows.length === 2) {
      const get = (k: string) => rows.find((r) => r.key === k)!.value;
      return { events: get("log_events"), bytes: get("log_bytes") };
    }
    const r = this.sql
      .exec<{ n: number; b: number | null }>("SELECT count(*) AS n, sum(length(body) + length(headers)) AS b FROM events")
      .one();
    const u = { events: r.n, bytes: r.b ?? 0 };
    this.setUsage(u);
    return u;
  }

  private setUsage(u: Quota): void {
    const up = "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value";
    this.sql.exec(up, "log_events", Math.max(0, u.events));
    this.sql.exec(up, "log_bytes", Math.max(0, u.bytes));
  }

  /** Deletes events up to `seq`, keeping the usage counters right. */
  private deleteThrough(seq: number): void {
    const gone = this.sql
      .exec<{ n: number; b: number | null }>(
        "SELECT count(*) AS n, sum(length(body) + length(headers)) AS b FROM events WHERE seq <= ?",
        seq,
      )
      .one();
    if (gone.n === 0) return;
    const u = this.usage();
    this.sql.exec("DELETE FROM events WHERE seq <= ?", seq);
    this.setUsage({ events: u.events - gone.n, bytes: u.bytes - (gone.b ?? 0) });
  }

  private retentionMs(): number {
    const days = Number(this.env.RETENTION_DAYS);
    return (Number.isFinite(days) && days > 0 ? Math.max(days, 1 / 24) : 7) * 24 * 3600_000;
  }

  /** Makes sure a device row exists; a new device starts at the head (it never saw older events). */
  private ensureDevice(deviceId: string): { acked: number; revoked: boolean } {
    this.sql.exec(
      "INSERT INTO devices (id, acked, revoked) VALUES (?, ?, 0) ON CONFLICT(id) DO NOTHING",
      deviceId,
      this.head(),
    );
    const row = this.sql
      .exec<{ acked: number; revoked: number }>("SELECT acked, revoked FROM devices WHERE id = ?", deviceId)
      .one();
    return { acked: row.acked, revoked: row.revoked === 1 };
  }

  // ── RPC from the Worker ────────────────────────────────────────────────────

  async addDevice(deviceId: string): Promise<void> {
    this.ensureDevice(deviceId);
  }

  /**
   * Spends a request nonce. False when the device is revoked or the nonce was already used: the
   * check and the write happen in this single-threaded object, so it's strongly consistent.
   */
  async spendNonce(deviceId: string, nonce: string): Promise<boolean> {
    const now = Date.now();
    const ok = this.ctx.storage.transactionSync(() => {
      if (this.ensureDevice(deviceId).revoked) return false;
      const fresh = this.sql
        .exec<{ n: number }>(
          "SELECT count(*) AS n FROM nonces WHERE device_id = ? AND nonce = ? AND at > ?",
          deviceId,
          nonce,
          now - NONCE_TTL_MS,
        )
        .one().n;
      if (fresh > 0) return false;
      this.sql.exec(
        "INSERT INTO nonces (device_id, nonce, at) VALUES (?, ?, ?) ON CONFLICT(device_id, nonce) DO UPDATE SET at = excluded.at",
        deviceId,
        nonce,
        now,
      );
      return true;
    });
    if (ok) await this.ensureAlarm();
    return ok;
  }

  /**
   * Appends one event, with its dedupe marks, in one transaction; then delivers it live. Refuses
   * (`full`) when the account's log is at its quota, until devices acknowledge what's waiting.
   */
  async append(input: AppendInput): Promise<AppendResult> {
    const headers = JSON.stringify(input.headers);
    const size = input.body.byteLength + headers.length;
    const result = this.ctx.storage.transactionSync((): AppendResult => {
      for (const key of input.dedupeKeys) {
        const seen = this.sql
          .exec<{ n: number }>("SELECT count(*) AS n FROM seen WHERE hook_id = ? AND key = ?", input.hookId, key)
          .one().n;
        if (seen > 0) return { duplicate: true };
      }
      const usage = this.usage();
      const quota = this.quota();
      if (usage.events + 1 > quota.events || usage.bytes + size > quota.bytes) return { duplicate: false, full: true };
      for (const key of new Set(input.dedupeKeys)) {
        this.sql.exec("INSERT INTO seen (hook_id, key, at) VALUES (?, ?, ?)", input.hookId, key, input.receivedAt);
      }
      const seq = this.head() + 1;
      this.sql.exec("INSERT INTO meta (key, value) VALUES ('head', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", seq);
      const id = newId("evt");
      this.sql.exec(
        `INSERT INTO events (seq, id, hook_id, received_at, verified, preset, event_type, content_type, headers, body)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        seq,
        id,
        input.hookId,
        input.receivedAt,
        input.verified ? 1 : 0,
        input.preset,
        input.eventType,
        input.contentType,
        headers,
        input.body,
      );
      this.setUsage({ events: usage.events + 1, bytes: usage.bytes + size });
      return { duplicate: false, full: false, seq, id };
    });
    if (!result.duplicate && !result.full) {
      this.deliverLive(result.seq);
      await this.ensureAlarm();
    }
    return result;
  }

  /** Counts a failed verification (counted, never stored: PROTOCOL §4). */
  async recordFailure(hookId: string): Promise<void> {
    const hour = Math.floor(Date.now() / 3600_000) * 3600_000;
    this.sql.exec(
      `INSERT INTO verify_failures (hook_id, hour, count) VALUES (?, ?, 1)
       ON CONFLICT(hook_id, hour) DO UPDATE SET count = count + 1`,
      hookId,
      hour,
    );
    await this.ensureAlarm();
  }

  /** Moves a device's ack cursor forward (never back, never past the head); returns it. */
  async ack(deviceId: string, through: number): Promise<number> {
    const head = this.head();
    const current = this.ensureDevice(deviceId).acked;
    const next = Math.max(current, Math.min(through, head));
    if (next !== current) {
      this.sql.exec("UPDATE devices SET acked = ? WHERE id = ?", next, deviceId);
      this.pruneAcknowledged();
      await this.ensureAlarm();
    }
    return next;
  }

  /** Revokes a device: its stream closes at once with 4401, and it no longer holds events back. */
  async revokeDevice(deviceId: string): Promise<void> {
    this.ensureDevice(deviceId);
    this.sql.exec("UPDATE devices SET revoked = 1 WHERE id = ?", deviceId);
    for (const ws of this.ctx.getWebSockets(deviceId)) {
      try {
        ws.close(CLOSE_REVOKED, "device revoked");
      } catch {
        // Already closing.
      }
    }
    this.pruneAcknowledged();
    await this.ensureAlarm();
  }

  // ── streams ────────────────────────────────────────────────────────────────

  /**
   * `GET /stream?account=…&device=…&lastEventId=…` with `Upgrade: websocket`, from the Worker only
   * (the Worker has already checked the request's signature and spent its nonce).
   */
  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade") !== "websocket") return new Response("expected a websocket", { status: 426 });
    const url = new URL(request.url);
    const accountId = url.searchParams.get("account") ?? "";
    const deviceId = url.searchParams.get("device") ?? "";
    const lastEventId = Number(url.searchParams.get("lastEventId") ?? "0");
    const device = this.ensureDevice(deviceId);
    if (device.revoked) return new Response("revoked", { status: 401 });

    // One stream per device: a newer one replaces the older (4409).
    for (const old of this.ctx.getWebSockets(deviceId)) {
      try {
        old.close(CLOSE_REPLACED, "replaced by a newer stream");
      } catch {
        // Already closing.
      }
    }

    const head = this.head();
    const after = Math.min(Math.max(lastEventId, device.acked), head);
    const pair = new WebSocketPair();
    const server = pair[1];
    this.ctx.acceptWebSocket(server, [deviceId]);
    const att: Attachment = { deviceId, cursor: after, catchingUp: true };
    if (this.trySend(server, JSON.stringify({ t: "ready", accountId, deviceId, after, head }))) this.sendPage(server, att);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (message !== "next") return;
    const att = ws.deserializeAttachment() as Attachment | null;
    if (att?.catchingUp) this.sendPage(ws, att);
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    try {
      ws.close(code === 1005 || code === 1006 ? 1000 : code, reason);
    } catch {
      // Already closed.
    }
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    try {
      ws.close(1011, "error");
    } catch {
      // Already closed.
    }
  }

  /**
   * Sends the next page of backlog after the socket's cursor, with `gap` events for ranges that
   * retention already dropped. When the backlog is done the socket goes live.
   */
  private sendPage(ws: WebSocket, att: Attachment): void {
    const rows = this.sql
      .exec<EventRow>("SELECT * FROM events WHERE seq > ? ORDER BY seq LIMIT ?", att.cursor, PAGE_EVENTS)
      .toArray();
    let bytes = 0;
    for (const row of rows) {
      if (row.seq > att.cursor + 1 && !this.sendGaps(ws, att, row.seq - 1)) return;
      const sent = this.sendHook(ws, att, row);
      if (sent === null) return;
      bytes += sent;
      if (bytes >= PAGE_BYTES) break;
    }
    const more =
      this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM (SELECT 1 FROM events WHERE seq > ? LIMIT 1)", att.cursor).one()
        .n > 0;
    if (!more) {
      const head = this.head();
      if (head > att.cursor && !this.sendGaps(ws, att, head)) return;
    }
    att.catchingUp = more;
    ws.serializeAttachment(att);
    if (more) this.trySend(ws, JSON.stringify({ t: "more" }));
  }

  /**
   * Sends one message; false when the socket can't take it. Such a socket is closed (the client
   * reconnects from its cursor) so one failing stream never throws into the others' delivery.
   */
  private trySend(ws: WebSocket, message: string): boolean {
    try {
      ws.send(message);
      return true;
    } catch {
      try {
        ws.close(CLOSE_SEND_FAILED, "send failed");
      } catch {
        // Already closing.
      }
      return false;
    }
  }

  /**
   * Sends one event and moves the cursor past it; returns the bytes sent, or null when the socket
   * failed. An event whose frame is over the WebSocket message limit can never be delivered, so it
   * is reported as a one-event `gap` (reason `too_large`) rather than wedging the stream on it.
   */
  private sendHook(ws: WebSocket, att: Attachment, row: EventRow): number | null {
    const frame = hookFrame(row.seq, eventJson(row));
    if (overLimit(frame, this.frameLimit)) {
      if (!this.trySend(ws, JSON.stringify({ t: "gap", from: row.seq, to: row.seq, reason: "too_large" }))) return null;
      att.cursor = row.seq;
      return 0;
    }
    if (!this.trySend(ws, frame)) return null;
    att.cursor = row.seq;
    return frame.length;
  }

  /**
   * Reports recorded pruned ranges within (cursor, through], and moves the cursor to `through`.
   * False when the socket failed.
   */
  private sendGaps(ws: WebSocket, att: Attachment, through: number): boolean {
    const ranges = this.sql
      .exec<{ from_seq: number; to_seq: number; reason: string }>(
        "SELECT from_seq, to_seq, reason FROM pruned WHERE to_seq > ? AND from_seq <= ? ORDER BY from_seq",
        att.cursor,
        through,
      )
      .toArray();
    for (const r of ranges) {
      const from = Math.max(r.from_seq, att.cursor + 1);
      const to = Math.min(r.to_seq, through);
      if (!this.trySend(ws, JSON.stringify({ t: "gap", from, to, reason: r.reason }))) return false;
    }
    att.cursor = through;
    return true;
  }

  /** Sends a just-appended event to every stream that is live (not still paging its backlog). */
  private deliverLive(seq: number): void {
    const sockets = this.ctx.getWebSockets();
    if (sockets.length === 0) return;
    const row = this.sql.exec<EventRow>("SELECT * FROM events WHERE seq = ?", seq).one();
    for (const ws of sockets) {
      const att = ws.deserializeAttachment() as Attachment | null;
      if (!att || att.catchingUp || att.cursor >= seq) continue;
      // A failed socket is closed by sendHook and resumes from its cursor on reconnect.
      if (this.sendHook(ws, att, row) !== null) ws.serializeAttachment(att);
    }
  }

  // ── pruning ────────────────────────────────────────────────────────────────

  /** Deletes events every active device has acknowledged, and gap records nobody can need. */
  private pruneAcknowledged(): void {
    const row = this.sql
      .exec<{ m: number | null; n: number }>("SELECT min(acked) AS m, count(*) AS n FROM devices WHERE revoked = 0")
      .one();
    if (row.n === 0 || row.m === null) return;
    this.deleteThrough(row.m);
    this.sql.exec("DELETE FROM pruned WHERE to_seq <= ?", row.m);
  }

  /** Drops events past retention, recording the range so a resume reports a `gap`. */
  private pruneRetention(now: number): void {
    const cutoff = now - this.retentionMs();
    const r = this.sql
      .exec<{ lo: number | null; hi: number | null }>("SELECT min(seq) AS lo, max(seq) AS hi FROM events WHERE received_at < ?", cutoff)
      .one();
    if (r.lo === null || r.hi === null) return;
    this.ctx.storage.transactionSync(() => {
      const last = this.sql
        .exec<{ rowid: number; to_seq: number; reason: string }>(
          "SELECT rowid, to_seq, reason FROM pruned ORDER BY to_seq DESC LIMIT 1",
        )
        .toArray()[0];
      if (last && last.reason === "retention" && last.to_seq + 1 >= r.lo!) {
        this.sql.exec("UPDATE pruned SET to_seq = max(to_seq, ?) WHERE rowid = ?", r.hi, last.rowid);
      } else {
        this.sql.exec("INSERT INTO pruned (from_seq, to_seq, reason) VALUES (?, ?, 'retention')", r.lo, r.hi);
      }
      this.deleteThrough(r.hi!);
    });
  }

  override async alarm(): Promise<void> {
    const now = Date.now();
    this.pruneAcknowledged();
    this.pruneRetention(now);
    this.sql.exec("DELETE FROM nonces WHERE at <= ?", now - NONCE_TTL_MS);
    this.sql.exec("DELETE FROM seen WHERE at <= ?", now - DEDUPE_TTL_MS);
    this.sql.exec("DELETE FROM verify_failures WHERE hour <= ?", now - this.retentionMs());
    await this.ensureAlarm(true);
  }

  /**
   * Schedules the alarm for the next time something expires, or clears it when nothing will.
   * An account with nothing pending has no alarm, so idle accounts never wake.
   */
  private async ensureAlarm(fromAlarm = false): Promise<void> {
    const q = (sql: string) => this.sql.exec<{ t: number | null }>(sql).one().t;
    const due = [
      q("SELECT min(at) AS t FROM nonces"),
      q("SELECT min(received_at) AS t FROM events"),
      q("SELECT min(at) AS t FROM seen"),
      q("SELECT min(hour) AS t FROM verify_failures"),
    ];
    const ttl = [NONCE_TTL_MS, this.retentionMs(), DEDUPE_TTL_MS, this.retentionMs()];
    let next = Infinity;
    due.forEach((t, i) => {
      if (t !== null) next = Math.min(next, t + ttl[i]! + 1);
    });
    const current = await this.ctx.storage.getAlarm();
    if (next === Infinity) {
      if (current !== null && !fromAlarm) await this.ctx.storage.deleteAlarm();
      return;
    }
    // Never sooner than a minute from now: expiry can wait, and wakes cost money.
    next = Math.max(next, Date.now() + 60_000);
    if (fromAlarm || current === null || current > next) await this.ctx.storage.setAlarm(next);
  }

  // ── test and diagnostics helpers (not routed) ───────────────────────────────

  async stats(): Promise<{
    head: number;
    events: number;
    usage: Quota;
    devices: { id: string; acked: number; revoked: boolean }[];
  }> {
    return {
      head: this.head(),
      events: this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM events").one().n,
      usage: this.usage(),
      devices: this.sql
        .exec<{ id: string; acked: number; revoked: number }>("SELECT id, acked, revoked FROM devices ORDER BY id")
        .toArray()
        .map((d) => ({ id: d.id, acked: d.acked, revoked: d.revoked === 1 })),
    };
  }
}

/** Whether a message is over `limit` bytes of UTF-8 (encoding it only when it might be). */
function overLimit(s: string, limit: number): boolean {
  return s.length * 3 > limit && new TextEncoder().encode(s).byteLength > limit;
}

function eventJson(row: EventRow): string {
  return JSON.stringify({
    seq: row.seq,
    id: row.id,
    hookId: row.hook_id,
    receivedAt: row.received_at,
    verified: row.verified === 1,
    preset: row.preset,
    eventType: row.event_type,
    contentType: row.content_type,
    headers: JSON.parse(row.headers) as Record<string, string>,
    body: toBase64(new Uint8Array(row.body)),
  });
}

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)",
  `CREATE TABLE IF NOT EXISTS events (
     seq INTEGER PRIMARY KEY, id TEXT NOT NULL, hook_id TEXT NOT NULL, received_at INTEGER NOT NULL,
     verified INTEGER NOT NULL, preset TEXT NOT NULL, event_type TEXT, content_type TEXT,
     headers TEXT NOT NULL, body BLOB NOT NULL)`,
  "CREATE INDEX IF NOT EXISTS events_received ON events(received_at)",
  "CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, acked INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)",
  `CREATE TABLE IF NOT EXISTS nonces (device_id TEXT NOT NULL, nonce TEXT NOT NULL, at INTEGER NOT NULL,
     PRIMARY KEY (device_id, nonce)) WITHOUT ROWID`,
  "CREATE INDEX IF NOT EXISTS nonces_at ON nonces(at)",
  `CREATE TABLE IF NOT EXISTS seen (hook_id TEXT NOT NULL, key TEXT NOT NULL, at INTEGER NOT NULL,
     PRIMARY KEY (hook_id, key)) WITHOUT ROWID`,
  "CREATE INDEX IF NOT EXISTS seen_at ON seen(at)",
  "CREATE TABLE IF NOT EXISTS pruned (from_seq INTEGER NOT NULL, to_seq INTEGER NOT NULL, reason TEXT NOT NULL)",
  `CREATE TABLE IF NOT EXISTS verify_failures (hook_id TEXT NOT NULL, hour INTEGER NOT NULL, count INTEGER NOT NULL,
     PRIMARY KEY (hook_id, hour)) WITHOUT ROWID`,
];
