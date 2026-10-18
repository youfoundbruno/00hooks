// One Durable Object per account for the phone links (PROTOCOL §10): the mailbox of sealed envelopes
// between a node and its phones, each device's ack cursor, the phones the account has (so a socket's
// sends are checked without D1), the phones' request nonces, and one hibernatable WebSocket per
// device.
//
// It is a separate class from AccountObject so these sockets never mix with the webhook stream
// sockets (AccountObject walks `getWebSockets()` for offline notices and event delivery), and so a
// phone never becomes a device of the webhook log.
//
// The relay never opens, verifies or logs what it routes. An envelope is checked for its shape and
// its routing (`from`, `to`, sizes, rates, queues) and stored as the JSON text it arrived as; logs
// carry sizes and ids only. As in AccountObject, nothing is kept in memory between calls: per-socket
// state is the socket's attachment and per-device state (the token bucket, the cursor, the gap
// record, the queue counters) is in SQLite, so the object hibernates while nothing moves.

import { DurableObject } from "cloudflare:workers";
import { isId } from "./encoding.ts";
import { PUSH_CATEGORIES, pushHook, type PushCategory } from "./phone-push.ts";

/** The phone protocol this relay speaks (`/v1/info`'s `phone.protocol`). */
export const PHONE_PROTOCOL = 1;

export const CLOSE_PROTOCOL = 4400;
export const CLOSE_REVOKED = 4401;
export const CLOSE_REPLACED = 4409;
/** A `hello` found the device's token bucket empty: reconnect with backoff. */
export const CLOSE_RATE_LIMITED = 4429;

/** Request nonces are remembered this long (PROTOCOL §1). */
export const NONCE_TTL_MS = 600_000;
/** A socket counts as online while it has shown life this recently (opened, a frame, or a ping). */
export const ONLINE_MS = 90_000;

/** The largest frame a phone may send, and a node. */
export const PHONE_FRAME_MAX = 64 * 1024;
export const NODE_FRAME_MAX = 512 * 1024;

/** Token buckets, one per device, spent by every frame: capacity, and tokens added per second. */
export const PHONE_BUCKET = { capacity: 30, refill: 1 };
export const NODE_BUCKET = { capacity: 200, refill: 20 };

/** Queue defaults: `PHONE_NODE_QUEUE_MAX`, `PHONE_PHONE_QUEUE_MAX`, `PHONE_QUEUE_MAX_BYTES`. */
export const DEFAULT_NODE_QUEUE_ROWS = 1000;
export const DEFAULT_PHONE_QUEUE_ROWS = 500;
export const DEFAULT_QUEUE_BYTES = 16 * 1024 * 1024;

export interface QueueLimits {
  /** Rows waiting for a node: past it, a phone's send is refused `queue_full`. */
  nodeRows: number;
  /** Rows waiting for a phone: past it, the oldest are dropped (the phone sees a `gap`). */
  phoneRows: number;
  /** Bytes waiting for one device, either way. */
  bytes: number;
}

export type Role = "node" | "phone";

/** The per-socket state, in the WebSocket's attachment so it survives hibernation. */
interface Attachment {
  deviceId: string;
  role: Role;
  /** A phone's node; null for a node. */
  peer: string | null;
  openedAt: number;
  /** When `hello` arrived; null until then (nothing is sent to the socket before it). */
  helloAt: number | null;
  /** The last frame received: a sign of life besides the auto-answered ping. */
  lastFrameAt: number;
}

interface PhoneRow extends Record<string, SqlStorageValue> {
  id: string;
  peer: string;
  pending_until: number | null;
  revoked: number;
}

interface MailRow extends Record<string, SqlStorageValue> {
  seq: number;
  kind: string;
  body: string;
}

export interface PresenceInfo {
  device: string;
  online: boolean;
  /** When it came online, or when it was last seen leaving; null when never seen. */
  since: number | null;
}

/** What the relay tells a node about a phone (`sys` frames): never content. */
export type SysMessage =
  | {
      kind: "pair";
      pairingId: string;
      device: string;
      name: string;
      publicKey: string;
      sealKey: string;
      hello: { enc: string; ct: string };
      at: number;
    }
  | { kind: "unpaired"; device: string; at: number };

const B64URL_22 = /^[A-Za-z0-9_-]{22}$/;
const B64URL_43 = /^[A-Za-z0-9_-]{43}$/;
const B64URL_86 = /^[A-Za-z0-9_-]{86}$/;
const ENVELOPE_KEYS = new Set(["v", "id", "from", "to", "at", "kid", "enc", "ct", "sig", "push"]);

/** Standard base64 with padding, as `ct` is written. */
export function isStandardBase64(s: unknown): s is string {
  return typeof s === "string" && s.length > 0 && s.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(s);
}

/**
 * Checks an envelope's shape (PROTOCOL §10.6) without reading what is sealed in it. Unknown fields
 * are refused, so the relay stores nothing but the envelope.
 */
export function envelopeShapeOk(env: unknown): env is {
  v: 1;
  id: string;
  from: string;
  to: string;
  at: number;
  kid: string;
  enc: string;
  ct: string;
  sig: string;
  push?: PushCategory;
} {
  if (typeof env !== "object" || env === null || Array.isArray(env)) return false;
  const e = env as Record<string, unknown>;
  for (const k of Object.keys(e)) if (!ENVELOPE_KEYS.has(k)) return false;
  return (
    e.v === 1 &&
    typeof e.id === "string" &&
    B64URL_22.test(e.id) &&
    isId("dev", e.from) &&
    isId("dev", e.to) &&
    typeof e.at === "number" &&
    Number.isSafeInteger(e.at) &&
    e.at >= 0 &&
    typeof e.kid === "string" &&
    B64URL_22.test(e.kid) &&
    typeof e.enc === "string" &&
    B64URL_43.test(e.enc) &&
    isStandardBase64(e.ct) &&
    typeof e.sig === "string" &&
    B64URL_86.test(e.sig) &&
    (e.push === undefined || (typeof e.push === "string" && (PUSH_CATEGORIES as readonly string[]).includes(e.push)))
  );
}

/** UTF-8 length of a string. */
function byteLength(s: string): number {
  return new TextEncoder().encode(s).byteLength;
}

/** Whether a string is over `limit` bytes of UTF-8 (encoding it only when it might be). */
function overLimit(s: string, limit: number): boolean {
  return s.length > limit || (s.length * 3 > limit && byteLength(s) > limit);
}

function positiveNumber(v: string | undefined, fallback: number): number {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

export class PhoneObject extends DurableObject<Env> {
  private readonly sql: SqlStorage;
  /** Tests lower the queue limits through this; production uses the env and the defaults. */
  limitsOverride: Partial<QueueLimits> | null = null;
  /** The push hook (PROTOCOL §10.7); tests replace it to see that it is called. */
  push: (env: Env, deviceId: string, category: PushCategory) => Promise<void> = pushHook;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    for (const stmt of SCHEMA) this.sql.exec(stmt);
    this.migrate();
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  /**
   * Brings an object written by an older relay up to `SCHEMA_VERSION`, once: the queue counters are
   * built from the mailbox, the old gap records (several per device, dated) become one per device,
   * and the resend index gains the recipient.
   */
  private migrate(): void {
    const version = this.sql.exec<{ value: number }>("SELECT value FROM meta WHERE key = 'schema'").toArray()[0]?.value ?? 1;
    if (version >= SCHEMA_VERSION) return;
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM queue_stats");
      this.sql.exec(
        `INSERT INTO queue_stats (recipient, queued_rows, queued_bytes)
         SELECT recipient, count(*), sum(size) FROM mailbox GROUP BY recipient`,
      );
      const oldGaps = this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM sqlite_master WHERE type = 'table' AND name = 'gaps'").one().n > 0;
      if (oldGaps) {
        this.sql.exec(
          `INSERT INTO device_gaps (recipient, from_seq, to_seq)
           SELECT recipient, min(from_seq), max(to_seq) FROM gaps GROUP BY recipient`,
        );
        this.sql.exec("DROP TABLE gaps");
      }
      this.sql.exec("DROP INDEX IF EXISTS mailbox_sender_id");
      this.sql.exec(
        "INSERT INTO meta (key, value) VALUES ('schema', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        SCHEMA_VERSION,
      );
    });
  }

  // ── bookkeeping ────────────────────────────────────────────────────────────

  private limits(): QueueLimits {
    return {
      nodeRows: this.limitsOverride?.nodeRows ?? positiveNumber(this.env.PHONE_NODE_QUEUE_MAX, DEFAULT_NODE_QUEUE_ROWS),
      phoneRows: this.limitsOverride?.phoneRows ?? positiveNumber(this.env.PHONE_PHONE_QUEUE_MAX, DEFAULT_PHONE_QUEUE_ROWS),
      bytes: this.limitsOverride?.bytes ?? positiveNumber(this.env.PHONE_QUEUE_MAX_BYTES, DEFAULT_QUEUE_BYTES),
    };
  }

  private retentionMs(): number {
    const days = Number(this.env.RETENTION_DAYS);
    return (Number.isFinite(days) && days > 0 ? Math.max(days, 1 / 24) : 7) * 24 * 3600_000;
  }

  /** The newest seq ever given (seqs are never reused). */
  private head(): number {
    return this.sql.exec<{ value: number }>("SELECT value FROM meta WHERE key = 'head'").toArray()[0]?.value ?? 0;
  }

  private phone(id: string): PhoneRow | null {
    return this.sql.exec<PhoneRow>("SELECT id, peer, pending_until, revoked FROM phones WHERE id = ?", id).toArray()[0] ?? null;
  }

  /**
   * A phone that may still use the relay: known, not revoked, not a pending one whose time ran out,
   * and paired with a node that isn't revoked.
   */
  private phoneLive(row: PhoneRow | null, now: number): row is PhoneRow {
    return row !== null && row.revoked === 0 && (row.pending_until === null || row.pending_until > now) && !this.nodeRevoked(row.peer);
  }

  /** Whether a node was revoked here (`revokeNode`): its sockets and its phones are refused for good. */
  private nodeRevoked(id: string): boolean {
    return this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM revoked_nodes WHERE id = ?", id).one().n > 0;
  }

  /** Rows and bytes waiting for a device, from the counters the mailbox triggers keep. */
  private queued(recipient: string): { rows: number; bytes: number } {
    const r = this.sql
      .exec<{ rows: number; bytes: number }>("SELECT queued_rows AS rows, queued_bytes AS bytes FROM queue_stats WHERE recipient = ?", recipient)
      .toArray()[0];
    return r ?? { rows: 0, bytes: 0 };
  }

  /**
   * Spends one token of a device's bucket. The bucket is kept per device in storage, not per
   * socket, so a reconnect doesn't refill it. Returns null when a token was spent, or else the
   * seconds until one will be.
   */
  private spendToken(device: string, role: Role, now: number): number | null {
    const bucket = role === "phone" ? PHONE_BUCKET : NODE_BUCKET;
    const row = this.sql.exec<{ tokens: number; at: number }>("SELECT tokens, at FROM buckets WHERE device = ?", device).toArray()[0];
    let tokens = row ? Math.min(bucket.capacity, row.tokens + (Math.max(0, now - row.at) / 1000) * bucket.refill) : bucket.capacity;
    const ok = tokens >= 1;
    if (ok) tokens -= 1;
    this.sql.exec(
      "INSERT INTO buckets (device, tokens, at) VALUES (?, ?, ?) ON CONFLICT(device) DO UPDATE SET tokens = excluded.tokens, at = excluded.at",
      device,
      tokens,
      Math.max(now, row?.at ?? 0),
    );
    return ok ? null : Math.max(1, Math.ceil((1 - tokens) / bucket.refill));
  }

  private acked(device: string): number {
    return this.sql.exec<{ acked: number }>("SELECT acked FROM cursors WHERE device = ?", device).toArray()[0]?.acked ?? 0;
  }

  /**
   * Moves a device's cursor forward (never back, never past the newest seq) and deletes what it
   * has acknowledged: its rows and the gap records before them. Returns the cursor.
   */
  private advance(device: string, through: number): number {
    const current = this.acked(device);
    const next = Math.max(current, Math.min(through, this.head()));
    if (next !== current) {
      this.sql.exec(
        "INSERT INTO cursors (device, acked) VALUES (?, ?) ON CONFLICT(device) DO UPDATE SET acked = excluded.acked",
        device,
        next,
      );
    }
    this.sql.exec("DELETE FROM mailbox WHERE recipient = ? AND seq <= ?", device, next);
    this.sql.exec("DELETE FROM device_gaps WHERE recipient = ? AND to_seq <= ?", device, next);
    return next;
  }

  /** Appends one row for `recipient`; returns its seq. */
  private store(recipient: string, sender: string | null, kind: "msg" | "sys", msgId: string | null, body: string, now: number): number {
    const seq = this.sql
      .exec<{ seq: number }>(
        "INSERT INTO mailbox (recipient, sender, kind, msg_id, body, size, at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING seq",
        recipient,
        sender,
        kind,
        msgId,
        body,
        byteLength(body),
        now,
      )
      .one().seq;
    this.sql.exec(
      "INSERT INTO meta (key, value) VALUES ('head', ?) ON CONFLICT(key) DO UPDATE SET value = max(value, excluded.value)",
      seq,
    );
    return seq;
  }

  /** The frame a row is sent as: the stored text is spliced in as it is, never re-encoded. */
  private frame(row: MailRow): string {
    return row.kind === "sys" ? `{"t":"sys","seq":${row.seq},"sys":${row.body}}` : `{"t":"msg","seq":${row.seq},"env":${row.body}}`;
  }

  private attachment(ws: WebSocket): Attachment | null {
    return ws.deserializeAttachment() as Attachment | null;
  }

  /** Sockets of a device that said hello (only those are sent anything). */
  private ready(device: string): WebSocket[] {
    return this.ctx.getWebSockets(device).filter((ws) => ws.readyState === 1 && this.attachment(ws)?.helloAt != null);
  }

  private trySend(ws: WebSocket, message: string): void {
    try {
      ws.send(message);
    } catch {
      // The socket is going; the client resumes from its cursor.
    }
  }

  private closeAll(device: string, code: number, reason: string): void {
    for (const ws of this.ctx.getWebSockets(device)) {
      try {
        ws.close(code, reason);
      } catch {
        // Already closing.
      }
    }
  }

  /** Online: a socket is open, past hello, and has shown life in the last 90 s. */
  presenceOf(device: string, now = Date.now()): PresenceInfo {
    for (const ws of this.ctx.getWebSockets(device)) {
      const att = this.attachment(ws);
      if (!att || att.helloAt == null || ws.readyState !== 1) continue;
      const pong = this.ctx.getWebSocketAutoResponseTimestamp(ws)?.getTime() ?? 0;
      if (now - Math.max(att.openedAt, att.lastFrameAt, pong) < ONLINE_MS) return { device, online: true, since: att.helloAt };
    }
    const at = this.sql.exec<{ at: number }>("SELECT at FROM presence WHERE device = ?", device).toArray()[0]?.at ?? null;
    return { device, online: false, since: at };
  }

  /** A device's peers: a phone's node; a node's phones that aren't revoked (pending ones included). */
  private peersOf(device: string, role: Role, peer: string | null, now: number): string[] {
    if (role === "phone") return peer ? [peer] : [];
    return this.sql
      .exec<{ id: string }>(
        "SELECT id FROM phones WHERE peer = ? AND revoked = 0 AND (pending_until IS NULL OR pending_until > ?) ORDER BY id",
        device,
        now,
      )
      .toArray()
      .map((r) => r.id);
  }

  private announce(device: string, peers: string[], info: PresenceInfo): void {
    const frame = JSON.stringify({ t: "presence", device, online: info.online, since: info.since });
    for (const p of peers) for (const ws of this.ready(p)) this.trySend(ws, frame);
  }

  /** Queues a relay message for a node and sends it at once when the node is connected. */
  private queueSys(node: string, sys: SysMessage, now: number): number {
    const body = JSON.stringify(sys);
    const seq = this.store(node, null, "sys", null, body, now);
    const frame = this.frame({ seq, kind: "sys", body });
    for (const ws of this.ready(node)) this.trySend(ws, frame);
    return seq;
  }

  // ── RPC from the Worker ────────────────────────────────────────────────────

  /**
   * A phone redeemed a pairing (the Worker checked the proof and spent the pairing): the phone is
   * known here as pending, and its node is told with a `pair` sys message carrying the sealed hello.
   * Null, with nothing stored, when the node was revoked here.
   */
  async pair(input: { phone: string; node: string; pendingUntil: number; sys: SysMessage }): Promise<number | null> {
    const now = Date.now();
    if (this.nodeRevoked(input.node)) return null;
    const seq = this.ctx.storage.transactionSync(() => {
      this.sql.exec(
        "INSERT INTO phones (id, peer, pending_until, revoked, created_at) VALUES (?, ?, ?, 0, ?) ON CONFLICT(id) DO NOTHING",
        input.phone,
        input.node,
        input.pendingUntil,
        now,
      );
      return this.queueSys(input.node, input.sys, now);
    });
    await this.ensureAlarm();
    return seq;
  }

  /** The node confirmed its pending phone: it may send from now on. False when it isn't pending. */
  async confirm(phone: string, node: string): Promise<boolean> {
    const now = Date.now();
    const row = this.phone(phone);
    if (!this.phoneLive(row, now) || row.peer !== node) return false;
    if (row.pending_until === null) return true;
    this.sql.exec("UPDATE phones SET pending_until = NULL WHERE id = ?", phone);
    await this.ensureAlarm();
    return true;
  }

  /**
   * Revokes a phone, idempotently: its socket closes with 4401, its queued rows (both ways) and
   * nonces are deleted, and its node hears it go. With `notify`, the node is also sent an `unpaired`
   * sys message, once. Returns whether it was revoked just now.
   */
  async revokePhone(phone: string, node: string, notify: boolean): Promise<boolean> {
    const now = Date.now();
    const newly = this.revokePhoneNow(phone, node, notify, now);
    await this.ensureAlarm();
    return newly;
  }

  private revokePhoneNow(phone: string, node: string, notify: boolean, now: number): boolean {
    const row = this.phone(phone);
    const wasOnline = this.presenceOf(phone, now).online;
    const newly = row === null || row.revoked === 0;
    const peer = row?.peer ?? node;
    this.sql.exec(
      `INSERT INTO phones (id, peer, pending_until, revoked, created_at) VALUES (?, ?, NULL, 1, ?)
       ON CONFLICT(id) DO UPDATE SET revoked = 1`,
      phone,
      peer,
      now,
    );
    this.closeAll(phone, CLOSE_REVOKED, "device revoked");
    this.forgetDevice(phone);
    if (newly) {
      if (wasOnline) this.announce(phone, [peer], { device: phone, online: false, since: now });
      if (notify) this.queueSys(peer, { kind: "unpaired", device: phone, at: now }, now);
    }
    return newly;
  }

  /**
   * Deletes what a device has here: rows to it and from it, its gap record, queue counter, cursor,
   * token bucket and nonces.
   */
  private forgetDevice(device: string): void {
    this.sql.exec("DELETE FROM mailbox WHERE recipient = ? OR sender = ?", device, device);
    this.sql.exec("DELETE FROM queue_stats WHERE recipient = ?", device);
    this.sql.exec("DELETE FROM device_gaps WHERE recipient = ?", device);
    this.sql.exec("DELETE FROM cursors WHERE device = ?", device);
    this.sql.exec("DELETE FROM buckets WHERE device = ?", device);
    this.sql.exec("DELETE FROM nonces WHERE device_id = ?", device);
  }

  /**
   * A node was revoked: its phone socket closes with 4401, its mailbox goes, and so does every phone
   * paired with it (`phones` from D1, plus any this object knows). Returns the phones revoked now.
   */
  async revokeNode(node: string, phones: string[]): Promise<string[]> {
    const now = Date.now();
    const known = this.sql.exec<{ id: string }>("SELECT id FROM phones WHERE peer = ?", node).toArray().map((r) => r.id);
    const revoked: string[] = [];
    for (const phone of new Set([...phones, ...known])) {
      if (this.revokePhoneNow(phone, node, false, now)) revoked.push(phone);
    }
    // Remembered, so an upgrade or a pairing already past the Worker's checks is refused here.
    this.sql.exec("INSERT INTO revoked_nodes (id, at) VALUES (?, ?) ON CONFLICT(id) DO NOTHING", node, now);
    this.closeAll(node, CLOSE_REVOKED, "device revoked");
    this.forgetDevice(node);
    await this.ensureAlarm();
    return revoked;
  }

  /** Presence for `GET /v1/phone/devices`. */
  async presence(devices: string[]): Promise<PresenceInfo[]> {
    const now = Date.now();
    return devices.map((d) => this.presenceOf(d, now));
  }

  /**
   * Spends a phone's request nonce (PROTOCOL §1). False when the phone isn't live here or the nonce
   * was used: checked and written in this single-threaded object, so it's strongly consistent.
   */
  async spendNonce(phone: string, nonce: string): Promise<boolean> {
    const now = Date.now();
    const ok = this.ctx.storage.transactionSync(() => {
      if (!this.phoneLive(this.phone(phone), now)) return false;
      const seen = this.sql
        .exec<{ n: number }>("SELECT count(*) AS n FROM nonces WHERE device_id = ? AND nonce = ? AND at > ?", phone, nonce, now - NONCE_TTL_MS)
        .one().n;
      if (seen > 0) return false;
      this.sql.exec(
        "INSERT INTO nonces (device_id, nonce, at) VALUES (?, ?, ?) ON CONFLICT(device_id, nonce) DO UPDATE SET at = excluded.at",
        phone,
        nonce,
        now,
      );
      return true;
    });
    if (ok) await this.ensureAlarm();
    return ok;
  }

  // ── sockets ────────────────────────────────────────────────────────────────

  /**
   * `GET /socket?device=…&role=node|phone&peer=…` with `Upgrade: websocket`, from the Worker only
   * (it has checked the request's signature, the device's kind and spent the nonce).
   */
  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade") !== "websocket") return new Response("expected a websocket", { status: 426 });
    const url = new URL(request.url);
    const deviceId = url.searchParams.get("device") ?? "";
    const role = url.searchParams.get("role");
    const now = Date.now();
    if (!isId("dev", deviceId) || (role !== "node" && role !== "phone")) return new Response("bad request", { status: 400 });
    const row = this.phone(deviceId);
    let peer: string | null = null;
    if (role === "phone") {
      if (!this.phoneLive(row, now)) return new Response("revoked", { status: 401 });
      peer = row.peer;
    } else if (row !== null) {
      // A phone is never a node.
      return new Response("not a node", { status: 403 });
    } else if (this.nodeRevoked(deviceId)) {
      return new Response("revoked", { status: 401 });
    }

    // One socket per device: a newer one replaces the older (4409).
    this.closeAll(deviceId, CLOSE_REPLACED, "replaced by a newer socket");

    const pair = new WebSocketPair();
    const server = pair[1];
    this.ctx.acceptWebSocket(server, [deviceId]);
    const att: Attachment = { deviceId, role, peer, openedAt: now, helloAt: null, lastFrameAt: now };
    server.serializeAttachment(att);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const att = this.attachment(ws);
    if (!att) return this.protocolError(ws, "no state");
    if (typeof message !== "string") return this.protocolError(ws, "text frames only");
    const now = Date.now();
    att.lastFrameAt = now;
    // The size first: an oversized frame is never parsed, and closes the socket.
    if (overLimit(message, att.role === "phone" ? PHONE_FRAME_MAX : NODE_FRAME_MAX)) return this.protocolError(ws, "frame too large");
    // A node revoked here, or a phone whose node was, routes nothing more.
    if (att.role === "node" ? this.nodeRevoked(att.deviceId) : !this.phoneLive(this.phone(att.deviceId), now)) {
      this.closeAll(att.deviceId, CLOSE_REVOKED, "device revoked");
      return;
    }
    // Every frame spends a token of the device's bucket, whatever it is and whether it is valid.
    const retryAfter = this.spendToken(att.deviceId, att.role, now);
    let frame: unknown;
    try {
      frame = JSON.parse(message);
    } catch {
      return this.protocolError(ws, "frames are JSON");
    }
    if (typeof frame !== "object" || frame === null || Array.isArray(frame)) return this.protocolError(ws, "frames are JSON objects");
    const f = frame as Record<string, unknown>;
    if (att.helloAt === null) {
      if (f.t !== "hello") return this.protocolError(ws, "hello first");
      if (retryAfter !== null) {
        try {
          ws.close(CLOSE_RATE_LIMITED, "rate limited");
        } catch {
          // Already closing.
        }
        return;
      }
      return this.onHello(ws, att, f, now);
    }
    if (f.t === "send") return this.onSend(ws, att, f, retryAfter, now);
    if (f.t === "ack") {
      // Acks are cumulative: one dropped for an empty bucket is covered by the next, or by `hello`.
      if (retryAfter !== null) return ws.serializeAttachment(att);
      return this.onAck(ws, att, f);
    }
    return this.protocolError(ws, f.t === "hello" ? "hello once" : "unknown frame");
  }

  private protocolError(ws: WebSocket, reason: string): void {
    try {
      ws.close(CLOSE_PROTOCOL, reason);
    } catch {
      // Already closing.
    }
  }

  private onHello(ws: WebSocket, att: Attachment, f: Record<string, unknown>, now: number): void {
    const after = f.after;
    if (typeof after !== "number" || !Number.isSafeInteger(after) || after < 0) return this.protocolError(ws, "hello.after must be a seq");
    const cursor = this.advance(att.deviceId, after);
    att.helloAt = now;
    ws.serializeAttachment(att);

    const head = this.sql.exec<{ m: number | null }>("SELECT max(seq) AS m FROM mailbox WHERE recipient = ?", att.deviceId).one().m ?? 0;
    const peers = this.peersOf(att.deviceId, att.role, att.peer, now);
    this.trySend(ws, JSON.stringify({ t: "ready", after: cursor, head, peers: peers.map((p) => this.presenceOf(p, now)) }));

    // The loss, if any, then the backlog in seq order. Rows are only ever dropped from the oldest
    // end of a queue, so every row still queued comes after the device's one gap record.
    const gap = this.sql
      .exec<{ from_seq: number; to_seq: number }>("SELECT from_seq, to_seq FROM device_gaps WHERE recipient = ? AND to_seq > ?", att.deviceId, cursor)
      .toArray()[0];
    if (gap) this.trySend(ws, JSON.stringify({ t: "gap", from: Math.max(gap.from_seq, cursor + 1), to: gap.to_seq }));
    for (const row of this.sql.exec<MailRow>("SELECT seq, kind, body FROM mailbox WHERE recipient = ? AND seq > ? ORDER BY seq", att.deviceId, cursor)) {
      this.trySend(ws, this.frame(row));
    }

    this.announce(att.deviceId, peers, { device: att.deviceId, online: true, since: now });
  }

  private onAck(ws: WebSocket, att: Attachment, f: Record<string, unknown>): void {
    const through = f.through;
    if (typeof through !== "number" || !Number.isSafeInteger(through) || through < 0) return this.protocolError(ws, "ack.through must be a seq");
    this.advance(att.deviceId, through);
    ws.serializeAttachment(att);
  }

  private async onSend(ws: WebSocket, att: Attachment, f: Record<string, unknown>, retryAfter: number | null, now: number): Promise<void> {
    const env = f.env as Record<string, unknown> | undefined;
    const rawId = typeof env === "object" && env !== null ? env.id : undefined;
    const id = typeof rawId === "string" && B64URL_22.test(rawId) ? rawId : null;
    const refuse = (code: string, extra: Record<string, unknown> = {}) => {
      ws.serializeAttachment(att);
      this.trySend(ws, JSON.stringify({ t: "refused", id, code, ...extra }));
    };
    // The frame has already spent its token (webSocketMessage); an empty bucket refuses it.
    if (retryAfter !== null) return refuse("rate_limited", { retryAfter });

    if (!envelopeShapeOk(env)) return refuse("invalid");
    if (env.push !== undefined && att.role === "phone") return refuse("invalid");
    if (env.from !== att.deviceId) return refuse("forbidden");

    let recipientRole: Role;
    if (att.role === "phone") {
      // Live: webSocketMessage checked it for this frame.
      const me = this.phone(att.deviceId)!;
      if (me.pending_until !== null) return refuse("not_paired");
      if (env.to !== me.peer) return refuse("forbidden");
      recipientRole = "node";
    } else {
      const target = this.phone(env.to);
      if (!this.phoneLive(target, now) || target.pending_until !== null || target.peer !== att.deviceId) return refuse("forbidden");
      recipientRole = "phone";
    }

    // A resend of an id that is still queued for the same recipient is answered with the seq it
    // already has.
    const existing = this.sql
      .exec<{ seq: number }>("SELECT seq FROM mailbox WHERE sender = ? AND recipient = ? AND msg_id = ?", att.deviceId, env.to, env.id)
      .toArray()[0];
    if (existing) {
      ws.serializeAttachment(att);
      this.trySend(ws, JSON.stringify({ t: "queued", id: env.id, seq: existing.seq }));
      return;
    }

    const body = JSON.stringify(env);
    const size = byteLength(body);
    const limits = this.limits();
    const seq = this.ctx.storage.transactionSync(() => {
      const queued = this.queued(env.to);
      if (recipientRole === "node") {
        if (queued.rows + 1 > limits.nodeRows || queued.bytes + size > limits.bytes) return null;
      } else {
        this.makeRoom(env.to, queued.rows, queued.bytes, size, limits);
      }
      return this.store(env.to, att.deviceId, "msg", env.id, body, now);
    });
    if (seq === null) return refuse("queue_full");

    ws.serializeAttachment(att);
    const frame = this.frame({ seq, kind: "msg", body });
    for (const r of this.ready(env.to)) this.trySend(r, frame);
    this.trySend(ws, JSON.stringify({ t: "queued", id: env.id, seq }));
    await this.ensureAlarm();

    if (recipientRole === "phone" && env.push !== undefined && !this.presenceOf(env.to, now).online) {
      try {
        await this.push(this.env, env.to, env.push);
      } catch {
        console.error("phone push hook failed");
      }
    }
  }

  /** Drops a phone's oldest rows until one more of `size` bytes fits, recording the loss as a gap. */
  private makeRoom(phone: string, rows: number, bytes: number, size: number, limits: QueueLimits): void {
    let n = rows;
    let b = bytes;
    if (n + 1 <= limits.phoneRows && b + size <= limits.bytes) return;
    let from: number | null = null;
    let to = 0;
    for (const r of this.sql.exec<{ seq: number; size: number }>("SELECT seq, size FROM mailbox WHERE recipient = ? ORDER BY seq", phone)) {
      if (n + 1 <= limits.phoneRows && b + size <= limits.bytes) break;
      from ??= r.seq;
      to = r.seq;
      n -= 1;
      b -= r.size;
    }
    if (from === null) return;
    this.sql.exec("DELETE FROM mailbox WHERE recipient = ? AND seq <= ?", phone, to);
    this.recordGap(phone, from, to);
  }

  /**
   * Records lost seqs for a device in its one gap record, widened to cover them. Exact, because rows
   * are only ever dropped from the oldest end of a queue (`seq <= to`): no row still queued lies
   * inside the record, and the seqs between two losses are other devices' (seqs are per account).
   * The record goes when the device acknowledges past it, or with the device; never by age, so a
   * loss is never itself lost.
   */
  private recordGap(device: string, from: number, to: number): void {
    this.sql.exec(
      `INSERT INTO device_gaps (recipient, from_seq, to_seq) VALUES (?, ?, ?)
       ON CONFLICT(recipient) DO UPDATE SET from_seq = min(from_seq, excluded.from_seq), to_seq = max(to_seq, excluded.to_seq)`,
      device,
      from,
      to,
    );
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    this.left(ws);
    try {
      ws.close(code === 1005 || code === 1006 ? 1000 : code, reason);
    } catch {
      // Already closed.
    }
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    this.left(ws);
    try {
      ws.close(1011, "error");
    } catch {
      // Already closed.
    }
  }

  /** A socket went: unless another is open for the same device, its peers hear it is offline. */
  private left(ws: WebSocket): void {
    const att = this.attachment(ws);
    if (!att || att.helloAt === null) return;
    const others = this.ctx.getWebSockets(att.deviceId).filter((o) => o !== ws && o.readyState === 1);
    if (others.length > 0) return;
    const now = Date.now();
    this.sql.exec(
      "INSERT INTO presence (device, at) VALUES (?, ?) ON CONFLICT(device) DO UPDATE SET at = excluded.at",
      att.deviceId,
      now,
    );
    // A revoked phone's node already heard (revokePhone announces it).
    if (att.role === "phone" && this.phone(att.deviceId)?.revoked === 1) return;
    this.announce(att.deviceId, this.peersOf(att.deviceId, att.role, att.peer, now), { device: att.deviceId, online: false, since: now });
  }

  // ── pruning ────────────────────────────────────────────────────────────────

  override async alarm(): Promise<void> {
    const now = Date.now();
    const cutoff = now - this.retentionMs();
    // Rows past retention are dropped, oldest first (everything up to the newest old one), and each
    // device sees the loss as a gap. Gap records themselves never expire.
    const old = this.sql
      .exec<{ recipient: string; hi: number }>("SELECT recipient, max(seq) AS hi FROM mailbox WHERE at < ? GROUP BY recipient", cutoff)
      .toArray();
    this.ctx.storage.transactionSync(() => {
      for (const r of old) {
        const lo = this.sql.exec<{ lo: number }>("SELECT min(seq) AS lo FROM mailbox WHERE recipient = ?", r.recipient).one().lo;
        this.sql.exec("DELETE FROM mailbox WHERE recipient = ? AND seq <= ?", r.recipient, r.hi);
        this.recordGap(r.recipient, lo, r.hi);
      }
      this.sql.exec("DELETE FROM nonces WHERE at <= ?", now - NONCE_TTL_MS);
    });
    // Pending phones whose pairing ran out: their sockets close with 4401 and their rows go.
    const expired = this.sql
      .exec<{ id: string; peer: string }>("SELECT id, peer FROM phones WHERE revoked = 0 AND pending_until IS NOT NULL AND pending_until <= ?", now)
      .toArray();
    for (const p of expired) this.revokePhoneNow(p.id, p.peer, false, now);
    await this.ensureAlarm(true);
  }

  /** Schedules the alarm for the next expiry, or clears it when nothing will expire. */
  private async ensureAlarm(fromAlarm = false): Promise<void> {
    const q = (sql: string) => this.sql.exec<{ t: number | null }>(sql).one().t;
    const retention = this.retentionMs();
    const due: (number | null)[] = [
      ((t) => (t === null ? null : t + retention))(q("SELECT min(at) AS t FROM mailbox")),
      ((t) => (t === null ? null : t + NONCE_TTL_MS))(q("SELECT min(at) AS t FROM nonces")),
      q("SELECT min(pending_until) AS t FROM phones WHERE revoked = 0 AND pending_until IS NOT NULL"),
    ];
    let next = Infinity;
    for (const t of due) if (t !== null) next = Math.min(next, t + 1);
    const current = await this.ctx.storage.getAlarm();
    if (next === Infinity) {
      if (current !== null && !fromAlarm) await this.ctx.storage.deleteAlarm();
      return;
    }
    // Never sooner than a minute from now: expiry can wait, and wakes cost money.
    next = Math.max(next, Date.now() + 60_000);
    if (fromAlarm || current === null || current > next) await this.ctx.storage.setAlarm(next);
  }
}

/** Bumped when `migrate` has something to do for objects written by an older relay. */
const SCHEMA_VERSION = 2;

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)",
  // Sealed envelopes (kind 'msg', the JSON text as it arrived) and the relay's own notices to a node
  // (kind 'sys'), each for one recipient, in seq order. Never plaintext: the relay can't open them.
  `CREATE TABLE IF NOT EXISTS mailbox (seq INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL, sender TEXT,
     kind TEXT NOT NULL, msg_id TEXT, body TEXT NOT NULL, size INTEGER NOT NULL, at INTEGER NOT NULL)`,
  "CREATE INDEX IF NOT EXISTS mailbox_recipient ON mailbox(recipient, seq)",
  // A resend is found by (sender, recipient, id).
  "CREATE INDEX IF NOT EXISTS mailbox_dedupe ON mailbox(sender, recipient, msg_id)",
  "CREATE INDEX IF NOT EXISTS mailbox_at ON mailbox(at)",
  // Rows and bytes queued for each recipient, kept by the two triggers below on every insert and
  // delete, so a send's queue check is one lookup and never a scan.
  `CREATE TABLE IF NOT EXISTS queue_stats (recipient TEXT PRIMARY KEY, queued_rows INTEGER NOT NULL,
     queued_bytes INTEGER NOT NULL) WITHOUT ROWID`,
  `CREATE TRIGGER IF NOT EXISTS mailbox_counted_in AFTER INSERT ON mailbox BEGIN
     INSERT INTO queue_stats (recipient, queued_rows, queued_bytes) VALUES (new.recipient, 1, new.size)
     ON CONFLICT(recipient) DO UPDATE SET queued_rows = queued_rows + 1, queued_bytes = queued_bytes + excluded.queued_bytes;
   END`,
  `CREATE TRIGGER IF NOT EXISTS mailbox_counted_out AFTER DELETE ON mailbox BEGIN
     UPDATE queue_stats SET queued_rows = queued_rows - 1, queued_bytes = queued_bytes - old.size WHERE recipient = old.recipient;
   END`,
  "CREATE TABLE IF NOT EXISTS cursors (device TEXT PRIMARY KEY, acked INTEGER NOT NULL) WITHOUT ROWID",
  // The seqs a device lost (its queue overflowed, or retention dropped them), reported as a `gap`
  // frame: one record per device, widened by each loss, gone when the device acknowledges past it.
  "CREATE TABLE IF NOT EXISTS device_gaps (recipient TEXT PRIMARY KEY, from_seq INTEGER NOT NULL, to_seq INTEGER NOT NULL) WITHOUT ROWID",
  // Each device's token bucket (every frame spends one), kept across its reconnects.
  "CREATE TABLE IF NOT EXISTS buckets (device TEXT PRIMARY KEY, tokens REAL NOT NULL, at INTEGER NOT NULL) WITHOUT ROWID",
  // The account's phones, mirrored from D1 so a socket's sends are checked without a D1 read.
  `CREATE TABLE IF NOT EXISTS phones (id TEXT PRIMARY KEY, peer TEXT NOT NULL, pending_until INTEGER,
     revoked INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)`,
  "CREATE INDEX IF NOT EXISTS phones_peer ON phones(peer)",
  "CREATE INDEX IF NOT EXISTS phones_pending ON phones(pending_until) WHERE revoked = 0 AND pending_until IS NOT NULL",
  // Nodes revoked here: a socket or a pairing that got past the Worker before the revocation is
  // refused, and their phones are dead with them.
  "CREATE TABLE IF NOT EXISTS revoked_nodes (id TEXT PRIMARY KEY, at INTEGER NOT NULL) WITHOUT ROWID",
  // When a device's socket last went, for `since` in presence.
  "CREATE TABLE IF NOT EXISTS presence (device TEXT PRIMARY KEY, at INTEGER NOT NULL) WITHOUT ROWID",
  `CREATE TABLE IF NOT EXISTS nonces (device_id TEXT NOT NULL, nonce TEXT NOT NULL, at INTEGER NOT NULL,
     PRIMARY KEY (device_id, nonce)) WITHOUT ROWID`,
  "CREATE INDEX IF NOT EXISTS nonces_at ON nonces(at)",
];
