// One Durable Object per account: the ordered event log (sealed envelopes, one per device), per-device
// ack cursors and sealing keys, request nonces, the dedupe marks, the audit log, and the device
// streams (hibernatable WebSockets bridged to SSE by the Worker).
//
// Nothing here keeps timers or in-memory state between calls, so the object hibernates whenever no
// event is moving: an always-on stream costs (almost) nothing while idle. The per-socket state lives
// in the socket's attachment.
//
// Storage never holds a payload in the clear (PLAN §4.4): an event row keeps only routing metadata,
// and its body and headers exist only as HPKE ciphertexts in `envelopes`, one per device. The
// plaintext the Worker hands to `append` is sealed in memory and never written anywhere.

import { DurableObject } from "cloudflare:workers";
import { newId } from "./encoding.ts";
import {
  encodeContent,
  eventMessage,
  importRelayKey,
  sealEnvelope,
  sealHeld,
  signEnvelope,
  type RelayKey,
  type SealedContent,
  type SealedEnvelope,
} from "./envelope.ts";

/** Nonces are remembered this long (PROTOCOL §1: 600 s; the time window is ±300 s). */
export const NONCE_TTL_MS = 600_000;
/** Dedupe marks: providers that sign no timestamp retry for hours, so keep them a week. */
export const DEDUPE_TTL_MS = 7 * 24 * 3600_000;
/** One offline notice per sender per hook in this long (PROTOCOL §4a). */
export const NOTICE_TTL_MS = 24 * 3600_000;
/**
 * A device stream counts as connected while its socket is open and has shown life this recently:
 * it opened, or answered the Worker's ping (every 30 s, auto-answered without waking the object).
 * A socket the runtime still holds but nobody pings is a stream that went away.
 */
export const STREAM_ALIVE_MS = 90_000;
/** Audit entries and the hourly counts are kept this long. */
export const AUDIT_TTL_MS = 90 * 24 * 3600_000;
/** A backlog page: the Worker asks for the next one once it has written this one out. */
export const PAGE_EVENTS = 64;
export const PAGE_BYTES = 128 * 1024;

export const CLOSE_REVOKED = 4401;
export const CLOSE_REPLACED = 4409;
/** A send to a stream failed for a reason other than size: the client reconnects and resumes. */
export const CLOSE_SEND_FAILED = 1011;

/** The stream protocol this object serves (PROTOCOL §6). */
export const STREAM_PROTOCOL = 2;

/**
 * The largest WebSocket message Cloudflare carries: 32 MiB since 2025-10 (it was 1 MiB). The largest
 * event the relay accepts (a 1,835,008-byte body sealed and base64-expanded to about 2.45 MB, plus
 * a few KiB of headers and metadata) is well under it; this guard is for what can't happen.
 */
export const MAX_FRAME_BYTES = 32 * 1024 * 1024;

/** Per-account storage quota defaults (PROTOCOL §4): `ACCOUNT_MAX_EVENTS`, `ACCOUNT_MAX_BYTES`. */
export const DEFAULT_MAX_EVENTS = 10_000;
export const DEFAULT_MAX_BYTES = 256 * 1024 * 1024;

/** The bytes an envelope adds besides its ciphertext: kid, enc, signature and row overhead. */
const ENVELOPE_OVERHEAD = 192;

export interface Quota {
  events: number;
  bytes: number;
}

export interface AppendInput {
  hookId: string;
  /** Replay marks: a duplicate when any was seen; all are written with the event. */
  dedupeKeys: string[];
  verified: boolean;
  /** A strict hook: the relay didn't verify; the devices do. */
  strict: boolean;
  preset: string;
  eventType: string | null;
  /** Everything that is content: sealed, never stored in the clear. */
  content: Omit<SealedContent, "body">;
  body: Uint8Array;
  receivedAt: number;
  /**
   * The hook has an offline notice and this delivery names a sender: `mark` is the sender's keyed
   * hash, `afterMs` how long no device stream may have been connected before a notice is due.
   */
  notice?: { mark: string; afterMs: number };
  /** The screen held it (PROTOCOL §4b): the rule's id. It is kept aside, not streamed, until released. */
  held?: string;
}

export type AppendResult =
  | { duplicate: true }
  | { duplicate: false; full: true }
  | { duplicate: false; full: false; held: true; id: string; sealedFor: number; notice: false }
  | { duplicate: false; full: false; held?: false; seq: number; id: string; sealedFor: number; notice: boolean };

/** One event the screen holds (PROTOCOL §4b), as `GET /v1/held` lists it: metadata only. */
export interface HeldSummary {
  id: string;
  hookId: string;
  receivedAt: number;
  verified: boolean;
  strict: boolean;
  preset: string;
  eventType: string | null;
  /** The rule that held it. */
  rule: string;
  /** Bytes held for it (its envelopes). */
  size: number;
  /** When it is dropped if nobody releases it. */
  expiresAt: number;
}

/** Held events wait this many days by default (`SCREEN_HELD_DAYS`). */
export const DEFAULT_HELD_DAYS = 7;

/** The per-socket state, kept in the WebSocket's attachment so it survives hibernation. */
interface Attachment {
  deviceId: string;
  /** The last seq this stream has been sent (or skipped past as a gap). */
  cursor: number;
  /** True while the backlog is being paged out; live events wait for the pages. */
  catchingUp: boolean;
  /** When the stream opened (ms): its first sign of life, before any ping. */
  openedAt?: number;
}

interface EventRow extends Record<string, SqlStorageValue> {
  seq: number;
  id: string;
  hook_id: string;
  received_at: number;
  verified: number;
  strict: number;
  preset: string;
  event_type: string | null;
  held: number;
}

interface EnvelopeRow extends Record<string, SqlStorageValue> {
  kid: string;
  enc: string;
  ct: ArrayBuffer;
  sig: string;
}

export interface AuditEntry {
  at: number;
  kind: string;
  /** Who did it: a device id, a key id, or null for the relay itself (verification failures). */
  actor: string | null;
  subject: string;
  name: string | null;
  /** For counted kinds (`key.used`, `verify.failed`): how many in the hour starting at `at`. */
  count?: number;
}

/** Kinds counted per hour rather than recorded one by one. */
export type CountedKind = "key.used" | "screen.held" | "screen.dropped";

export interface EventSummary {
  seq: number;
  id: string;
  hookId: string;
  receivedAt: number;
  verified: boolean;
  strict: boolean;
  preset: string;
  eventType: string | null;
  /** Bytes held for it (the sealed envelopes). */
  size: number;
  /** Devices that have acknowledged it. */
  deliveredTo: string[];
  /** Devices it is sealed for that haven't yet. */
  pendingFor: string[];
}

/**
 * Messages to the Worker. Hook events are `h<seq>\n<event json>` so the Worker can frame them
 * without re-parsing; everything else is a JSON object with a `t` field.
 */
export function hookFrame(seq: number, eventJson: string): string {
  return `h${seq}\n${eventJson}`;
}

export class AccountObject extends DurableObject<Env> {
  private readonly sql: SqlStorage;
  /** Tests lower these to exercise the guards; production uses the constants and the env. */
  frameLimit = MAX_FRAME_BYTES;
  quotaOverride: Quota | null = null;
  private relayKey: Promise<RelayKey | null> | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    for (const stmt of SCHEMA) this.sql.exec(stmt);
    this.migrate();
    // Liveness pings from the Worker are answered without waking the object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  /** Columns added after phase 0, for objects created before them. */
  private migrate(): void {
    const version = this.sql.exec<{ value: number }>("SELECT value FROM meta WHERE key = 'schema'").toArray()[0]?.value ?? 1;
    if (version >= 3) return;
    const steps = [
      "ALTER TABLE events ADD COLUMN strict INTEGER NOT NULL DEFAULT 0",
      "ALTER TABLE devices ADD COLUMN seal_key BLOB",
      "ALTER TABLE devices ADD COLUMN seal_kid TEXT",
      // Schema 3: events released from the screen's hold (PROTOCOL §4b).
      "ALTER TABLE events ADD COLUMN held INTEGER NOT NULL DEFAULT 0",
    ];
    for (const stmt of steps) {
      try {
        this.sql.exec(stmt);
      } catch {
        // Already there: the table was created with it.
      }
    }
    this.sql.exec("INSERT INTO meta (key, value) VALUES ('schema', 3) ON CONFLICT(key) DO UPDATE SET value = 3");
  }

  private signingKey(): Promise<RelayKey | null> {
    this.relayKey ??= importRelayKey(this.env.RELAY_SIGNING_KEY);
    return this.relayKey;
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
   * What the log holds: events, and bytes (envelopes, plus any legacy body and headers), kept as
   * counters in `meta` so an append doesn't scan the log. An object from before the counters
   * existed counts once.
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
    const e = this.sql.exec<{ b: number | null }>(`SELECT sum(length(ct) + ${ENVELOPE_OVERHEAD}) AS b FROM envelopes`).one();
    const u = { events: r.n, bytes: (r.b ?? 0) + (e.b ?? 0) };
    this.setUsage(u);
    return u;
  }

  private setUsage(u: Quota): void {
    const up = "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value";
    this.sql.exec(up, "log_events", Math.max(0, u.events));
    this.sql.exec(up, "log_bytes", Math.max(0, u.bytes));
  }

  /** Deletes envelopes matching `where`, keeping the usage counter right. */
  private deleteEnvelopes(where: string, ...args: SqlStorageValue[]): void {
    const gone = this.sql
      .exec<{ n: number; b: number | null }>(`SELECT count(*) AS n, sum(length(ct) + ${ENVELOPE_OVERHEAD}) AS b FROM envelopes WHERE ${where}`, ...args)
      .one();
    if (gone.n === 0) return;
    const u = this.usage();
    this.sql.exec(`DELETE FROM envelopes WHERE ${where}`, ...args);
    this.setUsage({ events: u.events, bytes: u.bytes - (gone.b ?? 0) });
  }

  /** Deletes events up to `seq` and their envelopes, keeping the usage counters right. */
  private deleteThrough(seq: number): void {
    this.deleteEnvelopes("seq <= ?", seq);
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
  private ensureDevice(deviceId: string): { acked: number; revoked: boolean; sealKid: string | null } {
    this.sql.exec(
      "INSERT INTO devices (id, acked, revoked) VALUES (?, ?, 0) ON CONFLICT(id) DO NOTHING",
      deviceId,
      this.head(),
    );
    const row = this.sql
      .exec<{ acked: number; revoked: number; seal_kid: string | null }>("SELECT acked, revoked, seal_kid FROM devices WHERE id = ?", deviceId)
      .one();
    return { acked: row.acked, revoked: row.revoked === 1, sealKid: row.seal_kid };
  }

  // ── RPC from the Worker ────────────────────────────────────────────────────

  async addDevice(deviceId: string, seal?: { key: Uint8Array; kid: string }): Promise<void> {
    this.ensureDevice(deviceId);
    if (seal) await this.setSealKey(deviceId, seal.key, seal.kid);
  }

  /**
   * Sets (or replaces) a device's sealing key. Events appended from now on are sealed to it; the
   * ones already in the log keep the key they were sealed to, named by its kid in each envelope.
   */
  async setSealKey(deviceId: string, key: Uint8Array, kid: string): Promise<void> {
    this.ensureDevice(deviceId);
    this.sql.exec("UPDATE devices SET seal_key = ?, seal_kid = ? WHERE id = ?", key, kid, deviceId);
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

  private isDuplicate(hookId: string, keys: string[]): boolean {
    for (const key of keys) {
      const seen = this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM seen WHERE hook_id = ? AND key = ?", hookId, key).one().n;
      if (seen > 0) return true;
    }
    return false;
  }

  /**
   * Appends one event: seals its content to every active device with a sealing key (HPKE, with the
   * hook, seq and id as associated data), signs each envelope, and writes the event, its envelopes
   * and its dedupe marks in one transaction; then delivers it live. Refuses (`full`) when the
   * account's log is at its quota, until devices acknowledge what's waiting.
   *
   * The seq must be known before sealing (it is in the associated data), so the object takes no
   * other request while it seals: nothing can append in between.
   */
  async append(input: AppendInput): Promise<AppendResult> {
    const relay = await this.signingKey();
    if (!relay) throw new Error("RELAY_SIGNING_KEY is missing or malformed");
    const result = await this.ctx.blockConcurrencyWhile(async (): Promise<AppendResult> => {
      if (this.isDuplicate(input.hookId, input.dedupeKeys)) return { duplicate: true };
      const devices = this.sql
        .exec<{ id: string; seal_key: ArrayBuffer; seal_kid: string }>(
          "SELECT id, seal_key, seal_kid FROM devices WHERE revoked = 0 AND seal_key IS NOT NULL ORDER BY id",
        )
        .toArray();
      let plaintext: Uint8Array | null = encodeContent({ ...input.content, body: input.body });
      const estimate = devices.length * (plaintext.byteLength + 16 + ENVELOPE_OVERHEAD) + 2;
      const usage = this.usage();
      const quota = this.quota();
      if (usage.events + 1 > quota.events || usage.bytes + estimate > quota.bytes) return { duplicate: false, full: true };
      if (input.held !== undefined) {
        const id = newId("evt");
        const sealed: Omit<SealedEnvelope, "sig">[] = [];
        for (const d of devices) {
          sealed.push(await sealHeld({ deviceId: d.id, kid: d.seal_kid, publicKey: new Uint8Array(d.seal_key) }, input.hookId, id, plaintext));
        }
        plaintext.fill(0);
        plaintext = null;
        let bytes = 2;
        this.ctx.storage.transactionSync(() => {
          for (const key of new Set(input.dedupeKeys)) {
            this.sql.exec("INSERT INTO seen (hook_id, key, at) VALUES (?, ?, ?)", input.hookId, key, input.receivedAt);
          }
          this.sql.exec(
            `INSERT INTO held_events (id, hook_id, received_at, verified, strict, preset, event_type, rule)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            id,
            input.hookId,
            input.receivedAt,
            input.verified ? 1 : 0,
            input.strict ? 1 : 0,
            input.preset,
            input.eventType,
            input.held!,
          );
          for (const e of sealed) {
            this.sql.exec("INSERT INTO held_envelopes (id, device_id, kid, enc, ct) VALUES (?, ?, ?, ?, ?)", id, e.deviceId, e.kid, e.enc, e.ct);
            bytes += e.ct.byteLength + ENVELOPE_OVERHEAD;
          }
          this.setUsage({ events: usage.events + 1, bytes: usage.bytes + bytes });
        });
        return { duplicate: false, full: false, held: true, id, sealedFor: sealed.length, notice: false };
      }
      // Decided before sealing, so the devices read that the sender was answered.
      const notice = input.notice ? this.noticeDue(input.hookId, input.notice, input.receivedAt) : false;
      if (notice) {
        plaintext.fill(0);
        plaintext = encodeContent({ ...input.content, notice: true, body: input.body });
      }

      const seq = this.head() + 1;
      const id = newId("evt");
      const meta = {
        seq,
        id,
        hookId: input.hookId,
        receivedAt: input.receivedAt,
        verified: input.verified,
        strict: input.strict,
        preset: input.preset,
        eventType: input.eventType,
      };
      const envelopes: SealedEnvelope[] = [];
      for (const d of devices) {
        envelopes.push(await sealEnvelope(relay, { deviceId: d.id, kid: d.seal_kid, publicKey: new Uint8Array(d.seal_key) }, meta, plaintext));
      }
      // The plaintext is no longer needed; nothing below may see it.
      plaintext.fill(0);
      plaintext = null;

      let bytes = 2;
      this.ctx.storage.transactionSync(() => {
        for (const key of new Set(input.dedupeKeys)) {
          this.sql.exec("INSERT INTO seen (hook_id, key, at) VALUES (?, ?, ?)", input.hookId, key, input.receivedAt);
        }
        if (notice) {
          this.sql.exec(
            "INSERT INTO notices (hook_id, mark, at) VALUES (?, ?, ?) ON CONFLICT(hook_id, mark) DO UPDATE SET at = excluded.at",
            input.hookId,
            input.notice!.mark,
            input.receivedAt,
          );
        }
        this.sql.exec("INSERT INTO meta (key, value) VALUES ('head', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", seq);
        // Routing metadata only: the body and headers columns stay empty (they held plaintext in
        // phase 0, and are kept so older rows still read).
        this.sql.exec(
          `INSERT INTO events (seq, id, hook_id, received_at, verified, strict, preset, event_type, content_type, headers, body)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, '{}', x'')`,
          seq,
          id,
          input.hookId,
          input.receivedAt,
          input.verified ? 1 : 0,
          input.strict ? 1 : 0,
          input.preset,
          input.eventType,
        );
        for (const e of envelopes) {
          this.sql.exec(
            "INSERT INTO envelopes (seq, device_id, kid, enc, ct, sig) VALUES (?, ?, ?, ?, ?, ?)",
            seq,
            e.deviceId,
            e.kid,
            e.enc,
            e.ct,
            e.sig,
          );
          bytes += e.ct.byteLength + ENVELOPE_OVERHEAD;
        }
        this.setUsage({ events: usage.events + 1, bytes: usage.bytes + bytes });
      });
      return { duplicate: false, full: false, seq, id, sealedFor: envelopes.length, notice };
    });
    if (!result.duplicate && !result.full) {
      if (!result.held) this.deliverLive(result.seq);
      await this.ensureAlarm();
    }
    return result;
  }

  // ── the screen's hold (PROTOCOL §4b) ───────────────────────────────────────

  private heldMs(): number {
    const days = Number(this.env.SCREEN_HELD_DAYS);
    return (Number.isFinite(days) && days > 0 ? days : DEFAULT_HELD_DAYS) * 24 * 3600_000;
  }

  /** Held events, newest first: metadata, never content. */
  async listHeld(): Promise<HeldSummary[]> {
    const ttl = this.heldMs();
    return this.sql
      .exec<{
        id: string;
        hook_id: string;
        received_at: number;
        verified: number;
        strict: number;
        preset: string;
        event_type: string | null;
        rule: string;
        size: number | null;
      }>(
        `SELECT h.*, (SELECT sum(length(ct)) FROM held_envelopes e WHERE e.id = h.id) AS size
         FROM held_events h ORDER BY received_at DESC LIMIT 500`,
      )
      .toArray()
      .map((r) => ({
        id: r.id,
        hookId: r.hook_id,
        receivedAt: r.received_at,
        verified: r.verified === 1,
        strict: r.strict === 1,
        preset: r.preset,
        eventType: r.event_type,
        rule: r.rule,
        size: r.size ?? 0,
        expiresAt: r.received_at + ttl,
      }));
  }

  /** Deletes held envelopes matching `where`, keeping the usage counter right. */
  private deleteHeldEnvelopes(where: string, ...args: SqlStorageValue[]): void {
    const gone = this.sql
      .exec<{ n: number; b: number | null }>(`SELECT count(*) AS n, sum(length(ct) + ${ENVELOPE_OVERHEAD}) AS b FROM held_envelopes WHERE ${where}`, ...args)
      .one();
    if (gone.n === 0) return;
    const u = this.usage();
    this.sql.exec(`DELETE FROM held_envelopes WHERE ${where}`, ...args);
    this.setUsage({ events: u.events, bytes: u.bytes - (gone.b ?? 0) });
  }

  /** Forgets one held event: dropped by a person, or past its wait. */
  private forgetHeld(id: string): boolean {
    const n = this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM held_events WHERE id = ?", id).one().n;
    if (n === 0) return false;
    this.ctx.storage.transactionSync(() => {
      this.deleteHeldEnvelopes("id = ?", id);
      this.sql.exec("DELETE FROM held_events WHERE id = ?", id);
      const u = this.usage();
      this.setUsage({ events: u.events - 1, bytes: u.bytes - 2 });
    });
    return true;
  }

  /** Drops a held event: it is never streamed. False when there is none. */
  async dropHeld(id: string): Promise<boolean> {
    const gone = this.forgetHeld(id);
    if (gone) await this.ensureAlarm();
    return gone;
  }

  /**
   * Releases a held event: it takes the next seq, each envelope is signed for it (with the `held`
   * line, so its device opens it with the held associated data), and it is streamed like any
   * event. Devices revoked meanwhile get nothing; null when there is no such held event.
   */
  async releaseHeld(id: string): Promise<{ seq: number } | null> {
    const relay = await this.signingKey();
    if (!relay) throw new Error("RELAY_SIGNING_KEY is missing or malformed");
    const result = await this.ctx.blockConcurrencyWhile(async (): Promise<{ seq: number } | null> => {
      const h = this.sql
        .exec<{ hook_id: string; received_at: number; verified: number; strict: number; preset: string; event_type: string | null }>(
          "SELECT hook_id, received_at, verified, strict, preset, event_type FROM held_events WHERE id = ?",
          id,
        )
        .toArray()[0];
      if (!h) return null;
      const envs = this.sql
        .exec<{ device_id: string; kid: string; enc: string; ct: ArrayBuffer }>(
          `SELECT e.device_id, e.kid, e.enc, e.ct FROM held_envelopes e JOIN devices d ON d.id = e.device_id
           WHERE e.id = ? AND d.revoked = 0 ORDER BY e.device_id`,
          id,
        )
        .toArray();
      const seq = this.head() + 1;
      const meta = {
        seq,
        id,
        hookId: h.hook_id,
        receivedAt: h.received_at,
        verified: h.verified === 1,
        strict: h.strict === 1,
        preset: h.preset,
        eventType: h.event_type,
        held: true,
      };
      const signed: { device_id: string; kid: string; enc: string; ct: Uint8Array<ArrayBuffer>; sig: string }[] = [];
      for (const e of envs) {
        const ct = new Uint8Array(e.ct);
        signed.push({ ...e, ct, sig: await signEnvelope(relay, e.device_id, meta, { kid: e.kid, enc: e.enc, ct }) });
      }
      this.ctx.storage.transactionSync(() => {
        this.sql.exec("INSERT INTO meta (key, value) VALUES ('head', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", seq);
        this.sql.exec(
          `INSERT INTO events (seq, id, hook_id, received_at, verified, strict, preset, event_type, content_type, headers, body, held)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, '{}', x'', 1)`,
          seq,
          id,
          h.hook_id,
          h.received_at,
          h.verified,
          h.strict,
          h.preset,
          h.event_type,
        );
        for (const e of signed) {
          this.sql.exec("INSERT INTO envelopes (seq, device_id, kid, enc, ct, sig) VALUES (?, ?, ?, ?, ?, ?)", seq, e.device_id, e.kid, e.enc, e.ct, e.sig);
        }
        // The bytes move from the hold to the log: the usage counters don't change.
        this.sql.exec("DELETE FROM held_envelopes WHERE id = ?", id);
        this.sql.exec("DELETE FROM held_events WHERE id = ?", id);
      });
      return { seq };
    });
    if (result) {
      this.deliverLive(result.seq);
      await this.ensureAlarm();
    }
    return result;
  }

  /**
   * Whether an offline notice is due (PROTOCOL §4a): no device stream is connected, none has been
   * for `afterMs`, and this sender (a keyed hash) hasn't had one from this hook in the last day.
   */
  private noticeDue(hookId: string, notice: { mark: string; afterMs: number }, now: number): boolean {
    let seen = this.sql.exec<{ value: number }>("SELECT value FROM meta WHERE key = 'stream_seen'").toArray()[0]?.value;
    for (const ws of this.ctx.getWebSockets()) {
      const att = ws.deserializeAttachment() as Attachment | null;
      const pong = this.ctx.getWebSocketAutoResponseTimestamp(ws)?.getTime() ?? 0;
      const alive = Math.max(att?.openedAt ?? 0, pong);
      if (ws.readyState === 1 && now - alive < STREAM_ALIVE_MS) return false;
      seen = Math.max(seen ?? 0, alive);
    }
    if (seen !== undefined && now - seen < notice.afterMs) return false;
    const last = this.sql
      .exec<{ at: number }>("SELECT at FROM notices WHERE hook_id = ? AND mark = ?", hookId, notice.mark)
      .toArray()[0]?.at;
    return last === undefined || now - last >= NOTICE_TTL_MS;
  }

  /** A device stream was connected until now: the offline clock starts again from here. */
  private streamSeen(): void {
    this.sql.exec(
      "INSERT INTO meta (key, value) VALUES ('stream_seen', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      Date.now(),
    );
  }

  /** Counts a failed verification (counted, never stored: PROTOCOL §4). */
  async recordFailure(hookId: string): Promise<void> {
    this.pruneAudit(Date.now());
    const hour = Math.floor(Date.now() / 3600_000) * 3600_000;
    this.sql.exec(
      `INSERT INTO verify_failures (hook_id, hour, count) VALUES (?, ?, 1)
       ON CONFLICT(hook_id, hour) DO UPDATE SET count = count + 1`,
      hookId,
      hour,
    );
  }

  /** Moves a device's ack cursor forward (never back, never past the head); returns it. */
  async ack(deviceId: string, through: number): Promise<number> {
    const head = this.head();
    const current = this.ensureDevice(deviceId).acked;
    const next = Math.max(current, Math.min(through, head));
    if (next !== current) {
      this.sql.exec("UPDATE devices SET acked = ? WHERE id = ?", next, deviceId);
      // This device's envelopes are of no use to anyone once it has them.
      this.deleteEnvelopes("device_id = ? AND seq <= ?", deviceId, next);
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
    this.deleteEnvelopes("device_id = ?", deviceId);
    this.deleteHeldEnvelopes("device_id = ?", deviceId);
    this.pruneAcknowledged();
    await this.ensureAlarm();
  }

  // ── audit (PLAN §4.3): names and ids only ──────────────────────────────────

  /**
   * Audit rows are pruned as they're written (and read), not by the alarm: an account where nothing
   * happens must never wake just to forget its history.
   */
  private pruneAudit(now: number): void {
    this.sql.exec("DELETE FROM audit WHERE at <= ?", now - AUDIT_TTL_MS);
    this.sql.exec("DELETE FROM audit_counts WHERE hour <= ?", now - AUDIT_TTL_MS);
    this.sql.exec("DELETE FROM verify_failures WHERE hour <= ?", now - AUDIT_TTL_MS);
  }

  async audit(entry: { kind: string; actor: string | null; subject: string; name?: string | null }): Promise<void> {
    this.pruneAudit(Date.now());
    this.sql.exec(
      "INSERT INTO audit (at, kind, actor, subject, name) VALUES (?, ?, ?, ?, ?)",
      Date.now(),
      entry.kind,
      entry.actor,
      entry.subject,
      entry.name ?? null,
    );
  }

  /** Counts one occurrence of a counted kind in the current hour. */
  async countAudit(kind: CountedKind, subject: string, name: string | null): Promise<void> {
    this.pruneAudit(Date.now());
    const hour = Math.floor(Date.now() / 3600_000) * 3600_000;
    this.sql.exec(
      `INSERT INTO audit_counts (kind, subject, hour, name, count) VALUES (?, ?, ?, ?, 1)
       ON CONFLICT(kind, subject, hour) DO UPDATE SET count = count + 1, name = excluded.name`,
      kind,
      subject,
      hour,
      name,
    );
  }

  /** The newest audit entries at or after `since`, newest first. */
  async readAudit(since: number, limit: number): Promise<AuditEntry[]> {
    this.pruneAudit(Date.now());
    const one = this.sql
      .exec<{ at: number; kind: string; actor: string | null; subject: string; name: string | null }>(
        "SELECT at, kind, actor, subject, name FROM audit WHERE at >= ? ORDER BY at DESC, rowid DESC LIMIT ?",
        since,
        limit,
      )
      .toArray()
      .map((r): AuditEntry => ({ at: r.at, kind: r.kind, actor: r.actor, subject: r.subject, name: r.name }));
    const counted = this.sql
      .exec<{ hour: number; kind: string; subject: string; name: string | null; count: number }>(
        "SELECT hour, kind, subject, name, count FROM audit_counts WHERE hour >= ? ORDER BY hour DESC LIMIT ?",
        Math.floor(since / 3600_000) * 3600_000,
        limit,
      )
      .toArray()
      .map((r): AuditEntry => ({
        at: r.hour,
        kind: r.kind,
        // A key's own uses are by the key; the screen's counts are the relay's.
        actor: r.kind === "key.used" ? r.subject : null,
        subject: r.subject,
        name: r.name,
        count: r.count,
      }));
    const failures = this.sql
      .exec<{ hour: number; hook_id: string; count: number }>(
        "SELECT hour, hook_id, count FROM verify_failures WHERE hour >= ? ORDER BY hour DESC LIMIT ?",
        Math.floor(since / 3600_000) * 3600_000,
        limit,
      )
      .toArray()
      .map((r): AuditEntry => ({ at: r.hour, kind: "verify.failed", actor: null, subject: r.hook_id, name: null, count: r.count }));
    return [...one, ...counted, ...failures].sort((a, b) => b.at - a.at).slice(0, limit);
  }

  /** Recent deliveries still in the log, newest first: metadata only, never content. */
  async listEvents(limit: number): Promise<EventSummary[]> {
    const rows = this.sql.exec<EventRow>("SELECT * FROM events ORDER BY seq DESC LIMIT ?", limit).toArray();
    const devices = this.sql.exec<{ id: string; acked: number }>("SELECT id, acked FROM devices WHERE revoked = 0").toArray();
    return rows.map((r) => {
      const sealed = this.sql
        .exec<{ device_id: string; n: number }>("SELECT device_id, length(ct) AS n FROM envelopes WHERE seq = ?", r.seq)
        .toArray();
      return {
        seq: r.seq,
        id: r.id,
        hookId: r.hook_id,
        receivedAt: r.received_at,
        verified: r.verified === 1,
        strict: r.strict === 1,
        preset: r.preset,
        eventType: r.event_type,
        size: sealed.reduce((n, e) => n + e.n, 0),
        deliveredTo: devices.filter((d) => d.acked >= r.seq).map((d) => d.id),
        pendingFor: sealed.map((e) => e.device_id).filter((id) => devices.some((d) => d.id === id && d.acked < r.seq)),
      };
    });
  }

  /** `ready` for a probe (PROTOCOL §6): where a stream would start, without opening one. */
  async probe(deviceId: string, lastEventId: number): Promise<{ after: number; head: number; sealKid: string | null } | null> {
    const device = this.ensureDevice(deviceId);
    if (device.revoked) return null;
    const head = this.head();
    return { after: Math.min(Math.max(lastEventId, device.acked), head), head, sealKid: device.sealKid };
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
    this.streamSeen();
    const att: Attachment = { deviceId, cursor: after, catchingUp: true, openedAt: Date.now() };
    const ready = { t: "ready", accountId, deviceId, after, head, protocol: STREAM_PROTOCOL, sealKid: device.sealKid };
    if (this.trySend(server, JSON.stringify(ready))) this.sendPage(server, att);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (message !== "next") return;
    const att = ws.deserializeAttachment() as Attachment | null;
    if (att?.catchingUp) this.sendPage(ws, att);
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    this.streamSeen();
    try {
      ws.close(code === 1005 || code === 1006 ? 1000 : code, reason);
    } catch {
      // Already closed.
    }
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    this.streamSeen();
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
   * Sends one event, as this socket's device's envelope, and moves the cursor past it; returns the
   * bytes sent, or null when the socket failed. An event with no envelope for this device (it had
   * no sealing key when the event arrived) is a one-event `gap` with reason `no_key`; one whose frame
   * is over the WebSocket message limit is a `gap` with reason `too_large`. Neither can wedge the stream.
   */
  private sendHook(ws: WebSocket, att: Attachment, row: EventRow): number | null {
    const env = this.sql
      .exec<EnvelopeRow>("SELECT kid, enc, ct, sig FROM envelopes WHERE seq = ? AND device_id = ?", row.seq, att.deviceId)
      .toArray()[0];
    const skip = (reason: string): number | null => {
      if (!this.trySend(ws, JSON.stringify({ t: "gap", from: row.seq, to: row.seq, reason }))) return null;
      att.cursor = row.seq;
      return 0;
    };
    if (!env) return skip("no_key");
    const frame = hookFrame(
      row.seq,
      eventMessage(
        {
          seq: row.seq,
          id: row.id,
          hookId: row.hook_id,
          receivedAt: row.received_at,
          verified: row.verified === 1,
          strict: row.strict === 1,
          preset: row.preset,
          eventType: row.event_type,
          ...(row.held === 1 ? { held: true } : {}),
        },
        { kid: env.kid, enc: env.enc, ct: new Uint8Array(env.ct), sig: env.sig },
      ),
    );
    if (overLimit(frame, this.frameLimit)) return skip("too_large");
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
    this.sql.exec("DELETE FROM notices WHERE at <= ?", now - NOTICE_TTL_MS);
    for (const r of this.sql.exec<{ id: string }>("SELECT id FROM held_events WHERE received_at <= ?", now - this.heldMs()).toArray()) {
      this.forgetHeld(r.id);
    }
    this.pruneAudit(now);
    await this.ensureAlarm(true);
  }

  /**
   * Schedules the alarm for the next time something expires, or clears it when nothing will.
   * An account with nothing pending has no alarm, so idle accounts never wake.
   */
  private async ensureAlarm(fromAlarm = false): Promise<void> {
    const q = (sql: string) => this.sql.exec<{ t: number | null }>(sql).one().t;
    const due: [number | null, number][] = [
      [q("SELECT min(at) AS t FROM nonces"), NONCE_TTL_MS],
      [q("SELECT min(received_at) AS t FROM events"), this.retentionMs()],
      [q("SELECT min(at) AS t FROM seen"), DEDUPE_TTL_MS],
      [q("SELECT min(at) AS t FROM notices"), NOTICE_TTL_MS],
      [q("SELECT min(received_at) AS t FROM held_events"), this.heldMs()],
    ];
    let next = Infinity;
    for (const [t, ttl] of due) if (t !== null) next = Math.min(next, t + ttl + 1);
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
    envelopes: number;
    held: number;
    usage: Quota;
    devices: { id: string; acked: number; revoked: boolean; sealKid: string | null }[];
  }> {
    return {
      head: this.head(),
      events: this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM events").one().n,
      envelopes: this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM envelopes").one().n,
      held: this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM held_events").one().n,
      usage: this.usage(),
      devices: this.sql
        .exec<{ id: string; acked: number; revoked: number; seal_kid: string | null }>(
          "SELECT id, acked, revoked, seal_kid FROM devices ORDER BY id",
        )
        .toArray()
        .map((d) => ({ id: d.id, acked: d.acked, revoked: d.revoked === 1, sealKid: d.seal_kid })),
    };
  }
}

/** Whether a message is over `limit` bytes of UTF-8 (encoding it only when it might be). */
function overLimit(s: string, limit: number): boolean {
  return s.length * 3 > limit && new TextEncoder().encode(s).byteLength > limit;
}

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)",
  // `headers`, `body` and `content_type` held plaintext in phase 0; new rows leave them empty.
  `CREATE TABLE IF NOT EXISTS events (
     seq INTEGER PRIMARY KEY, id TEXT NOT NULL, hook_id TEXT NOT NULL, received_at INTEGER NOT NULL,
     verified INTEGER NOT NULL, preset TEXT NOT NULL, event_type TEXT, content_type TEXT,
     headers TEXT NOT NULL, body BLOB NOT NULL, strict INTEGER NOT NULL DEFAULT 0)`,
  "CREATE INDEX IF NOT EXISTS events_received ON events(received_at)",
  `CREATE TABLE IF NOT EXISTS envelopes (seq INTEGER NOT NULL, device_id TEXT NOT NULL, kid TEXT NOT NULL,
     enc TEXT NOT NULL, ct BLOB NOT NULL, sig TEXT NOT NULL)`,
  "CREATE UNIQUE INDEX IF NOT EXISTS envelopes_seq_device ON envelopes(seq, device_id)",
  "CREATE INDEX IF NOT EXISTS envelopes_device ON envelopes(device_id, seq)",
  `CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, acked INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
     seal_key BLOB, seal_kid TEXT)`,
  `CREATE TABLE IF NOT EXISTS nonces (device_id TEXT NOT NULL, nonce TEXT NOT NULL, at INTEGER NOT NULL,
     PRIMARY KEY (device_id, nonce)) WITHOUT ROWID`,
  "CREATE INDEX IF NOT EXISTS nonces_at ON nonces(at)",
  `CREATE TABLE IF NOT EXISTS seen (hook_id TEXT NOT NULL, key TEXT NOT NULL, at INTEGER NOT NULL,
     PRIMARY KEY (hook_id, key)) WITHOUT ROWID`,
  "CREATE INDEX IF NOT EXISTS seen_at ON seen(at)",
  // Offline notices sent (PROTOCOL §4a): the sender only as a keyed hash, never the address.
  `CREATE TABLE IF NOT EXISTS notices (hook_id TEXT NOT NULL, mark TEXT NOT NULL, at INTEGER NOT NULL,
     PRIMARY KEY (hook_id, mark)) WITHOUT ROWID`,
  "CREATE INDEX IF NOT EXISTS notices_at ON notices(at)",
  // The screen's hold (PROTOCOL §4b): events sealed (with the held associated data) and kept aside
  // until a device releases or drops them. Metadata and ciphertext only, as in the log.
  `CREATE TABLE IF NOT EXISTS held_events (id TEXT PRIMARY KEY, hook_id TEXT NOT NULL, received_at INTEGER NOT NULL,
     verified INTEGER NOT NULL, strict INTEGER NOT NULL, preset TEXT NOT NULL, event_type TEXT, rule TEXT NOT NULL)`,
  "CREATE INDEX IF NOT EXISTS held_received ON held_events(received_at)",
  `CREATE TABLE IF NOT EXISTS held_envelopes (id TEXT NOT NULL, device_id TEXT NOT NULL, kid TEXT NOT NULL, enc TEXT NOT NULL,
     ct BLOB NOT NULL, PRIMARY KEY (id, device_id)) WITHOUT ROWID`,
  "CREATE TABLE IF NOT EXISTS pruned (from_seq INTEGER NOT NULL, to_seq INTEGER NOT NULL, reason TEXT NOT NULL)",
  `CREATE TABLE IF NOT EXISTS verify_failures (hook_id TEXT NOT NULL, hour INTEGER NOT NULL, count INTEGER NOT NULL,
     PRIMARY KEY (hook_id, hour)) WITHOUT ROWID`,
  "CREATE TABLE IF NOT EXISTS audit (at INTEGER NOT NULL, kind TEXT NOT NULL, actor TEXT, subject TEXT NOT NULL, name TEXT)",
  "CREATE INDEX IF NOT EXISTS audit_at ON audit(at)",
  `CREATE TABLE IF NOT EXISTS audit_counts (kind TEXT NOT NULL, subject TEXT NOT NULL, hour INTEGER NOT NULL,
     name TEXT, count INTEGER NOT NULL, PRIMARY KEY (kind, subject, hour)) WITHOUT ROWID`,
];
