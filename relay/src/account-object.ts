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

/**
 * Nonces are remembered this long (PROTOCOL §1: 660 s). The time window is ±300 s, so a request
 * signed at the far edge of the window stays refused for longer than it could still be accepted.
 */
export const NONCE_TTL_MS = 660_000;
/** Dedupe marks: providers that sign no timestamp retry for hours, so keep them a week. */
export const DEDUPE_TTL_MS = 7 * 24 * 3600_000;
/**
 * Body-hash replay marks of presets that sign no timestamp (`REPLAY_MARK_DAYS`): a captured genuine
 * delivery verifies forever, so the mark that refuses its replay is kept far longer than a week.
 */
export const DEFAULT_REPLAY_MARK_DAYS = 180;
/** Alarms are rounded up to this, so a busy account wakes at most hourly just to prune. */
export const ALARM_BUCKET_MS = 3600_000;
/** The object's storage layout; the schema statements run only when the stored one is older. */
export const SCHEMA_VERSION = 8;
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
/**
 * Per-hook shares of the account's quota (PROTOCOL §4), so one flooded hook can't fill the log for
 * every other: a hook the relay verifies may hold half of it (`HOOK_MAX_EVENTS`, `HOOK_MAX_BYTES`);
 * a strict or unverified hook, which anyone who knows its URL can fill, a sixteenth
 * (`UNCHECKED_HOOK_MAX_EVENTS`, `UNCHECKED_HOOK_MAX_BYTES`).
 */
export const HOOK_SHARE = 2;
export const UNCHECKED_HOOK_SHARE = 16;
/** What the screen may hold per hook (`HELD_MAX_EVENTS`, `HELD_MAX_BYTES`), apart from the log. */
export const DEFAULT_HELD_MAX_EVENTS = 200;
export const DEFAULT_HELD_MAX_BYTES = 16 * 1024 * 1024;

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
  /** The marks among `dedupeKeys` kept for `REPLAY_MARK_DAYS` rather than a week. */
  longKeys?: string[];
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
  /**
   * The hook's target (PROTOCOL §3): only the devices it names, or that carry one of its tags, get
   * an envelope, and the others' streams pass the event by. Absent: every device. A target that
   * matches no active device with a sealing key refuses the delivery (`noRecipient`).
   */
  recipients?: { devices: string[]; tags: string[] };
  /** The account's plan (PROTOCOL §2a). Without it, only the backlog quota of the settings applies. */
  plan?: PlanInput;
  /** What the hook does past the daily cap: refuse (429, the default) or accept and drop. */
  onLimit?: "refuse" | "accept_and_drop";
}

/** A `limit` notice (PROTOCOL §6) as the object keeps it: one per scope and hook. */
export interface LimitNotice {
  scope: LimitScope | "paused" | "no_recipient";
  hookId?: string;
  refused: number;
  since: number;
  until: number | null;
  plan: string;
}

/** `GET /v1/account`'s usage, as the object counts it. */
export interface AccountUsage {
  day: number;
  today: { events: number; refused: number; dropped: number };
  perHook: Record<string, { today: number; refused: number; backlog: Quota; lastEventAt: number | null }>;
  backlog: Quota;
}

/** Which quota refused an append: the account's log, the hook's share of it, or the hook's hold. */
export type FullScope = "account" | "hook" | "held";

/**
 * The plan's limits the Worker passes with each delivery (PROTOCOL §2a), counted exactly here: the
 * token buckets and daily counters are rows of this object's SQLite (`counters`, `hook_usage`), read
 * in the synchronous step that decides the append and written in its commit's transaction, with
 * the appends in between counted from memory (`Reservation.count`). No timer runs and hibernation
 * is unaffected; an append lost before its commit was never stored, and is never counted.
 */
export interface PlanInput {
  /** The plan's name, as the `limit` stream event says it. */
  name: string;
  /** The account's entitled plan ran out: `name` is the fallback (PROTOCOL §2b). */
  expired: boolean;
  eventsPerDay: number | null;
  hookRatePerMin: number | null;
  hookBurst: number | null;
  accountRatePerMin: number | null;
  accountBurst: number | null;
  retentionHours: number | null;
  backlogEvents: number | null;
  backlogBytes: number | null;
  /** Refusals of one hook within `pauseWindowMs` that pause it; 0 never pauses. */
  pauseAfter: number;
  pauseWindowMs: number;
}

/** What refused a delivery under the plan (PROTOCOL §4, step 7). */
export type LimitScope = "hook_rate" | "account_rate" | "daily" | "plan_expired";

export interface Refusal {
  error: "rate_limited" | "quota";
  scope: LimitScope;
  /** Whole seconds until a delivery could be taken: what `Retry-After` says. */
  retryAfter: number;
  /** This refusal paused the hook until then (the Worker writes it to D1 once). */
  pause?: { until: number };
}

/** A paused hook's first pause lasts this long; each repeat doubles it, up to `PAUSE_MAX_MS`. */
export const PAUSE_BASE_MS = 3600_000;
export const PAUSE_MAX_MS = 24 * 3600_000;
/** A hook unpaused (or whose pause ended) this long ago starts again from `PAUSE_BASE_MS`. */
export const PAUSE_FORGET_MS = 24 * 3600_000;
/** A `limit` stream event per scope and hook at most this often (PROTOCOL §6). */
export const LIMIT_NOTICE_MS = 3600_000;
/** `last_event_at` is written to D1 at most this often per hook (the object keeps the exact time). */
export const LAST_EVENT_WRITE_MS = 60_000;

export type AppendResult =
  | { duplicate: true }
  /** The hook's target matches no device that can be sealed to: nothing stored, the hook pauses. */
  | { duplicate: false; full: false; noRecipient: true }
  | { duplicate: false; full: true; scope: FullScope }
  | { duplicate: false; full: false; limited: Refusal }
  /** Past the daily cap on a hook whose policy is `accept_and_drop`: nothing stored, a gap `over_limit`. */
  | { duplicate: false; full: false; dropped: true; seq: number }
  | { duplicate: false; full: false; held: true; id: string; sealedFor: number; notice: false }
  | {
      duplicate: false;
      full: false;
      held?: false;
      seq: number;
      id: string;
      sealedFor: number;
      notice: boolean;
      /** The hook's `last_event_at` in D1 is due a write (at most once a minute per hook). */
      touch?: boolean;
    };

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

/** A change to one of the account's hooks, announced on every device's stream (PROTOCOL §6). */
export interface HookChange {
  kind: "hook.created" | "hook.rotated" | "hook.renamed" | "hook.deleted";
  hookId: string;
  name: string;
  /** The name before a rename. */
  previousName?: string;
  /** The device or API key that made it. */
  actor: string | null;
}

/** Per-hook quota caps, for tests. */
export interface HookQuotas {
  checked: Quota;
  unchecked: Quota;
  held: Quota;
}

/**
 * An append or release between taking its seq (or its share of the quota) and committing: sealing
 * and signing run outside any critical section, so the object keeps taking nonces and acks while
 * they do (PROTOCOL §4). What it reserved counts against the quotas until it commits.
 */
interface Reservation {
  hookId: string;
  held: boolean;
  bytes: number;
  /** `hook_id\nmark` of its replay marks, so a duplicate arriving meanwhile is refused. */
  marks: string[];
  /** `hook_id\nsender mark` of an offline notice it decided to send. */
  notice?: string;
  /** When it was taken (ms): what its counts are dated, and its tokens taken, at commit. */
  at?: number;
  /**
   * A delivery the plan counts (PROTOCOL §2a): one more today for the account and the hook, and a
   * token from each rate's bucket. Written with the commit, in the rows it writes anyway; until then
   * the limits count it from here, so the plan stays exact, and an append lost before its commit
   * (an eviction) was never taken and is never counted.
   */
  count?: { day: number; hook: Rate | null; account: Rate | null };
  /** An append to the log (not held, not a release): the hook's "last seen" moves at commit. */
  seen?: boolean;
  /** D1's `last_event_at` is due a write for this append (at most once a minute per hook). */
  touch?: boolean;
}

/** A token bucket's rate and size (PROTOCOL §2a). */
interface Rate {
  perMin: number;
  burst: number;
}

/** A hook's row in `hook_usage`: its share of the log, today's count, last delivery, and bucket. */
interface HookCounters extends Record<string, SqlStorageValue> {
  events: number;
  bytes: number;
  day: number;
  taken: number;
  last_at: number | null;
  written_at: number;
  tokens: number | null;
  tokens_at: number | null;
}

/** The account's row in `counters`: the head, today's count, and the account's bucket. */
interface AccountCounters extends Record<string, SqlStorageValue> {
  head: number;
  day: number;
  taken: number;
  tokens: number | null;
  tokens_at: number | null;
}

/** Usage changes gathered while deleting, written once per hook when the step ends. */
type UsageDelta = Map<string, Quota>;

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
  stored_at: number | null;
  /** Schema 6's one device; schema 7 moved it into `recipients` and no longer writes it. */
  route: string | null;
  /** The devices the event is for (a JSON array of ids, resolved when it arrived), or null for every device. */
  recipients: string | null;
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
  /** Devices that have acknowledged it (of its recipients, when it has a list). */
  deliveredTo: string[];
  /** The devices it was for, when its hook had a target; null for every device. */
  recipients: string[] | null;
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
  hookQuotaOverride: HookQuotas | null = null;
  /** How many times the schema statements ran in this instance (tests check a wake skips them). */
  schemaRuns = 0;
  private relayKey: Promise<RelayKey | null> | null = null;
  /** Appends and releases in flight (see `Reservation`). */
  private readonly reservations = new Set<Reservation>();
  /** The last seq handed out, while any reservation holds one; null means "the head". */
  private reservedSeq: number | null = null;
  /** Commits happen in seq order: each waits for the one before it. */
  private commitTail: Promise<void> = Promise.resolve();
  /** When audit rows were last pruned (they're pruned at most hourly outside the alarm). */
  private auditPrunedAt = 0;
  /** The plan values last written to `meta`, so an append writes them only when they change. */
  private planKey: string | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    // A wake of an object whose schema is current runs no DDL at all.
    if (this.storedSchema() < SCHEMA_VERSION) {
      this.schemaRuns++;
      for (const stmt of SCHEMA) this.sql.exec(stmt);
      this.migrate();
    }
    // Liveness pings from the Worker are answered without waking the object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  private storedSchema(): number {
    try {
      return this.sql.exec<{ value: number }>("SELECT value FROM meta WHERE key = 'schema'").toArray()[0]?.value ?? 0;
    } catch {
      // No meta table yet: a new object.
      return 0;
    }
  }

  /** Columns and counters added after phase 0, for objects created before them. */
  private migrate(): void {
    const version = this.storedSchema();
    const tryExec = (stmt: string) => {
      try {
        this.sql.exec(stmt);
      } catch {
        // Already there: the table was created with it.
      }
    };
    this.ctx.storage.transactionSync(() => {
      if (version < 3) {
        tryExec("ALTER TABLE events ADD COLUMN strict INTEGER NOT NULL DEFAULT 0");
        tryExec("ALTER TABLE devices ADD COLUMN seal_key BLOB");
        tryExec("ALTER TABLE devices ADD COLUMN seal_kid TEXT");
        // Schema 3: events released from the screen's hold (PROTOCOL §4b).
        tryExec("ALTER TABLE events ADD COLUMN held INTEGER NOT NULL DEFAULT 0");
      }
      // Schema 6: events for one device only (a hook's `deliverTo`). Schema 5 (plans) only adds
      // tables, which SCHEMA creates, so a log already at 5 still needs these columns.
      if (version < 6) {
        tryExec("ALTER TABLE events ADD COLUMN route TEXT");
        tryExec("ALTER TABLE held_events ADD COLUMN route TEXT");
      }
      // Schema 7: events for a list of devices (a hook's recipients), and each device's tags. An
      // event schema 6 routed to one device becomes a one-device list.
      if (version < 7) {
        tryExec("ALTER TABLE events ADD COLUMN recipients TEXT");
        tryExec("ALTER TABLE held_events ADD COLUMN recipients TEXT");
        tryExec("ALTER TABLE devices ADD COLUMN tags TEXT");
        this.sql.exec("UPDATE events SET recipients = json_array(route) WHERE route IS NOT NULL AND recipients IS NULL");
        this.sql.exec("UPDATE held_events SET recipients = json_array(route) WHERE route IS NOT NULL AND recipients IS NULL");
      }
      // Schema 4: retention by when an event entered the log; per-hook quotas; the hold counted
      // apart from the log; long replay marks; hook changes announced to devices. (Schema 5 only
      // adds tables, which SCHEMA creates; schemas 6 and 7 are the route columns above.)
      if (version < 4) this.migrateTo4(tryExec);
      // Schema 8: fewer rows written per webhook (docs/COSTS.md).
      if (version < 8) this.migrateTo8();
      this.sql.exec(
        "INSERT INTO meta (key, value) VALUES ('schema', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        SCHEMA_VERSION,
      );
    });
  }

  private migrateTo4(tryExec: (stmt: string) => void): void {
    {
      tryExec("ALTER TABLE events ADD COLUMN stored_at INTEGER");
      this.sql.exec("UPDATE events SET stored_at = received_at WHERE stored_at IS NULL");
      tryExec("ALTER TABLE devices ADD COLUMN changes_seen INTEGER NOT NULL DEFAULT 0");
      tryExec("ALTER TABLE seen ADD COLUMN long INTEGER NOT NULL DEFAULT 0");
      for (const stmt of SCHEMA_4_INDEXES) this.sql.exec(stmt);
      // The log's counters once included held events: count them again, without.
      this.sql.exec("DELETE FROM meta WHERE key IN ('log_events', 'log_bytes')");
      this.sql.exec("DELETE FROM hook_usage");
      this.sql.exec("INSERT INTO hook_usage (hook_id, events, bytes) SELECT hook_id, count(*), 0 FROM events GROUP BY hook_id");
      this.sql.exec(
        `UPDATE hook_usage SET bytes = (SELECT coalesce(sum(length(e.ct) + ${ENVELOPE_OVERHEAD}), 0)
           FROM envelopes e JOIN events ev ON ev.seq = e.seq WHERE ev.hook_id = hook_usage.hook_id)`,
      );
      this.sql.exec("DELETE FROM held_usage");
      this.sql.exec("INSERT INTO held_usage (hook_id, events, bytes) SELECT hook_id, count(*), 0 FROM held_events GROUP BY hook_id");
      this.sql.exec(
        `UPDATE held_usage SET bytes = (SELECT coalesce(sum(length(e.ct) + ${ENVELOPE_OVERHEAD}), 0)
           FROM held_envelopes e JOIN held_events h ON h.id = e.id WHERE h.hook_id = held_usage.hook_id)`,
      );
    }
  }

  /**
   * Schema 8 drops the indexes no query needs, each a row written with every insert (Cloudflare
   * bills index entries as rows): `events_received`, `events_hook` and `events_route` (no query
   * reads events by arrival time, hook or route; schema 7 stopped writing `route`); `seen_at` (the
   * alarm and its schedule read marks by `long, at`, which `seen_long_at` serves); `envelopes_device`
   * (an ack deletes its device's envelopes by seq range, which `envelopes_seq_device` serves);
   * `held_hook` (dropping a hook's holds scans the hold, at most a few hundred rows per hook);
   * `nonces_at` (a row written per signed request: the hourly alarm scans the nonces, which are
   * at most the last hour's requests, and `ensureAlarm` doesn't read them between alarms).
   */
  private migrateTo8(): void {
    for (const index of ["events_received", "events_hook", "events_route", "seen_at", "envelopes_device", "held_hook", "nonces_at"]) {
      this.sql.exec(`DROP INDEX IF EXISTS ${index}`);
    }
    // Counters that every append wrote as rows of their own now share one row each, written once
    // per append: the account's (`counters`: the head, today's count, the account's bucket, which
    // were rows of `meta`, `daily` and `buckets`) and each hook's (`hook_usage`, which takes in its
    // `daily` count, its `buckets` row and its `hook_seen` row). What the log holds in all is the
    // sum of the hooks' rows, no longer a counter of its own.
    for (const col of [
      "day INTEGER NOT NULL DEFAULT 0",
      "taken INTEGER NOT NULL DEFAULT 0",
      "last_at INTEGER",
      "written_at INTEGER NOT NULL DEFAULT 0",
      "tokens REAL",
      "tokens_at INTEGER",
    ]) {
      try {
        this.sql.exec(`ALTER TABLE hook_usage ADD COLUMN ${col}`);
      } catch {
        // A new object: the table was created with it.
      }
    }
    const head = this.sql.exec<{ value: number }>("SELECT value FROM meta WHERE key = 'head'").toArray()[0]?.value ?? 0;
    this.sql.exec("INSERT INTO counters (id, head) VALUES (1, ?) ON CONFLICT(id) DO NOTHING", head);
    // Each hook's share of the log, counted from the log itself (as `usage()` once did for objects
    // without counters), so the hooks' rows add up to exactly what the log holds. An envelope whose
    // event is gone can never be streamed (it was always deleted with it): it goes now.
    this.sql.exec("DELETE FROM envelopes WHERE seq NOT IN (SELECT seq FROM events)");
    this.sql.exec("UPDATE hook_usage SET events = 0, bytes = 0");
    this.sql.exec(
      `INSERT INTO hook_usage (hook_id, events, bytes)
       SELECT ev.hook_id, count(*), sum(length(ev.body) + length(ev.headers)) + coalesce(sum(
         (SELECT sum(length(e.ct) + ${ENVELOPE_OVERHEAD}) FROM envelopes e WHERE e.seq = ev.seq)), 0)
       FROM events ev GROUP BY ev.hook_id
       ON CONFLICT(hook_id) DO UPDATE SET events = excluded.events, bytes = excluded.bytes`,
    );
    const tables = new Set(this.sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table'").toArray().map((r) => r.name));
    // Today's counts: the newest day kept of each.
    const daily = this.sql
      .exec<{ key: string; day: number; count: number }>(
        "SELECT key, day, count FROM daily d WHERE (key = 'a' OR key LIKE 'h:%') AND day = (SELECT max(day) FROM daily x WHERE x.key = d.key)",
      )
      .toArray();
    for (const d of daily) {
      if (d.key === "a") this.sql.exec("UPDATE counters SET day = ?, taken = ? WHERE id = 1", d.day, d.count);
      else this.upsertHookColumns(d.key.slice(2), "day = ?2, taken = ?3", d.day, d.count);
    }
    this.sql.exec("DELETE FROM daily WHERE key = 'a' OR key LIKE 'h:%'");
    if (tables.has("buckets")) {
      for (const b of this.sql.exec<{ key: string; tokens: number; at: number }>("SELECT key, tokens, at FROM buckets").toArray()) {
        if (b.key === "a") this.sql.exec("UPDATE counters SET tokens = ?, tokens_at = ? WHERE id = 1", b.tokens, b.at);
        else if (b.key.startsWith("h:")) this.upsertHookColumns(b.key.slice(2), "tokens = ?2, tokens_at = ?3", b.tokens, b.at);
      }
      this.sql.exec("DROP TABLE buckets");
    }
    if (tables.has("hook_seen")) {
      for (const h of this.sql.exec<{ hook_id: string; last_at: number; written_at: number }>("SELECT hook_id, last_at, written_at FROM hook_seen").toArray()) {
        this.upsertHookColumns(h.hook_id, "last_at = ?2, written_at = ?3", h.last_at, h.written_at);
      }
      this.sql.exec("DROP TABLE hook_seen");
    }
    this.sql.exec("DELETE FROM meta WHERE key IN ('head', 'log_events', 'log_bytes')");
  }

  /** Sets columns of a hook's row (`set` names them as ?2, ?3), creating the row when it has none. */
  private upsertHookColumns(hookId: string, set: string, a: SqlStorageValue, b: SqlStorageValue): void {
    this.sql.exec(`INSERT INTO hook_usage (hook_id, events, bytes) VALUES (?1, 0, 0) ON CONFLICT(hook_id) DO NOTHING`, hookId);
    this.sql.exec(`UPDATE hook_usage SET ${set} WHERE hook_id = ?1`, hookId, a, b);
  }

  private signingKey(): Promise<RelayKey | null> {
    this.relayKey ??= importRelayKey(this.env.RELAY_SIGNING_KEY);
    return this.relayKey;
  }

  // ── bookkeeping ────────────────────────────────────────────────────────────

  private head(): number {
    return this.accountCounters().head;
  }

  private accountCounters(): AccountCounters {
    return (
      this.sql.exec<AccountCounters>("SELECT head, day, taken, tokens, tokens_at FROM counters WHERE id = 1").toArray()[0] ?? {
        head: 0,
        day: 0,
        taken: 0,
        tokens: null,
        tokens_at: null,
      }
    );
  }

  private hookCounters(hookId: string): HookCounters {
    return (
      this.sql
        .exec<HookCounters>("SELECT events, bytes, day, taken, last_at, written_at, tokens, tokens_at FROM hook_usage WHERE hook_id = ?", hookId)
        .toArray()[0] ?? { events: 0, bytes: 0, day: 0, taken: 0, last_at: null, written_at: 0, tokens: null, tokens_at: null }
    );
  }

  private quota(): Quota {
    if (this.quotaOverride) return this.quotaOverride;
    // The plan's backlog (PROTOCOL §2a), as the last delivery passed it; the settings otherwise.
    const plan = this.planMeta();
    return {
      events: plan.backlogEvents ?? positive(this.env.ACCOUNT_MAX_EVENTS, DEFAULT_MAX_EVENTS),
      bytes: plan.backlogBytes ?? positive(this.env.ACCOUNT_MAX_BYTES, DEFAULT_MAX_BYTES),
    };
  }

  /** The plan values kept in `meta` (retention and backlog), so the alarm and releases use them too. */
  private planMeta(): { retentionMs: number | null; backlogEvents: number | null; backlogBytes: number | null } {
    const rows = this.sql
      .exec<{ key: string; value: number }>(
        "SELECT key, value FROM meta WHERE key IN ('plan_retention_ms', 'plan_backlog_events', 'plan_backlog_bytes')",
      )
      .toArray();
    const get = (k: string) => rows.find((r) => r.key === k)?.value ?? null;
    return { retentionMs: get("plan_retention_ms"), backlogEvents: get("plan_backlog_events"), backlogBytes: get("plan_backlog_bytes") };
  }

  /** Keeps the plan's retention and backlog in `meta`, writing only when they changed. */
  private notePlan(plan: PlanInput): void {
    const want: [string, number | null][] = [
      ["plan_retention_ms", plan.retentionHours === null ? null : Math.max(plan.retentionHours, 1) * 3600_000],
      ["plan_backlog_events", plan.backlogEvents === null ? null : Math.max(1, plan.backlogEvents)],
      ["plan_backlog_bytes", plan.backlogBytes === null ? null : Math.max(1, plan.backlogBytes)],
      ["plan_expired", plan.expired ? 1 : null],
    ];
    const key = JSON.stringify(want);
    if (this.planKey === key) return;
    // After a wake the cache is empty: compare with what is stored, so a wake costs no write.
    const stored = new Map(
      this.sql
        .exec<{ key: string; value: number }>(
          "SELECT key, value FROM meta WHERE key IN ('plan_retention_ms', 'plan_backlog_events', 'plan_backlog_bytes', 'plan_expired')",
        )
        .toArray()
        .map((r) => [r.key, r.value]),
    );
    const had = stored.get("plan_expired") ?? null;
    for (const [k, v] of want) {
      if ((stored.get(k) ?? null) === v) continue;
      if (v === null) this.sql.exec("DELETE FROM meta WHERE key = ?", k);
      else this.sql.exec("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", k, v);
    }
    // The plan came back: its `plan_expired` notice no longer holds.
    if (had !== null && !plan.expired) this.sql.exec("DELETE FROM limit_notices WHERE scope = 'plan_expired'");
    this.planKey = key;
  }

  /** One hook's caps: its share of the log (by whether the relay verifies it) and of the hold. */
  private hookQuotas(): HookQuotas {
    if (this.hookQuotaOverride) return this.hookQuotaOverride;
    const q = this.quota();
    const share = (n: number, by: number) => Math.max(1, Math.floor(n / by));
    return {
      checked: {
        events: positive(this.env.HOOK_MAX_EVENTS, share(q.events, HOOK_SHARE)),
        bytes: positive(this.env.HOOK_MAX_BYTES, share(q.bytes, HOOK_SHARE)),
      },
      unchecked: {
        events: positive(this.env.UNCHECKED_HOOK_MAX_EVENTS, share(q.events, UNCHECKED_HOOK_SHARE)),
        bytes: positive(this.env.UNCHECKED_HOOK_MAX_BYTES, share(q.bytes, UNCHECKED_HOOK_SHARE)),
      },
      held: {
        events: positive(this.env.HELD_MAX_EVENTS, DEFAULT_HELD_MAX_EVENTS),
        bytes: positive(this.env.HELD_MAX_BYTES, DEFAULT_HELD_MAX_BYTES),
      },
    };
  }

  private replayMarkMs(): number {
    return positive(this.env.REPLAY_MARK_DAYS, DEFAULT_REPLAY_MARK_DAYS) * 24 * 3600_000;
  }

  /** What one hook holds in the log, or in the hold. */
  private hookUsage(table: "hook_usage" | "held_usage", hookId: string): Quota {
    const r = this.sql.exec<{ events: number; bytes: number }>(`SELECT events, bytes FROM ${table} WHERE hook_id = ?`, hookId).toArray()[0];
    return { events: r?.events ?? 0, bytes: r?.bytes ?? 0 };
  }

  /**
   * Adds (or with negative numbers, removes) to one hook's counters: in the log (its row keeps its
   * other counters, so it stays), or in the hold (dropping rows that reach zero).
   */
  private addHookUsage(table: "hook_usage" | "held_usage", hookId: string, events: number, bytes: number): void {
    this.sql.exec(
      `INSERT INTO ${table} (hook_id, events, bytes) VALUES (?1, max(?2, 0), max(?3, 0))
       ON CONFLICT(hook_id) DO UPDATE SET events = max(events + ?2, 0), bytes = max(bytes + ?3, 0)`,
      hookId,
      events,
      bytes,
    );
    if (table === "held_usage") this.sql.exec(`DELETE FROM held_usage WHERE hook_id = ? AND events = 0 AND bytes = 0`, hookId);
  }

  /** Writes what a step's deletes took from each hook's share of the log: one write per hook. */
  private applyUsage(delta: UsageDelta): void {
    for (const [hookId, d] of delta) if (d.events !== 0 || d.bytes !== 0) this.addHookUsage("hook_usage", hookId, d.events, d.bytes);
  }

  /** Everything the hold has, across hooks. */
  private heldTotal(): Quota {
    const r = this.sql.exec<{ e: number | null; b: number | null }>("SELECT sum(events) AS e, sum(bytes) AS b FROM held_usage").one();
    return { events: r.e ?? 0, bytes: r.b ?? 0 };
  }

  /** What appends and releases in flight have reserved: in all, and for one hook. */
  private reserved(held: boolean, hookId: string): { all: Quota; hook: Quota } {
    const all = { events: 0, bytes: 0 };
    const hook = { events: 0, bytes: 0 };
    for (const r of this.reservations) {
      if (r.held !== held) continue;
      all.events++;
      all.bytes += r.bytes;
      if (r.hookId === hookId) {
        hook.events++;
        hook.bytes += r.bytes;
      }
    }
    return { all, hook };
  }

  /**
   * Whether one more event of `bytes` fits: in the log (the account's quota and the hook's share of
   * it), or in the hold (the hook's own hold quota, and the account's quota again, apart from the
   * log). Null when it fits; otherwise the quota it doesn't fit in.
   */
  private refuses(hookId: string, bytes: number, kind: { held: boolean; checked: boolean }): FullScope | null {
    const q = this.quota();
    const caps = this.hookQuotas();
    const pending = this.reserved(kind.held, hookId);
    const over = (u: Quota, p: Quota, cap: Quota) => u.events + p.events + 1 > cap.events || u.bytes + p.bytes + bytes > cap.bytes;
    if (kind.held) {
      if (over(this.hookUsage("held_usage", hookId), pending.hook, caps.held)) return "held";
      if (over(this.heldTotal(), pending.all, q)) return "held";
      return null;
    }
    if (over(this.usage(), pending.all, q)) return "account";
    if (over(this.hookUsage("hook_usage", hookId), pending.hook, kind.checked ? caps.checked : caps.unchecked)) return "hook";
    return null;
  }

  /**
   * What the log holds: events, and bytes (envelopes, plus any legacy body and headers): the sum of
   * the hooks' counters, which every append, release and delete keeps exact, so an append doesn't
   * scan the log and a delete writes one row per hook rather than another for the account.
   */
  private usage(): Quota {
    const r = this.sql.exec<{ e: number | null; b: number | null }>("SELECT sum(events) AS e, sum(bytes) AS b FROM hook_usage").one();
    return { events: r.e ?? 0, bytes: r.b ?? 0 };
  }

  /**
   * Deletes envelopes matching `where` (written against the alias `e`), adding what they held to
   * `delta` for the caller to write once (`applyUsage`).
   */
  private deleteEnvelopes(delta: UsageDelta, where: string, ...args: SqlStorageValue[]): void {
    const groups = this.sql
      .exec<{ h: string | null; b: number | null }>(
        `SELECT ev.hook_id AS h, sum(length(e.ct) + ${ENVELOPE_OVERHEAD}) AS b
         FROM envelopes e LEFT JOIN events ev ON ev.seq = e.seq WHERE ${where} GROUP BY ev.hook_id`,
        ...args,
      )
      .toArray();
    if (groups.length === 0) return;
    this.sql.exec(`DELETE FROM envelopes AS e WHERE ${where}`, ...args);
    for (const g of groups) if (g.h !== null) addDelta(delta, g.h, 0, -(g.b ?? 0));
  }

  /** Deletes the events with seq in [lo, hi] and their envelopes, adding what they held to `delta`. */
  private deleteRange(delta: UsageDelta, lo: number, hi: number): void {
    this.deleteEnvelopes(delta, "e.seq BETWEEN ? AND ?", lo, hi);
    const groups = this.sql
      .exec<{ h: string; n: number; b: number | null }>(
        `SELECT hook_id AS h, count(*) AS n, sum(length(body) + length(headers)) AS b FROM events
         WHERE seq BETWEEN ? AND ? GROUP BY hook_id`,
        lo,
        hi,
      )
      .toArray();
    if (groups.length === 0) return;
    this.sql.exec("DELETE FROM events WHERE seq BETWEEN ? AND ?", lo, hi);
    // An event row's own bytes (its empty headers and body) were counted with it.
    for (const g of groups) addDelta(delta, g.h, -g.n, -(g.b ?? 0));
  }

  private retentionMs(): number {
    const plan = this.planMeta().retentionMs;
    if (plan !== null) return Math.max(plan, 3600_000);
    const days = Number(this.env.RETENTION_DAYS);
    return (Number.isFinite(days) && days > 0 ? Math.max(days, 1 / 24) : 7) * 24 * 3600_000;
  }

  /**
   * Makes sure a device row exists; a new device starts at the head (it never saw older events) and
   * after the last hook change (it is told only of changes made once it existed).
   */
  private ensureDevice(deviceId: string): { acked: number; revoked: boolean; sealKid: string | null } {
    this.sql.exec(
      `INSERT INTO devices (id, acked, revoked, changes_seen)
       VALUES (?, ?, 0, (SELECT coalesce(max(n), 0) FROM hook_changes)) ON CONFLICT(id) DO NOTHING`,
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
          "SELECT count(*) AS n FROM nonces WHERE device_id = ? AND nonce = ? AND at >= ?",
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
    if (ok) await this.ensureAlarm(false, now);
    return ok;
  }

  private isDuplicate(hookId: string, keys: string[]): boolean {
    for (const key of keys) {
      const seen = this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM seen WHERE hook_id = ? AND key = ?", hookId, key).one().n;
      if (seen > 0) return true;
    }
    for (const r of this.reservations) {
      for (const key of keys) if (r.marks.includes(`${hookId}\n${key}`)) return true;
    }
    return false;
  }

  /** Takes the next seq for an append or release; it commits in this order (see `inOrder`). */
  private takeSeq(): number {
    const seq = (this.reservedSeq ?? this.head()) + 1;
    this.reservedSeq = seq;
    return seq;
  }

  /**
   * Runs `commit` after every commit that took an earlier seq, so the log is always written in seq
   * order however long each one's sealing took. `work` (sealing, signing) runs at once, concurrently
   * with other requests; only `commit`, a synchronous transaction, is serialised.
   */
  private async inOrder<T>(work: () => Promise<T>, commit: (t: T) => void): Promise<void> {
    const before = this.commitTail;
    let done!: () => void;
    this.commitTail = new Promise<void>((resolve) => (done = resolve));
    try {
      const t = await work();
      await before;
      commit(t);
    } finally {
      done();
    }
  }

  /** Ends a reservation; once none holds a seq, the head is read from storage again. */
  private release(r: Reservation): void {
    this.reservations.delete(r);
    if (![...this.reservations].some((x) => !x.held)) this.reservedSeq = null;
  }

  /** Writes replay marks: long ones for `REPLAY_MARK_DAYS`, the rest for a week. */
  private writeMarks(input: AppendInput): void {
    const long = new Set(input.longKeys ?? []);
    for (const key of new Set(input.dedupeKeys)) {
      this.sql.exec(
        "INSERT INTO seen (hook_id, key, at, long) VALUES (?, ?, ?, ?) ON CONFLICT(hook_id, key) DO NOTHING",
        input.hookId,
        key,
        input.receivedAt,
        long.has(key) ? 1 : 0,
      );
    }
  }

  /** The active devices with a sealing key, in id order, with their tags. */
  private sealingDevices(): SealingDevice[] {
    return this.sql
      .exec<{ id: string; seal_key: ArrayBuffer; seal_kid: string; tags: string | null }>(
        "SELECT id, seal_key, seal_kid, tags FROM devices WHERE revoked = 0 AND seal_key IS NOT NULL ORDER BY id",
      )
      .toArray()
      .map((d) => ({ id: d.id, seal_key: d.seal_key, seal_kid: d.seal_kid, tags: jsonList(d.tags) }));
  }

  /**
   * Who an event is sealed to: every active device with a sealing key, or, for a hook with a target,
   * the devices it lists and those carrying one of its tags (`recipients`, kept with the event so its
   * acknowledgements and pruning follow those devices alone). Held events too: a device that isn't a
   * recipient never gets an envelope it could open. Null when a target matches no device that can be
   * sealed to: the delivery is refused rather than sealed to nobody or to everyone.
   */
  private routeTo(target: AppendInput["recipients"]): { devices: SealingDevice[]; recipients: string[] | null } | null {
    const all = this.sealingDevices();
    if (!target) return { devices: all, recipients: null };
    const chosen = all.filter((d) => target.devices.includes(d.id) || d.tags.some((t) => target.tags.includes(t)));
    if (chosen.length === 0) return null;
    return { devices: chosen, recipients: chosen.map((d) => d.id) };
  }

  /**
   * A delivery whose hook's target matches nobody: counted on the `limit` notice of scope
   * `no_recipient`, and, the first time, an audit line `hook.paused` and the notice sent to every
   * stream at once. The Worker writes the pause to D1 and answers later deliveries from there.
   */
  private noRecipient(hookId: string, plan: string, now: number): AppendResult {
    const paused =
      this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM limit_notices WHERE scope = 'no_recipient' AND hook_id = ?", hookId).one().n > 0;
    if (!paused) {
      this.pruneAudit(now);
      this.sql.exec("INSERT INTO audit (at, kind, actor, subject, name) VALUES (?, 'hook.paused', NULL, ?, 'no_recipient')", now, hookId);
    }
    this.noteLimit("no_recipient", hookId, null, plan, now, !paused);
    return { duplicate: false, full: false, noRecipient: true };
  }

  /**
   * The Worker found a hook's target matches nobody any more (`paused`), or matches again: the
   * audit says so, and the `limit` notice of scope `no_recipient` is sent at once, or forgotten.
   */
  async recipientPause(hookId: string, paused: boolean, actor: string | null, plan: string): Promise<void> {
    const now = Date.now();
    const had =
      this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM limit_notices WHERE scope = 'no_recipient' AND hook_id = ?", hookId).one().n > 0;
    if (paused === had) return;
    this.pruneAudit(now);
    if (paused) {
      this.sql.exec("INSERT INTO audit (at, kind, actor, subject, name) VALUES (?, 'hook.paused', ?, ?, 'no_recipient')", now, actor, hookId);
      // A pause noticed before any delivery was refused: nothing refused yet.
      this.sql.exec(
        `INSERT INTO limit_notices (scope, hook_id, refused, since, until, plan, sent_at) VALUES ('no_recipient', ?1, 0, ?2, NULL, ?3, ?2)
         ON CONFLICT(scope, hook_id) DO NOTHING`,
        hookId,
        now,
        plan,
      );
      const msg = JSON.stringify(limitMessage({ scope: "no_recipient", hookId, refused: 0, since: now, until: null, plan }));
      for (const ws of this.ctx.getWebSockets()) if (ws.readyState === WebSocket.OPEN) this.trySend(ws, msg);
    } else {
      this.sql.exec("DELETE FROM limit_notices WHERE scope = 'no_recipient' AND hook_id = ?", hookId);
      this.sql.exec("INSERT INTO audit (at, kind, actor, subject, name) VALUES (?, 'hook.unpaused', ?, ?, 'no_recipient')", now, actor, hookId);
    }
  }

  /** Sets a device's tags (PROTOCOL §2), which hooks' targets match against from the next event on. */
  async setDeviceTags(deviceId: string, tags: string[]): Promise<void> {
    this.ensureDevice(deviceId);
    this.sql.exec("UPDATE devices SET tags = ? WHERE id = ?", tags.length > 0 ? JSON.stringify(tags) : null, deviceId);
  }

  /** Devices revoked since `ids` were read (their envelopes are left out at commit). */
  private revokedAmong(ids: string[]): Set<string> {
    if (ids.length === 0) return new Set();
    return new Set(
      this.sql.exec<{ id: string }>("SELECT id FROM devices WHERE revoked = 1").toArray().map((r) => r.id).filter((id) => ids.includes(id)),
    );
  }

  /**
   * Appends one event: seals its content to every active device with a sealing key (HPKE, with the
   * hook, seq and id as associated data), signs each envelope, and writes the event, its envelopes
   * and its dedupe marks in one transaction; then delivers it live. Refuses (`full`) when the
   * account's log, the hook's share of it, or (for a held event) the hook's hold is at its quota.
   *
   * The seq must be known before sealing (it is in the associated data), so it is taken first, with
   * the quota the event needs, in a synchronous step; the sealing then runs without blocking the
   * object (nonces and acks go on being served), and the commits are written in seq order.
   */
  async append(input: AppendInput): Promise<AppendResult> {
    const relay = await this.signingKey();
    if (!relay) throw new Error("RELAY_SIGNING_KEY is missing or malformed");
    // ── synchronous: decide, and reserve (nothing else runs until the first await) ──
    if (this.isDuplicate(input.hookId, input.dedupeKeys)) return { duplicate: true };
    const now = Date.now();
    const held = input.held !== undefined;
    // Who it is for, before any limit counts it: a delivery nobody can receive takes nothing.
    const routed = this.routeTo(input.recipients);
    if (!routed) return this.noRecipient(input.hookId, input.plan?.name ?? "default", now);
    const { devices } = routed;
    const recipients = routed.recipients === null ? null : JSON.stringify(routed.recipients);
    if (input.plan) {
      this.notePlan(input.plan);
      // The plan's limits, before the backlog quota: nothing is counted unless all of them pass.
      const refusal = this.limitRefusal(input.hookId, input.plan, now);
      if (refusal) {
        if (refusal.scope === "daily" && input.onLimit === "accept_and_drop" && !held) return this.dropOverLimit(input.hookId, input.plan, now);
        return { duplicate: false, full: false, limited: this.refused(input.hookId, input.plan, refusal, now) };
      }
    }
    let plaintext: Uint8Array | null = encodeContent({ ...input.content, body: input.body });
    const estimate = devices.length * (plaintext.byteLength + 16 + ENVELOPE_OVERHEAD) + 2;
    const scope = this.refuses(input.hookId, estimate, { held, checked: input.verified && !input.strict });
    if (scope) {
      plaintext.fill(0);
      return { duplicate: false, full: true, scope };
    }
    const reservation: Reservation = {
      hookId: input.hookId,
      held,
      bytes: estimate,
      marks: input.dedupeKeys.map((k) => `${input.hookId}\n${k}`),
    };
    // Decided before sealing, so the devices read that the sender was answered.
    const notice = !held && input.notice ? this.noticeDue(input.hookId, input.notice, input.receivedAt) : false;
    if (notice) {
      reservation.notice = `${input.hookId}\n${input.notice!.mark}`;
      plaintext.fill(0);
      plaintext = encodeContent({ ...input.content, notice: true, body: input.body });
    }
    const id = newId("evt");
    const seq = held ? 0 : this.takeSeq();
    // Taken: it counts against the plan's buckets and today's counters, and the hook was seen. The
    // counts are written with the commit; the limits count the reservation until then.
    reservation.at = now;
    if (input.plan) reservation.count = planCount(input.plan, now);
    reservation.seen = !held;
    const touch = held ? false : this.touchDue(input.hookId, now);
    reservation.touch = touch;
    this.reservations.add(reservation);

    try {
      if (held) {
        const sealed: Omit<SealedEnvelope, "sig">[] = [];
        for (const d of devices) {
          const e = await sealHeld({ deviceId: d.id, kid: d.seal_kid, publicKey: new Uint8Array(d.seal_key) }, input.hookId, id, plaintext).catch(() => null);
          if (e) sealed.push(e);
        }
        plaintext.fill(0);
        plaintext = null;
        const revoked = this.revokedAmong(sealed.map((e) => e.deviceId));
        let bytes = 2;
        this.ctx.storage.transactionSync(() => {
          this.writeMarks(input);
          this.sql.exec(
            `INSERT INTO held_events (id, hook_id, received_at, verified, strict, preset, event_type, rule, recipients)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            id,
            input.hookId,
            input.receivedAt,
            input.verified ? 1 : 0,
            input.strict ? 1 : 0,
            input.preset,
            input.eventType,
            input.held!,
            recipients,
          );
          for (const e of sealed) {
            if (revoked.has(e.deviceId)) continue;
            this.sql.exec("INSERT INTO held_envelopes (id, device_id, kid, enc, ct) VALUES (?, ?, ?, ?, ?)", id, e.deviceId, e.kid, e.enc, e.ct);
            bytes += e.ct.byteLength + ENVELOPE_OVERHEAD;
          }
          // The hold is counted apart from the log: a held flood can't refuse the hook's deliveries.
          this.addHookUsage("held_usage", input.hookId, 1, bytes);
          this.commitCounts(reservation, null, null);
        });
        await this.ensureAlarm();
        return { duplicate: false, full: false, held: true, id, sealedFor: sealed.length - revoked.size, notice: false };
      }

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
      let sealedFor = 0;
      await this.inOrder(
        async () => {
          const envelopes: SealedEnvelope[] = [];
          for (const d of devices) {
            // A device whose key can't be sealed to gets a `no_key` gap for this event, as one
            // without a key does; it never fails the delivery for every other device.
            const e = await sealEnvelope(relay, { deviceId: d.id, kid: d.seal_kid, publicKey: new Uint8Array(d.seal_key) }, meta, plaintext!).catch(
              () => null,
            );
            if (e) envelopes.push(e);
          }
          // The plaintext is no longer needed; nothing below may see it.
          plaintext!.fill(0);
          plaintext = null;
          return envelopes;
        },
        (envelopes) => {
          const revoked = this.revokedAmong(envelopes.map((e) => e.deviceId));
          let bytes = 2;
          this.ctx.storage.transactionSync(() => {
            this.writeMarks(input);
            if (notice) {
              this.sql.exec(
                "INSERT INTO notices (hook_id, mark, at) VALUES (?, ?, ?) ON CONFLICT(hook_id, mark) DO UPDATE SET at = excluded.at",
                input.hookId,
                input.notice!.mark,
                input.receivedAt,
              );
            }
            // Routing metadata only: the body and headers columns stay empty (they held plaintext in
            // phase 0, and are kept so older rows still read).
            this.sql.exec(
              `INSERT INTO events (seq, id, hook_id, received_at, verified, strict, preset, event_type, content_type, headers, body, stored_at, recipients)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, '{}', x'', ?, ?)`,
              seq,
              id,
              input.hookId,
              input.receivedAt,
              input.verified ? 1 : 0,
              input.strict ? 1 : 0,
              input.preset,
              input.eventType,
              Date.now(),
              recipients,
            );
            for (const e of envelopes) {
              if (revoked.has(e.deviceId)) continue;
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
              sealedFor++;
            }
            // The head, the hook's share of the log, today's counts, buckets and "last seen": two rows.
            this.commitCounts(reservation, { events: 1, bytes }, seq);
          });
          this.deliverLive(seq);
        },
      );
      await this.ensureAlarm();
      return { duplicate: false, full: false, seq, id, sealedFor, notice, touch };
    } finally {
      plaintext?.fill(0);
      this.release(reservation);
    }
  }

  // ── plans: rates, daily caps, pauses and notices (PROTOCOL §2a) ────────────

  /** Reservations the plan counts that haven't committed yet, matching `which`. */
  private pending(which: (r: Reservation) => boolean): number {
    let n = 0;
    for (const r of this.reservations) if (r.count && which(r)) n++;
    return n;
  }

  /** Deliveries the account has taken today: committed, and in flight. */
  private takenToday(day: number): number {
    const a = this.accountCounters();
    return (a.day === day ? a.taken : 0) + this.pending((r) => r.count!.day === day);
  }

  /** Counts refusals and drops (`ar`, `r:<hook>`, `ad`) for the day: rare, so rows of their own. */
  private addDaily(key: string, day: number, n = 1): void {
    if (this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM daily WHERE day = ?", day).one().n === 0) {
      // The first count of a new UTC day: yesterday's are of no more use.
      this.sql.exec("DELETE FROM daily WHERE day < ?", day);
    }
    this.sql.exec(
      "INSERT INTO daily (key, day, count) VALUES (?, ?, ?) ON CONFLICT(key, day) DO UPDATE SET count = count + excluded.count",
      key,
      day,
      n,
    );
  }

  /**
   * Whether the plan refuses one more delivery to `hookId` now, without counting anything: an
   * expired plan that takes nothing, the account's daily cap, then the hook's and the account's
   * token buckets. Null when every limit passes. Deliveries taken but not yet committed count as
   * taken, so the limits are exactly what they were when each was counted as it was taken.
   */
  private limitRefusal(hookId: string, plan: PlanInput, now: number): Omit<Refusal, "pause"> | null {
    const day = utcDay(now);
    if (plan.eventsPerDay !== null && this.takenToday(day) >= plan.eventsPerDay) {
      // A plan that takes nothing at all is a lapsed entitlement's fallback (or a suspension).
      if (plan.eventsPerDay === 0 && plan.expired) return { error: "quota", scope: "plan_expired", retryAfter: PLAN_EXPIRED_RETRY_S };
      return { error: "quota", scope: "daily", retryAfter: secondsUntilDay(day + 1, now) };
    }
    const check = (stored: { tokens: number | null; tokens_at: number | null }, rate: Rate | null, inFlight: number, scope: LimitScope) => {
      if (!rate) return null;
      const tokens = refill(stored, rate, now) - inFlight;
      if (tokens >= 1) return null;
      return { error: "rate_limited" as const, scope, retryAfter: Math.max(1, Math.ceil(((1 - tokens) * 60_000) / rate.perMin / 1000)) };
    };
    const count = planCount(plan, now);
    return (
      check(this.hookCounters(hookId), count.hook, this.pending((r) => r.hookId === hookId && r.count!.hook !== null), "hook_rate") ??
      check(this.accountCounters(), count.account, this.pending((r) => r.count!.account !== null), "account_rate")
    );
  }

  /** Whether D1's `last_event_at` is due a write for a delivery to `hookId` now (once a minute). */
  private touchDue(hookId: string, now: number): boolean {
    for (const r of this.reservations) if (r.hookId === hookId && r.touch) return false;
    return now - this.hookCounters(hookId).written_at >= LAST_EVENT_WRITE_MS;
  }

  /**
   * Writes what a committed append, hold or release changes, in one row for the hook and one for
   * the account: the hook's share of the log (`add`), the head (`head`), today's counts and a token
   * from each bucket (a counted delivery), and the hook's "last seen" (an append to the log). Runs
   * inside the commit's transaction, so the counts are exactly the commits.
   */
  private commitCounts(r: Reservation, add: Quota | null, head: number | null): void {
    const c = r.count;
    const at = r.at ?? Date.now();
    if (add || c || r.seen) {
      const h = this.hookCounters(r.hookId);
      if (add) {
        h.events = Math.max(0, h.events + add.events);
        h.bytes = Math.max(0, h.bytes + add.bytes);
      }
      if (c) {
        [h.day, h.taken] = countDay(h.day, h.taken, c.day);
        if (c.hook) [h.tokens, h.tokens_at] = take(h, c.hook, at);
      }
      if (r.seen) {
        h.last_at = at;
        if (r.touch) h.written_at = at;
      }
      this.sql.exec(
        `INSERT INTO hook_usage (hook_id, events, bytes, day, taken, last_at, written_at, tokens, tokens_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(hook_id) DO UPDATE SET events = ?2, bytes = ?3, day = ?4, taken = ?5, last_at = ?6, written_at = ?7,
           tokens = ?8, tokens_at = ?9`,
        r.hookId,
        h.events,
        h.bytes,
        h.day,
        h.taken,
        h.last_at,
        h.written_at,
        h.tokens,
        h.tokens_at,
      );
    }
    if (head !== null || c) {
      const a = this.accountCounters();
      if (head !== null) a.head = head;
      if (c) {
        [a.day, a.taken] = countDay(a.day, a.taken, c.day);
        if (c.account) [a.tokens, a.tokens_at] = take(a, c.account, at);
      }
      this.sql.exec(
        `INSERT INTO counters (id, head, day, taken, tokens, tokens_at) VALUES (1, ?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET head = ?1, day = ?2, taken = ?3, tokens = ?4, tokens_at = ?5`,
        a.head,
        a.day,
        a.taken,
        a.tokens,
        a.tokens_at,
      );
    }
  }

  /**
   * Records a refusal: counted for the day, noted for the `limit` stream event, and counted towards
   * pausing the hook. Past `pauseAfter` refusals in `pauseWindowMs`, the hook is paused for an hour,
   * twice as long each time it is paused again (up to a day), and the audit says so; the Worker
   * writes the pause to D1 and answers from there without waking this object.
   */
  private refused(hookId: string, plan: PlanInput, r: Omit<Refusal, "pause">, now: number): Refusal {
    this.addDaily("ar", utcDay(now));
    this.addDaily(`r:${hookId}`, utcDay(now));
    const until = r.scope === "plan_expired" ? null : now + r.retryAfter * 1000;
    this.noteLimit(r.scope, r.scope === "hook_rate" ? hookId : "", until, plan.name, now);
    if (plan.pauseAfter <= 0) return r;
    const row = this.sql
      .exec<{ window_start: number; count: number; level: number; paused_until: number | null }>(
        "SELECT window_start, count, level, paused_until FROM refusals WHERE hook_id = ?",
        hookId,
      )
      .toArray()[0] ?? { window_start: now, count: 0, level: 0, paused_until: null };
    let { window_start, count, level, paused_until } = row;
    if (now - window_start > plan.pauseWindowMs) {
      window_start = now;
      count = 0;
    }
    count++;
    let pause: { until: number } | undefined;
    if (count >= plan.pauseAfter && !(paused_until !== null && paused_until > now)) {
      if (paused_until === null || now - paused_until > PAUSE_FORGET_MS) level = 0;
      const ms = Math.min(PAUSE_BASE_MS * 2 ** Math.min(level, 10), PAUSE_MAX_MS);
      level++;
      paused_until = now + ms;
      window_start = now;
      count = 0;
      pause = { until: paused_until };
      this.sql.exec("INSERT INTO audit (at, kind, actor, subject, name) VALUES (?, 'hook.paused', NULL, ?, ?)", now, hookId, r.scope);
      this.noteLimit("paused", hookId, paused_until, plan.name, now, true);
    }
    this.sql.exec(
      `INSERT INTO refusals (hook_id, window_start, count, level, paused_until) VALUES (?1, ?2, ?3, ?4, ?5)
       ON CONFLICT(hook_id) DO UPDATE SET window_start = ?2, count = ?3, level = ?4, paused_until = ?5`,
      hookId,
      window_start,
      count,
      level,
      paused_until,
    );
    return pause ? { ...r, pause } : r;
  }

  /**
   * Past the daily cap on an `accept_and_drop` hook: the sender gets `200`, nothing is stored, and
   * the seq the event would have had becomes a gap with the reason `over_limit` (joined to the
   * previous one when nothing was stored between), so the devices hear what they missed.
   */
  private async dropOverLimit(hookId: string, plan: PlanInput, now: number): Promise<AppendResult> {
    this.addDaily("ad", utcDay(now));
    this.noteLimit("daily", "", now + secondsUntilDay(utcDay(now) + 1, now) * 1000, plan.name, now);
    const seq = this.takeSeq();
    const reservation: Reservation = { hookId, held: false, bytes: 0, marks: [] };
    this.reservations.add(reservation);
    try {
      await this.inOrder(
        async () => null,
        () => {
          this.ctx.storage.transactionSync(() => {
            const last = this.sql
              .exec<{ rowid: number; to_seq: number; reason: string }>("SELECT rowid, to_seq, reason FROM pruned ORDER BY to_seq DESC LIMIT 1")
              .toArray()[0];
            if (last && last.reason === "over_limit" && last.to_seq === seq - 1) {
              this.sql.exec("UPDATE pruned SET to_seq = ? WHERE rowid = ?", seq, last.rowid);
            } else {
              this.sql.exec("INSERT INTO pruned (from_seq, to_seq, reason) VALUES (?, ?, 'over_limit')", seq, seq);
            }
            this.sql.exec("UPDATE counters SET head = ? WHERE id = 1", seq);
          });
        },
      );
    } finally {
      this.release(reservation);
    }
    return { duplicate: false, full: false, dropped: true, seq };
  }

  /**
   * Notes a refusal for the `limit` stream event (PROTOCOL §6): one row per scope and hook, counting
   * the refusals since the limit began to bite. Every device's stream is sent it at most once an
   * hour per scope and hook (`force`: now, as when a hook is paused), and again after `ready`.
   */
  private noteLimit(scope: LimitNotice["scope"], hookId: string, until: number | null, plan: string, now: number, force = false): void {
    const r = this.sql
      .exec<{ refused: number; since: number; until: number | null; sent_at: number }>(
        "SELECT refused, since, until, sent_at FROM limit_notices WHERE scope = ? AND hook_id = ?",
        scope,
        hookId,
      )
      .toArray()[0];
    // A limit that had lifted begins again: count from now.
    const fresh = !r || (r.until !== null && r.until <= now);
    const refused = (fresh ? 0 : r.refused) + (scope === "paused" ? 0 : 1);
    const since = fresh ? now : r.since;
    const due = force || !r || now - r.sent_at >= LIMIT_NOTICE_MS;
    const sentAt = due ? now : r!.sent_at;
    this.sql.exec(
      `INSERT INTO limit_notices (scope, hook_id, refused, since, until, plan, sent_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
       ON CONFLICT(scope, hook_id) DO UPDATE SET refused = ?3, since = ?4, until = ?5, plan = ?6, sent_at = ?7`,
      scope,
      hookId,
      refused,
      since,
      until,
      plan,
      sentAt,
    );
    if (!due) return;
    const msg = JSON.stringify(limitMessage({ scope, hookId, refused, since, until, plan }));
    for (const ws of this.ctx.getWebSockets()) {
      if (ws.readyState === WebSocket.OPEN) this.trySend(ws, msg);
    }
  }

  /** After `ready`: the newest notices still in effect, so a device that reconnects hears of them. */
  private sendLimits(ws: WebSocket): boolean {
    const rows = this.sql
      .exec<{ scope: LimitNotice["scope"]; hook_id: string; refused: number; since: number; until: number | null; plan: string }>(
        "SELECT scope, hook_id, refused, since, until, plan FROM limit_notices WHERE until IS NULL OR until > ? ORDER BY since DESC LIMIT 10",
        Date.now(),
      )
      .toArray();
    for (const r of rows) {
      if (!this.trySend(ws, JSON.stringify(limitMessage({ ...r, hookId: r.hook_id })))) return false;
    }
    return true;
  }

  /**
   * A device unpaused the hook (PROTOCOL §3): its refusal window starts again, and the next pause
   * doubles from this one unless a day passes first.
   */
  async hookUnpaused(hookId: string, actor: string): Promise<void> {
    const now = Date.now();
    this.sql.exec("UPDATE refusals SET count = 0, window_start = ?1, paused_until = min(coalesce(paused_until, ?1), ?1) WHERE hook_id = ?2", now, hookId);
    this.sql.exec("DELETE FROM limit_notices WHERE scope = 'paused' AND hook_id = ?", hookId);
    this.pruneAudit(now);
    this.sql.exec("INSERT INTO audit (at, kind, actor, subject, name) VALUES (?, 'hook.unpaused', ?, ?, NULL)", now, actor, hookId);
  }

  /** The plan was set or refreshed (PROTOCOL §2b): an expired plan's notice no longer holds. */
  async planChanged(): Promise<void> {
    this.sql.exec("DELETE FROM limit_notices WHERE scope = 'plan_expired'");
    this.sql.exec("DELETE FROM meta WHERE key = 'plan_expired'");
    this.planKey = null;
  }

  /** Today's counts and what the log holds, per hook and in all (`GET /v1/account`). */
  async accountUsage(): Promise<AccountUsage> {
    const now = Date.now();
    const day = utcDay(now);
    const counts = new Map(
      this.sql.exec<{ key: string; count: number }>("SELECT key, count FROM daily WHERE day = ?", day).toArray().map((r) => [r.key, r.count]),
    );
    const perHook: AccountUsage["perHook"] = {};
    const hook = (id: string) => (perHook[id] ??= { today: 0, refused: 0, backlog: { events: 0, bytes: 0 }, lastEventAt: null });
    for (const [k, n] of counts) if (k.startsWith("r:")) hook(k.slice(2)).refused = n;
    for (const r of this.sql
      .exec<HookCounters & { hook_id: string }>("SELECT hook_id, events, bytes, day, taken, last_at FROM hook_usage")
      .toArray()) {
      // A hook is listed for what it holds, took today, or was last delivered (a deleted hook keeps
      // what it took today, and what it still holds, but no longer its last delivery).
      if (r.day === day && r.taken > 0) hook(r.hook_id).today = r.taken;
      if (r.events > 0 || r.bytes > 0) hook(r.hook_id).backlog = { events: r.events, bytes: r.bytes };
      if (r.last_at !== null) hook(r.hook_id).lastEventAt = r.last_at;
    }
    const a = this.accountCounters();
    return {
      day,
      today: { events: a.day === day ? a.taken : 0, refused: counts.get("ar") ?? 0, dropped: counts.get("ad") ?? 0 },
      perHook,
      backlog: this.usage(),
    };
  }

  /** The limit notices the object keeps (tests and `GET /v1/account`). */
  async limitNotices(): Promise<LimitNotice[]> {
    return this.sql
      .exec<{ scope: LimitNotice["scope"]; hook_id: string; refused: number; since: number; until: number | null; plan: string }>(
        "SELECT scope, hook_id, refused, since, until, plan FROM limit_notices ORDER BY since DESC",
      )
      .toArray()
      .map((r) => {
        const { t: _t, ...n } = limitMessage({ ...r, hookId: r.hook_id });
        return n as LimitNotice;
      });
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

  /** Forgets one held event: dropped by a person, or past its wait. */
  private forgetHeld(id: string): boolean {
    const h = this.sql.exec<{ hook_id: string }>("SELECT hook_id FROM held_events WHERE id = ?", id).toArray()[0];
    if (!h) return false;
    this.ctx.storage.transactionSync(() => {
      const b = this.sql
        .exec<{ b: number | null }>(`SELECT sum(length(ct) + ${ENVELOPE_OVERHEAD}) AS b FROM held_envelopes WHERE id = ?`, id)
        .one().b;
      this.sql.exec("DELETE FROM held_envelopes WHERE id = ?", id);
      this.sql.exec("DELETE FROM held_events WHERE id = ?", id);
      this.addHookUsage("held_usage", h.hook_id, -1, -((b ?? 0) + 2));
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
   * Drops every held event of a hook, or held by a rule, or both (`DELETE /v1/held?hookId=&rule=`):
   * how a person clears a quarantine flood in one call. Returns how many went.
   */
  async dropHeldWhere(filter: { hookId?: string; rule?: string }): Promise<number> {
    const where: string[] = [];
    const args: string[] = [];
    if (filter.hookId !== undefined) {
      where.push("hook_id = ?");
      args.push(filter.hookId);
    }
    if (filter.rule !== undefined) {
      where.push("rule = ?");
      args.push(filter.rule);
    }
    const ids = this.sql
      .exec<{ id: string }>(`SELECT id FROM held_events ${where.length ? `WHERE ${where.join(" AND ")}` : ""}`, ...args)
      .toArray();
    let n = 0;
    for (const r of ids) if (this.forgetHeld(r.id)) n++;
    if (n > 0) await this.ensureAlarm();
    return n;
  }

  /**
   * Releases a held event: it takes the next seq, each envelope is signed for it (with the `held`
   * line, so its device opens it with the held associated data), and it is streamed like any
   * event. Devices revoked meanwhile get nothing; null when there is no such held event; `full`
   * when the log (or the hook's share of it) has no room for it.
   */
  async releaseHeld(id: string): Promise<{ seq: number } | { full: FullScope } | null> {
    const relay = await this.signingKey();
    if (!relay) throw new Error("RELAY_SIGNING_KEY is missing or malformed");
    // ── synchronous: read it, check the log has room, reserve its seq ──
    const h = this.sql
      .exec<{ hook_id: string; received_at: number; verified: number; strict: number; preset: string; event_type: string | null; recipients: string | null }>(
        "SELECT hook_id, received_at, verified, strict, preset, event_type, recipients FROM held_events WHERE id = ?",
        id,
      )
      .toArray()[0];
    if (!h) return null;
    if ([...this.reservations].some((r) => r.marks.includes(`release\n${id}`))) return null;
    const sealedFor = this.sql
      .exec<{ device_id: string; kid: string; enc: string; ct: ArrayBuffer }>(
        `SELECT e.device_id, e.kid, e.enc, e.ct FROM held_envelopes e JOIN devices d ON d.id = e.device_id
         WHERE e.id = ? AND d.revoked = 0 ORDER BY e.device_id`,
        id,
      )
      .toArray();
    // An event for a list of devices: only their envelopes go into the log (one held before schema
    // 7 was sealed to every device). When none of them is left, nobody may read it: it is dropped.
    const listed = h.recipients === null ? null : jsonList(h.recipients);
    const envs = listed === null ? sealedFor : sealedFor.filter((e) => listed.includes(e.device_id));
    if (listed !== null && envs.length === 0) {
      this.forgetHeld(id);
      await this.ensureAlarm();
      return null;
    }
    const recipients = listed === null ? null : JSON.stringify(listed.filter((d) => envs.some((e) => e.device_id === d)));
    const bytes = envs.reduce((n, e) => n + e.ct.byteLength + ENVELOPE_OVERHEAD, 2);
    const scope = this.refuses(h.hook_id, bytes, { held: false, checked: h.verified === 1 && h.strict === 0 });
    if (scope) return { full: scope };
    const reservation: Reservation = { hookId: h.hook_id, held: false, bytes, marks: [`release\n${id}`] };
    const seq = this.takeSeq();
    this.reservations.add(reservation);
    let released = false;
    try {
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
      await this.inOrder(
        async () => {
          const signed: { device_id: string; kid: string; enc: string; ct: Uint8Array<ArrayBuffer>; sig: string }[] = [];
          for (const e of envs) {
            const ct = new Uint8Array(e.ct);
            signed.push({ ...e, ct, sig: await signEnvelope(relay, e.device_id, meta, { kid: e.kid, enc: e.enc, ct }) });
          }
          return signed;
        },
        (signed) => {
          // Dropped while it was being signed: nothing to release (its seq stays unused).
          if (this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM held_events WHERE id = ?", id).one().n === 0) return;
          const revoked = this.revokedAmong(signed.map((e) => e.device_id));
          this.ctx.storage.transactionSync(() => {
            // Retention counts from now, when it enters the log, not from when it was received:
            // an old event released today must never take newer ones with it (PROTOCOL §7).
            this.sql.exec(
              `INSERT INTO events (seq, id, hook_id, received_at, verified, strict, preset, event_type, content_type, headers, body, held, stored_at, recipients)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, '{}', x'', 1, ?, ?)`,
              seq,
              id,
              h.hook_id,
              h.received_at,
              h.verified,
              h.strict,
              h.preset,
              h.event_type,
              Date.now(),
              recipients,
            );
            let moved = 2;
            for (const e of signed) {
              if (revoked.has(e.device_id)) continue;
              this.sql.exec("INSERT INTO envelopes (seq, device_id, kid, enc, ct, sig) VALUES (?, ?, ?, ?, ?, ?)", seq, e.device_id, e.kid, e.enc, e.ct, e.sig);
              moved += e.ct.byteLength + ENVELOPE_OVERHEAD;
            }
            const heldBytes = this.sql
              .exec<{ b: number | null }>(`SELECT sum(length(ct) + ${ENVELOPE_OVERHEAD}) AS b FROM held_envelopes WHERE id = ?`, id)
              .one().b;
            this.sql.exec("DELETE FROM held_envelopes WHERE id = ?", id);
            this.sql.exec("DELETE FROM held_events WHERE id = ?", id);
            // The bytes move from the hold to the log.
            this.addHookUsage("held_usage", h.hook_id, -1, -((heldBytes ?? 0) + 2));
            this.commitCounts(reservation, { events: 1, bytes: moved }, seq);
          });
          released = true;
          this.deliverLive(seq);
        },
      );
    } finally {
      this.release(reservation);
    }
    if (!released) return null;
    await this.ensureAlarm();
    return { seq };
  }

  /**
   * Whether an offline notice is due (PROTOCOL §4a): no device stream is connected, none has been
   * for `afterMs`, and this sender (a keyed hash) hasn't had one from this hook in the last day.
   */
  private noticeDue(hookId: string, notice: { mark: string; afterMs: number }, now: number): boolean {
    // One already on its way to this sender.
    if ([...this.reservations].some((r) => r.notice === `${hookId}\n${notice.mark}`)) return false;
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

  /**
   * Counts failed verifications (counted, never stored: PROTOCOL §4). The Worker batches them, so a
   * flood of forged signatures wakes this object at most once a minute per hook per Worker instance.
   */
  async recordFailures(hookId: string, count = 1): Promise<void> {
    this.pruneAudit(Date.now());
    const hour = Math.floor(Date.now() / 3600_000) * 3600_000;
    this.sql.exec(
      `INSERT INTO verify_failures (hook_id, hour, count) VALUES (?, ?, ?)
       ON CONFLICT(hook_id, hour) DO UPDATE SET count = count + excluded.count`,
      hookId,
      hour,
      Math.max(1, Math.floor(count)),
    );
  }

  /** Moves a device's ack cursor forward (never back, never past the head); returns it. */
  async ack(deviceId: string, through: number): Promise<number> {
    const head = this.head();
    const current = this.ensureDevice(deviceId).acked;
    const next = Math.max(current, Math.min(through, head));
    if (next !== current) {
      // One transaction, and one write per hook for what every delete in it took from the log.
      this.ctx.storage.transactionSync(() => {
        const delta: UsageDelta = new Map();
        this.sql.exec("UPDATE devices SET acked = ? WHERE id = ?", next, deviceId);
        // This device's envelopes are of no use to anyone once it has them. Those up to `current`
        // went with its earlier acks, so the range is the newly acknowledged seqs alone (read by
        // `envelopes_seq_device`, without scanning other devices' backlog).
        this.deleteEnvelopes(delta, "e.seq > ? AND e.seq <= ? AND e.device_id = ?", current, next, deviceId);
        this.pruneRecipients(delta, deviceId, current, next);
        this.pruneAcknowledged(delta);
        this.applyUsage(delta);
      });
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
    const delta: UsageDelta = new Map();
    this.deleteEnvelopes(delta, "e.device_id = ?", deviceId);
    this.pruneRecipients(delta, deviceId, 0, Number.MAX_SAFE_INTEGER);
    // Its held envelopes too, each hook's hold counter with them.
    for (const g of this.sql
      .exec<{ h: string; b: number | null }>(
        `SELECT h.hook_id AS h, sum(length(e.ct) + ${ENVELOPE_OVERHEAD}) AS b FROM held_envelopes e
         JOIN held_events h ON h.id = e.id WHERE e.device_id = ? GROUP BY h.hook_id`,
        deviceId,
      )
      .toArray()) {
      this.addHookUsage("held_usage", g.h, 0, -(g.b ?? 0));
    }
    this.sql.exec("DELETE FROM held_envelopes WHERE device_id = ?", deviceId);
    this.pruneAcknowledged(delta);
    this.applyUsage(delta);
    await this.ensureAlarm();
  }

  // ── audit (PLAN §4.3): names and ids only ──────────────────────────────────

  /**
   * Audit rows are pruned as they're written (and read), not by the alarm: an account where nothing
   * happens must never wake just to forget its history.
   */
  private pruneAudit(now: number, force = false): void {
    // Hourly at most: the rows expire after 90 days, so an hour late costs nothing, and a burst of
    // audit writes doesn't each pay for three deletes.
    if (!force && now - this.auditPrunedAt < 3600_000) return;
    this.auditPrunedAt = now;
    this.sql.exec("DELETE FROM hook_changes WHERE at <= ?", now - AUDIT_TTL_MS);
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

  /** Counts occurrences of a counted kind in the current hour (one, or a batch from the Worker). */
  async countAudit(kind: CountedKind, subject: string, name: string | null, count = 1): Promise<void> {
    this.pruneAudit(Date.now());
    const hour = Math.floor(Date.now() / 3600_000) * 3600_000;
    this.sql.exec(
      `INSERT INTO audit_counts (kind, subject, hour, name, count) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(kind, subject, hour) DO UPDATE SET count = count + excluded.count, name = excluded.name`,
      kind,
      subject,
      hour,
      name,
      Math.max(1, Math.floor(count)),
    );
  }

  /**
   * Records a change to a hook (PROTOCOL §6): an audit line, and a `hook-change` message on every
   * device's stream, now for those connected and after `ready` for the others. Each device is sent
   * each change once, so a device learns when someone (an API key, say) created or rotated a hook.
   */
  async hookChanged(change: HookChange): Promise<void> {
    const now = Date.now();
    this.pruneAudit(now);
    if (change.kind === "hook.deleted") {
      // Its counters go with it (today's counts keep what it took, the log what it still holds).
      this.sql.exec("UPDATE hook_usage SET last_at = NULL, written_at = 0, tokens = NULL, tokens_at = NULL WHERE hook_id = ?", change.hookId);
      this.sql.exec("DELETE FROM refusals WHERE hook_id = ?", change.hookId);
      this.sql.exec("DELETE FROM limit_notices WHERE hook_id = ?", change.hookId);
    }
    this.sql.exec(
      "INSERT INTO audit (at, kind, actor, subject, name) VALUES (?, ?, ?, ?, ?)",
      now,
      change.kind,
      change.actor,
      change.hookId,
      change.name,
    );
    this.sql.exec(
      "INSERT INTO hook_changes (at, kind, hook_id, name, previous_name, actor) VALUES (?, ?, ?, ?, ?, ?)",
      now,
      change.kind,
      change.hookId,
      change.name,
      change.previousName ?? null,
      change.actor,
    );
    for (const ws of this.ctx.getWebSockets()) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      const att = ws.deserializeAttachment() as Attachment | null;
      // Live, without marking it sent: a stream that is going away unnoticed would take it and lose
      // it, so the device is sent it again when it next connects (clients dedupe by `n`).
      if (att) this.sendChanges(ws, att.deviceId, { after: this.lastChange() - 1, mark: false });
    }
  }

  private lastChange(): number {
    return this.sql.exec<{ n: number | null }>("SELECT max(n) AS n FROM hook_changes").one().n ?? 0;
  }

  /**
   * Sends a device's stream hook changes, skipping its own: by default those it hasn't been sent at
   * a stream's start (at most 100 at a time; older ones wait for the next stream), marking them
   * sent. False when the socket failed.
   */
  private sendChanges(ws: WebSocket, deviceId: string, live?: { after: number; mark: false }): boolean {
    const seen = live
      ? live.after
      : (this.sql.exec<{ c: number }>("SELECT changes_seen AS c FROM devices WHERE id = ?", deviceId).toArray()[0]?.c ?? 0);
    const rows = this.sql
      .exec<{ n: number; at: number; kind: string; hook_id: string; name: string; previous_name: string | null; actor: string | null }>(
        "SELECT n, at, kind, hook_id, name, previous_name, actor FROM hook_changes WHERE n > ? ORDER BY n LIMIT 100",
        seen,
      )
      .toArray();
    let last = seen;
    for (const r of rows) {
      // A device isn't told of what it did itself.
      if (r.actor === deviceId) {
        last = r.n;
        continue;
      }
      const msg = {
        t: "change",
        n: r.n,
        kind: r.kind,
        hookId: r.hook_id,
        name: r.name,
        ...(r.previous_name !== null ? { previousName: r.previous_name } : {}),
        actor: r.actor,
        at: r.at,
      };
      if (!this.trySend(ws, JSON.stringify(msg))) break;
      last = r.n;
    }
    if (!live && last !== seen) this.sql.exec("UPDATE devices SET changes_seen = ? WHERE id = ?", last, deviceId);
    return last === (rows.at(-1)?.n ?? seen);
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
      const recipients = r.recipients === null ? null : jsonList(r.recipients);
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
        deliveredTo: devices.filter((d) => d.acked >= r.seq && (recipients === null || recipients.includes(d.id))).map((d) => d.id),
        recipients,
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
    if (this.trySend(server, JSON.stringify(ready)) && this.sendChanges(server, deviceId) && this.sendLimits(server)) this.sendPage(server, att);
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
    if (!env) {
      // An event for other devices (its hook's recipients): not this device's, so passed by in silence.
      if (row.recipients !== null && !jsonList(row.recipients).includes(att.deviceId)) {
        att.cursor = row.seq;
        return 0;
      }
      return skip("no_key");
    }
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
      const before = att.cursor;
      // A failed socket is closed by sendHook and resumes from its cursor on reconnect.
      if (this.sendHook(ws, att, row) === null) continue;
      // Seqs skipped since this stream's last one (deliveries dropped `over_limit`) are said after
      // the event, once the stream has shown a seq past them (a client ignores a gap beyond it).
      if (seq > before + 1 && !this.sendGaps(ws, { ...att, cursor: before }, seq - 1)) continue;
      ws.serializeAttachment(att);
    }
  }

  // ── pruning ────────────────────────────────────────────────────────────────

  /**
   * Deletes the events for a list of devices (a hook's recipients) among `deviceId`'s in
   * (`after`, `through`], once every one of their recipients has acknowledged them or is revoked:
   * nobody else will ever read them, so they mustn't wait for the other devices' acknowledgements
   * (or retention) and hold the account's quota. One recipient acknowledging never takes an event
   * from another that hasn't.
   */
  private pruneRecipients(delta: UsageDelta, deviceId: string, after: number, through: number): void {
    const rows = this.sql
      .exec<{ seq: number; recipients: string }>(
        `SELECT seq, recipients FROM events e WHERE recipients IS NOT NULL AND seq > ? AND seq <= ?
           AND EXISTS (SELECT 1 FROM json_each(e.recipients) j WHERE j.value = ?) ORDER BY seq`,
        after,
        through,
        deviceId,
      )
      .toArray();
    if (rows.length === 0) return;
    const devices = new Map(
      this.sql.exec<{ id: string; acked: number; revoked: number }>("SELECT id, acked, revoked FROM devices").toArray().map((d) => [d.id, d]),
    );
    for (const r of rows) {
      const done = jsonList(r.recipients).every((id) => {
        const d = devices.get(id);
        return d === undefined || d.revoked === 1 || d.acked >= r.seq;
      });
      if (done) this.deleteRange(delta, r.seq, r.seq);
    }
  }

  /** Deletes events every active device has acknowledged, and gap records nobody can need. */
  private pruneAcknowledged(delta: UsageDelta): void {
    const row = this.sql
      .exec<{ m: number | null; n: number }>("SELECT min(acked) AS m, count(*) AS n FROM devices WHERE revoked = 0")
      .one();
    if (row.n === 0 || row.m === null) return;
    this.deleteRange(delta, 0, row.m);
    this.sql.exec("DELETE FROM pruned WHERE to_seq <= ?", row.m);
  }

  /**
   * Drops events past retention, recording each dropped range so a resume reports a `gap`. Retention
   * counts from when an event entered the log (`stored_at`: appended, or released from the hold),
   * and only events that old go: a released event received long ago never takes newer ones with it.
   * Old events are a prefix of the log in practice; any newer event among them splits the ranges.
   */
  private pruneRetention(delta: UsageDelta, now: number): void {
    const cutoff = now - this.retentionMs();
    const hi = this.sql.exec<{ hi: number | null }>("SELECT max(seq) AS hi FROM events WHERE stored_at < ?", cutoff).one().hi;
    if (hi === null) return;
    const rows = this.sql
      .exec<{ seq: number; old: number }>("SELECT seq, (stored_at < ?) AS old FROM events WHERE seq <= ? ORDER BY seq", cutoff, hi)
      .toArray();
    const ranges: [number, number][] = [];
    for (let i = 0; i < rows.length; i++) {
      const r = rows[i]!;
      if (!r.old) continue;
      const last = ranges.at(-1);
      // Contiguous: the event before it in the log is old too, so no surviving event is between.
      if (last && i > 0 && rows[i - 1]!.old && last[1] === rows[i - 1]!.seq) last[1] = r.seq;
      else ranges.push([r.seq, r.seq]);
    }
    {
      for (const [lo, hi] of ranges) {
        const last = this.sql
          .exec<{ rowid: number; from_seq: number; to_seq: number; reason: string }>(
            "SELECT rowid, from_seq, to_seq, reason FROM pruned WHERE to_seq < ? ORDER BY to_seq DESC LIMIT 1",
            lo,
          )
          .toArray()[0];
        // The range reaches back to the previous retention gap when nothing survives in between.
        const between =
          last === undefined
            ? 1
            : this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM events WHERE seq > ? AND seq < ?", last.to_seq, lo).one().n;
        if (last && last.reason === "retention" && between === 0) {
          this.sql.exec("UPDATE pruned SET to_seq = max(to_seq, ?) WHERE rowid = ?", hi, last.rowid);
        } else {
          this.sql.exec("INSERT INTO pruned (from_seq, to_seq, reason) VALUES (?, ?, 'retention')", lo, hi);
        }
        this.deleteRange(delta, lo, hi);
      }
    }
  }

  override async alarm(): Promise<void> {
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      const delta: UsageDelta = new Map();
      this.pruneAcknowledged(delta);
      this.pruneRetention(delta, now);
      this.applyUsage(delta);
      // Rows of hooks that hold nothing, took nothing today, and have no bucket or last delivery
      // (deleted hooks, or hooks only ever held) have nothing left to say.
      this.sql.exec(
        "DELETE FROM hook_usage WHERE events = 0 AND bytes = 0 AND last_at IS NULL AND tokens IS NULL AND day < ?",
        utcDay(now),
      );
    });
    this.sql.exec("DELETE FROM nonces WHERE at < ?", now - NONCE_TTL_MS);
    this.sql.exec("DELETE FROM seen WHERE long = 0 AND at <= ?", now - DEDUPE_TTL_MS);
    this.sql.exec("DELETE FROM seen WHERE long = 1 AND at <= ?", now - this.replayMarkMs());
    this.sql.exec("DELETE FROM notices WHERE at <= ?", now - NOTICE_TTL_MS);
    for (const r of this.sql.exec<{ id: string }>("SELECT id FROM held_events WHERE received_at <= ?", now - this.heldMs()).toArray()) {
      this.forgetHeld(r.id);
    }
    this.pruneAudit(now, true);
    await this.ensureAlarm(true);
  }

  /**
   * Schedules the alarm for the next time something expires, or clears it when nothing will.
   * An account with nothing pending has no alarm, so idle accounts never wake.
   *
   * Nonces have no index on `at` (it would be a row written per signed request), so their earliest
   * expiry is read (a scan of at most the last hour's nonces) only in the alarm, or when no alarm is
   * set. Otherwise the alarm already covers every nonce stored (each one spent lowered it if needed,
   * and the alarm reschedules from the exact earliest), so only the nonce just spent (`nonceAt`)
   * can need it sooner. The alarm is only ever moved earlier between alarms, never later.
   */
  private async ensureAlarm(fromAlarm = false, nonceAt: number | null = null): Promise<void> {
    const q = (sql: string) => this.sql.exec<{ t: number | null }>(sql).one().t;
    const current = await this.ctx.storage.getAlarm();
    const exactNonces = fromAlarm || current === null;
    const due: [number | null, number][] = [
      [exactNonces ? q("SELECT min(at) AS t FROM nonces") : nonceAt, NONCE_TTL_MS],
      [q("SELECT min(stored_at) AS t FROM events"), this.retentionMs()],
      [q("SELECT min(at) AS t FROM seen WHERE long = 0"), DEDUPE_TTL_MS],
      [q("SELECT min(at) AS t FROM seen WHERE long = 1"), this.replayMarkMs()],
      [q("SELECT min(at) AS t FROM notices"), NOTICE_TTL_MS],
      [q("SELECT min(received_at) AS t FROM held_events"), this.heldMs()],
    ];
    let next = Infinity;
    for (const [t, ttl] of due) if (t !== null) next = Math.min(next, t + ttl + 1);
    if (next === Infinity) {
      // Nothing else expires: the alarm goes only when no nonce is left for it either.
      if (current !== null && !fromAlarm && q("SELECT min(at) AS t FROM nonces") === null) await this.ctx.storage.deleteAlarm();
      return;
    }
    // Rounded up to the hour, and never sooner than a minute from now: expiry can wait, and wakes
    // cost money, so a busy account wakes at most hourly to prune.
    next = Math.max(Math.ceil(next / ALARM_BUCKET_MS) * ALARM_BUCKET_MS, Date.now() + 60_000);
    if (fromAlarm || current === null || current > next) await this.ctx.storage.setAlarm(next);
  }

  // ── test and diagnostics helpers (not routed) ───────────────────────────────

  async stats(): Promise<{
    head: number;
    events: number;
    envelopes: number;
    held: number;
    usage: Quota;
    hooks: Record<string, Quota>;
    heldUsage: Quota;
    devices: { id: string; acked: number; revoked: boolean; sealKid: string | null }[];
  }> {
    return {
      head: this.head(),
      events: this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM events").one().n,
      hooks: Object.fromEntries(
        this.sql
          .exec<{ hook_id: string; events: number; bytes: number }>("SELECT hook_id, events, bytes FROM hook_usage WHERE events > 0 OR bytes > 0")
          .toArray().map((r) => [r.hook_id, { events: r.events, bytes: r.bytes }]),
      ),
      heldUsage: this.heldTotal(),
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
     headers TEXT NOT NULL, body BLOB NOT NULL, strict INTEGER NOT NULL DEFAULT 0,
     held INTEGER NOT NULL DEFAULT 0, stored_at INTEGER, route TEXT, recipients TEXT)`,
  `CREATE TABLE IF NOT EXISTS envelopes (seq INTEGER NOT NULL, device_id TEXT NOT NULL, kid TEXT NOT NULL,
     enc TEXT NOT NULL, ct BLOB NOT NULL, sig TEXT NOT NULL)`,
  "CREATE UNIQUE INDEX IF NOT EXISTS envelopes_seq_device ON envelopes(seq, device_id)",
  `CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, acked INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
     seal_key BLOB, seal_kid TEXT, changes_seen INTEGER NOT NULL DEFAULT 0, tags TEXT)`,
  `CREATE TABLE IF NOT EXISTS nonces (device_id TEXT NOT NULL, nonce TEXT NOT NULL, at INTEGER NOT NULL,
     PRIMARY KEY (device_id, nonce)) WITHOUT ROWID`,
  // Replay marks; `long` ones (body hashes of presets that sign no timestamp) are kept for
  // REPLAY_MARK_DAYS rather than a week.
  `CREATE TABLE IF NOT EXISTS seen (hook_id TEXT NOT NULL, key TEXT NOT NULL, at INTEGER NOT NULL,
     long INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (hook_id, key)) WITHOUT ROWID`,
  // Offline notices sent (PROTOCOL §4a): the sender only as a keyed hash, never the address.
  `CREATE TABLE IF NOT EXISTS notices (hook_id TEXT NOT NULL, mark TEXT NOT NULL, at INTEGER NOT NULL,
     PRIMARY KEY (hook_id, mark)) WITHOUT ROWID`,
  "CREATE INDEX IF NOT EXISTS notices_at ON notices(at)",
  // The screen's hold (PROTOCOL §4b): events sealed (with the held associated data) and kept aside
  // until a device releases or drops them. Metadata and ciphertext only, as in the log.
  `CREATE TABLE IF NOT EXISTS held_events (id TEXT PRIMARY KEY, hook_id TEXT NOT NULL, received_at INTEGER NOT NULL,
     verified INTEGER NOT NULL, strict INTEGER NOT NULL, preset TEXT NOT NULL, event_type TEXT, rule TEXT NOT NULL,
     route TEXT, recipients TEXT)`,
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
  // What each hook holds in the log and in the hold, kept as counters (PROTOCOL §4).
  // Schema 8: each hook's row also holds today's count (`day`, `taken`), its last delivery
  // (`last_at`, and `written_at`, when D1's `last_event_at` was last written) and its token bucket
  // (`tokens`, `tokens_at`), so an append writes one row for the hook.
  `CREATE TABLE IF NOT EXISTS hook_usage (hook_id TEXT PRIMARY KEY, events INTEGER NOT NULL, bytes INTEGER NOT NULL,
     day INTEGER NOT NULL DEFAULT 0, taken INTEGER NOT NULL DEFAULT 0, last_at INTEGER, written_at INTEGER NOT NULL DEFAULT 0,
     tokens REAL, tokens_at INTEGER) WITHOUT ROWID`,
  `CREATE TABLE IF NOT EXISTS held_usage (hook_id TEXT PRIMARY KEY, events INTEGER NOT NULL, bytes INTEGER NOT NULL) WITHOUT ROWID`,
  // Hook changes announced on the streams (PROTOCOL §6); each device's `changes_seen` is the last sent.
  `CREATE TABLE IF NOT EXISTS hook_changes (n INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, kind TEXT NOT NULL,
     hook_id TEXT NOT NULL, name TEXT NOT NULL, previous_name TEXT, actor TEXT)`,
  "CREATE INDEX IF NOT EXISTS hook_changes_at ON hook_changes(at)",
  // Plans (PROTOCOL §2a), schema 5: today's refusals and drops (`ar` refused, `r:<hook>` refused at
  // a hook, `ad` dropped; schema 8 moved the counts taken into `counters` and `hook_usage`), each
  // hook's refusal window and pauses, and the `limit` notices.
  "CREATE TABLE IF NOT EXISTS daily (key TEXT NOT NULL, day INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (key, day)) WITHOUT ROWID",
  `CREATE TABLE IF NOT EXISTS refusals (hook_id TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL,
     level INTEGER NOT NULL DEFAULT 0, paused_until INTEGER) WITHOUT ROWID`,
  `CREATE TABLE IF NOT EXISTS limit_notices (scope TEXT NOT NULL, hook_id TEXT NOT NULL, refused INTEGER NOT NULL, since INTEGER NOT NULL,
     until INTEGER, plan TEXT NOT NULL, sent_at INTEGER NOT NULL, PRIMARY KEY (scope, hook_id)) WITHOUT ROWID`,
  // Schema 8: the account's counters in one row, written once per append: the head (the last seq
  // taken), today's count taken (`day`, `taken`), and the account's token bucket.
  `CREATE TABLE IF NOT EXISTS counters (id INTEGER PRIMARY KEY CHECK (id = 1), head INTEGER NOT NULL DEFAULT 0,
     day INTEGER NOT NULL DEFAULT 0, taken INTEGER NOT NULL DEFAULT 0, tokens REAL, tokens_at INTEGER)`,
];

/** Indexes on columns schema 4 added: created after the columns exist, on old objects too. */
const SCHEMA_4_INDEXES = [
  "CREATE INDEX IF NOT EXISTS events_stored ON events(stored_at)",
  "CREATE INDEX IF NOT EXISTS seen_long_at ON seen(long, at)",
];

/** How long a lapsed plan's refusal asks a sender to wait: an hour (a refreshed plan takes effect at once). */
export const PLAN_EXPIRED_RETRY_S = 3600;

/** The UTC day `now` is in (days since the epoch). */
export function utcDay(now: number): number {
  return Math.floor(now / 86_400_000);
}

/** Whole seconds from `now` until the start of UTC day `day`, at least one. */
function secondsUntilDay(day: number, now: number): number {
  return Math.max(1, Math.ceil((day * 86_400_000 - now) / 1000));
}

/** The `limit` message (PROTOCOL §6): `hookId` only for a hook's own scope. */
function limitMessage(n: { scope: string; hookId: string; refused: number; since: number; until: number | null; plan: string }) {
  return {
    t: "limit",
    scope: n.scope,
    ...(n.hookId ? { hookId: n.hookId } : {}),
    refused: n.refused,
    since: n.since,
    until: n.until,
    plan: n.plan,
  };
}

/** What a delivery the plan takes counts: today, and a token from each rate the plan sets. */
function planCount(plan: PlanInput, now: number): NonNullable<Reservation["count"]> {
  const rate = (perMin: number | null, burst: number | null): Rate | null =>
    perMin === null || perMin <= 0 ? null : { perMin, burst: Math.max(1, burst ?? perMin) };
  return { day: utcDay(now), hook: rate(plan.hookRatePerMin, plan.hookBurst), account: rate(plan.accountRatePerMin, plan.accountBurst) };
}

/** A token bucket's tokens at `now`, refilled at its rate up to its size; full when it has none. */
function refill(b: { tokens: number | null; tokens_at: number | null }, rate: Rate, now: number): number {
  if (b.tokens === null) return rate.burst;
  return Math.min(rate.burst, b.tokens + (Math.max(0, now - (b.tokens_at ?? now)) * rate.perMin) / 60_000);
}

/** A bucket after one token is taken at `at`. Never dated back: a hold committed late takes it then. */
function take(b: { tokens: number | null; tokens_at: number | null }, rate: Rate, at: number): [number, number] {
  return [refill(b, rate, at) - 1, Math.max(b.tokens_at ?? at, at)];
}

/** A day's count after one more on `day`; a count for a day already past is of no more use. */
function countDay(storedDay: number, taken: number, day: number): [number, number] {
  if (day > storedDay) return [day, 1];
  if (day === storedDay) return [day, taken + 1];
  return [storedDay, taken];
}

function addDelta(delta: UsageDelta, hookId: string, events: number, bytes: number): void {
  const d = delta.get(hookId) ?? { events: 0, bytes: 0 };
  d.events += events;
  d.bytes += bytes;
  delta.set(hookId, d);
}

/** A device that can be sealed to, with the tags hooks' targets match against. */
interface SealingDevice {
  id: string;
  seal_key: ArrayBuffer;
  seal_kid: string;
  tags: string[];
}

/** A JSON array of strings as stored (recipients, tags); anything unreadable is empty. */
function jsonList(stored: string | null): string[] {
  if (!stored) return [];
  try {
    const v = JSON.parse(stored) as unknown;
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

function positive(v: string | undefined, fallback: number): number {
  const x = Number(v);
  return Number.isFinite(x) && x > 0 ? x : fallback;
}
