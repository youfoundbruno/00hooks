// Plans (PROTOCOL §2a): the limits an account works under, from the operator's configuration.
//
// A relay without `PLANS` has one plan, `default`, equal to how the relay behaved before plans
// existed: no daily cap, no account rate, the backlog quota and retention of `ACCOUNT_MAX_*` and
// `RETENTION_DAYS`, the device cap of `ACCOUNT_MAX_DEVICES`. A self-hosted relay sees no change.
//
// `PLANS` (a JSON var) maps a plan's name to its limits. A limit left out takes the `default`
// plan's value; `null` means "no limit". An account names its plan (`accounts.plan`, null for
// `default`), may carry a per-account override (`accounts.limits`), and, when the plan came with an
// entitlement (src/entitlements.ts), an end (`plan_until`): past it and the grace period, the
// account falls back to `ENTITLEMENT_FALLBACK_PLAN` (`suspended` unless set).

import { DEFAULT_MAX_BYTES, DEFAULT_MAX_EVENTS, utcDay } from "./account-object.ts";
import { HttpError, unavailable } from "./http.ts";

export interface Limits {
  /** Hooks the account may have at once. */
  hooks: number | null;
  /** Node devices the account may have at once. */
  devices: number | null;
  /** Deliveries the account may take per UTC day. */
  eventsPerDay: number | null;
  /** A hook's sustained rate, per minute, and its burst (the token bucket's size). */
  hookRatePerMin: number | null;
  hookBurst: number | null;
  /** The account's sustained rate across its hooks, per minute, and its burst. */
  accountRatePerMin: number | null;
  accountBurst: number | null;
  /** How long unacknowledged events are kept. */
  retentionHours: number | null;
  /** The largest body any of the account's hooks takes (a hook's own `maxBodyBytes` may be lower). */
  maxBodyBytes: number | null;
  /** What the account's log may hold waiting for acknowledgement. */
  backlogEvents: number | null;
  backlogBytes: number | null;
  /** Hooks the account may create per UTC day. */
  hookCreatesPerDay: number | null;
}

export const LIMIT_KEYS = [
  "hooks",
  "devices",
  "eventsPerDay",
  "hookRatePerMin",
  "hookBurst",
  "accountRatePerMin",
  "accountBurst",
  "retentionHours",
  "maxBodyBytes",
  "backlogEvents",
  "backlogBytes",
  "hookCreatesPerDay",
] as const satisfies readonly (keyof Limits)[];

export const DEFAULT_PLAN = "default";
/** The plan an account falls back to when its entitlement ran out, unless configured otherwise. */
export const SUSPENDED_PLAN = "suspended";
/** Days an entitlement's plan keeps working past its `exp` (`ENTITLEMENT_GRACE_DAYS`). */
export const DEFAULT_GRACE_DAYS = 7;
/** The largest number a limit may be: beyond it, a limit is as good as none. */
const MAX_LIMIT = 1e12;

export interface ResolvedPlan {
  /** The plan in effect: the account's, or the fallback once its entitlement ran out. */
  name: string;
  limits: Limits;
  /** When the account's plan ends (its entitlement's `exp`), or null for a plan without an end. */
  until: number | null;
  /** The account's plan ran out (past `until` and the grace period): `name` is the fallback. */
  expired: boolean;
}

/** The `default` plan: today's behaviour, from the existing settings. */
export function defaultLimits(env: Env): Limits {
  const days = Number(env.RETENTION_DAYS);
  return {
    hooks: null,
    devices: maxDevicesFromEnv(env),
    eventsPerDay: null,
    hookRatePerMin: null,
    hookBurst: null,
    accountRatePerMin: null,
    accountBurst: null,
    retentionHours: (Number.isFinite(days) && days > 0 ? Math.max(days, 1 / 24) : 7) * 24,
    maxBodyBytes: null,
    backlogEvents: positive(env.ACCOUNT_MAX_EVENTS, DEFAULT_MAX_EVENTS),
    backlogBytes: positive(env.ACCOUNT_MAX_BYTES, DEFAULT_MAX_BYTES),
    hookCreatesPerDay: null,
  };
}

/**
 * Parses a set of limits (a plan in `PLANS`, an account's override, an entitlement's `limits`):
 * each key optional, each value a non-negative number or null. Null when anything is malformed.
 */
export function parseLimits(v: unknown): Partial<Limits> | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const out: Partial<Limits> = {};
  for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
    if (!(LIMIT_KEYS as readonly string[]).includes(k)) return null;
    if (x === null) {
      out[k as keyof Limits] = null;
      continue;
    }
    if (typeof x !== "number" || !Number.isFinite(x) || x < 0 || x > MAX_LIMIT) return null;
    // Rates may be fractional (one a minute is 1); counts and sizes are whole.
    if (k !== "hookRatePerMin" && k !== "accountRatePerMin" && k !== "retentionHours" && !Number.isInteger(x)) return null;
    out[k as keyof Limits] = x;
  }
  return out;
}

interface PlanTable {
  plans: Map<string, Partial<Limits>>;
}

let cached: { raw: string | undefined; table: PlanTable } | null = null;

/** `PLANS`, parsed once per isolate. Malformed configuration fails closed (`503`). */
function planTable(env: Env): PlanTable {
  const raw = env.PLANS;
  if (cached && cached.raw === raw) return cached.table;
  const plans = new Map<string, Partial<Limits>>();
  if (raw !== undefined && raw.trim() !== "") {
    let v: unknown;
    try {
      v = JSON.parse(raw);
    } catch {
      throw new HttpError(unavailable());
    }
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw new HttpError(unavailable());
    for (const [name, limits] of Object.entries(v as Record<string, unknown>)) {
      const parsed = parseLimits(limits);
      if (!isPlanName(name) || !parsed) throw new HttpError(unavailable());
      plans.set(name, parsed);
    }
  }
  const table = { plans };
  cached = { raw, table };
  return table;
}

export function isPlanName(name: unknown): name is string {
  return typeof name === "string" && /^[a-z0-9][a-z0-9_-]{0,39}$/.test(name);
}

/** Whether `name` is a plan this relay knows (`default` and `suspended` always are). */
export function knownPlan(env: Env, name: string): boolean {
  return name === DEFAULT_PLAN || name === SUSPENDED_PLAN || planTable(env).plans.has(name);
}

/** A plan's limits: the `default` plan's, with the plan's own on top. Null for an unknown plan. */
export function planLimits(env: Env, name: string): Limits | null {
  const base = defaultLimits(env);
  const table = planTable(env);
  const own = table.plans.get(name);
  if (name === DEFAULT_PLAN) return { ...base, ...(own ?? {}) };
  const withDefault = { ...base, ...(table.plans.get(DEFAULT_PLAN) ?? {}) };
  if (own) return { ...withDefault, ...own };
  // Built in, unless the operator defines it: accepts nothing new, keeps the backlog readable.
  if (name === SUSPENDED_PLAN) return { ...withDefault, hooks: 0, hookCreatesPerDay: 0, eventsPerDay: 0 };
  return null;
}

/** The plan accounts fall back to once an entitlement's plan ran out. */
export function fallbackPlan(env: Env): string {
  const name = env.ENTITLEMENT_FALLBACK_PLAN?.trim();
  return name && isPlanName(name) && knownPlan(env, name) ? name : SUSPENDED_PLAN;
}

export function graceMs(env: Env): number {
  return positive(env.ENTITLEMENT_GRACE_DAYS, DEFAULT_GRACE_DAYS, true) * 24 * 3600_000;
}

/** What an account row says about its plan (the columns of migration 0008). */
export interface AccountPlanColumns {
  plan: string | null;
  plan_until: number | null;
  limits: string | null;
}

/**
 * The plan an account works under right now. An account naming a plan the configuration no longer
 * has gets the `default` plan's limits, under its own name (an operator who removes a plan has to
 * move its accounts; until then they lose nothing).
 */
export function resolvePlan(env: Env, row: AccountPlanColumns | null, now: number): ResolvedPlan {
  const own = row?.plan && isPlanName(row.plan) ? row.plan : DEFAULT_PLAN;
  const until = row?.plan_until ?? null;
  const expired = until !== null && now > until + graceMs(env);
  const name = expired ? fallbackPlan(env) : own;
  let limits = planLimits(env, name) ?? planLimits(env, DEFAULT_PLAN)!;
  // The account's override (from its entitlement, or set by the operator) applies to its own plan,
  // never to the fallback.
  if (!expired && row?.limits) {
    let parsed: Partial<Limits> | null = null;
    try {
      parsed = parseLimits(JSON.parse(row.limits));
    } catch {
      parsed = null;
    }
    if (parsed) limits = { ...limits, ...parsed };
  }
  return { name, limits, until, expired };
}

/** A body limit: the hook's own, lowered to the plan's when the plan has one. */
export function effectiveMaxBody(hookMax: number, limits: Limits): number {
  return limits.maxBodyBytes === null ? hookMax : Math.min(hookMax, limits.maxBodyBytes);
}

/** Seconds until the next UTC midnight: what a daily refusal's `Retry-After` says. */
export function secondsToMidnight(now: number): number {
  return Math.max(1, Math.ceil(((utcDay(now) + 1) * 86_400_000 - now) / 1000));
}

/**
 * How to get the hosted plan, as the operator announces it (`HOSTED_PLAN`): data, never code.
 * `{ "plan", "title", "description"?, "url"? }`; anything malformed is left out.
 */
export interface HostedPlan {
  plan: string;
  title: string;
  description?: string;
  url?: string;
}

export function hostedPlan(raw: string | undefined): HostedPlan | null {
  if (!raw) return null;
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const text = (x: unknown, max: number) => (typeof x === "string" && x.trim().length > 0 && x.length <= max ? x.trim() : undefined);
  const title = text(o.title, 80);
  if (!isPlanName(o.plan) || !title) return null;
  const description = text(o.description, 400);
  const url = text(o.url, 300);
  return { plan: o.plan, title, ...(description ? { description } : {}), ...(url && /^https:\/\//.test(url) ? { url } : {}) };
}

/** `ACCOUNT_MAX_DEVICES`: node devices per account, 10 when unset. */
export function maxDevicesFromEnv(env: Env): number {
  const n = Number(env.ACCOUNT_MAX_DEVICES);
  return Number.isInteger(n) && n > 0 ? n : 10;
}

function positive(v: string | undefined, fallback: number, allowZero = false): number {
  const x = Number(v);
  return v !== undefined && v.trim() !== "" && Number.isFinite(x) && (allowZero ? x >= 0 : x > 0) ? x : fallback;
}
