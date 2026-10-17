// The idle-cost measurement's pure half: argument parsing, the GraphQL Analytics query, parsing its
// answer, and the cost arithmetic. Tested with fixtures (test/idle-cost.test.ts); the network half
// is scripts/idle-cost.ts.

/**
 * Durable Objects pricing on Workers Paid, as published at
 * https://developers.cloudflare.com/durable-objects/platform/pricing/ (checked 2026-10-17):
 * - requests: 1 million a month included, then $0.15 per million. HTTP requests, RPC sessions,
 *   WebSocket messages and alarms count; incoming WebSocket messages are billed at 20:1, outgoing
 *   messages and protocol pings aren't billed, and `setWebSocketAutoResponse` replies are free;
 * - duration: 400,000 GB-s a month included, then $12.50 per million GB-s, billed at 128 MB per
 *   object while it's awake (one active second = 0.128 GB-s); hibernation-eligible idle objects
 *   aren't billed for duration.
 * The included allowances are shared by the whole account, so the figures below are marginal
 * (as if the allowance were already used up).
 */
export const PRICING = {
  requestUsdPerMillion: 0.15,
  durationUsdPerMillionGbS: 12.5,
  gbPerObject: 0.128,
  incomingWebSocketMessagesPerRequest: 20,
} as const;

export const HOURS_PER_MONTH = 730;
const MS_PER_HOUR = 3_600_000;

export interface Args {
  relay: string;
  connections: number;
  hours: number;
  namespaceId?: string;
  /** Skip the hold: analyse an earlier run's window. */
  analyzeOnly?: { start: Date; end: Date };
}

export function parseArgs(argv: string[]): Args {
  const opts = new Map<string, string>();
  const rest = argv.filter((a) => a !== "--");
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (!a.startsWith("--")) throw new Error(`unexpected argument: ${a}`);
    const eq = a.indexOf("=");
    if (eq > 0) opts.set(a.slice(2, eq), a.slice(eq + 1));
    else {
      const v = rest[i + 1];
      if (v === undefined || v.startsWith("--")) throw new Error(`${a} needs a value`);
      opts.set(a.slice(2), v);
      i++;
    }
  }
  const known = new Set(["relay", "connections", "hours", "namespace-id", "start", "end"]);
  for (const k of opts.keys()) if (!known.has(k)) throw new Error(`unknown option: --${k}`);

  const relay = opts.get("relay");
  if (!relay) throw new Error("--relay <url> is required");
  let url: URL;
  try {
    url = new URL(relay);
  } catch {
    throw new Error("--relay must be a URL");
  }
  if (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
    throw new Error("--relay must be https (or localhost)");
  }
  const connections = Number(opts.get("connections") ?? "1");
  if (!Number.isInteger(connections) || connections < 1 || connections > 1000) {
    throw new Error("--connections must be a whole number from 1 to 1000");
  }
  const hours = Number(opts.get("hours") ?? "24");
  if (!Number.isFinite(hours) || hours <= 0 || hours > 24 * 31) throw new Error("--hours must be between 0 and 744");
  const namespaceId = opts.get("namespace-id");
  if (namespaceId !== undefined && !/^[0-9a-f]{32}$/.test(namespaceId)) {
    throw new Error("--namespace-id must be 32 hex characters");
  }
  const args: Args = { relay: url.origin, connections, hours };
  if (namespaceId) args.namespaceId = namespaceId;
  const start = opts.get("start");
  const end = opts.get("end");
  if (start || end) {
    const s = new Date(start ?? "");
    const e = new Date(end ?? "");
    if (Number.isNaN(s.getTime()) || Number.isNaN(e.getTime()) || e <= s) {
      throw new Error("--start and --end must both be ISO times, end after start");
    }
    args.analyzeOnly = { start: s, end: e };
  }
  return args;
}

export const GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql";

/** Splits a window into slices of at most a day: the analytics datasets limit a query's range. */
export function slices(start: Date, end: Date, maxMs = 24 * MS_PER_HOUR): { start: Date; end: Date }[] {
  const out: { start: Date; end: Date }[] = [];
  for (let t = start.getTime(); t < end.getTime(); t += maxMs) {
    out.push({ start: new Date(t), end: new Date(Math.min(t + maxMs, end.getTime())) });
  }
  return out;
}

/**
 * The GraphQL query for one slice. Values are validated and inlined (account ids and namespace ids
 * are hex, times are ISO), so no input type names are needed.
 */
export function buildQuery(accountId: string, start: Date, end: Date, namespaceId?: string): string {
  if (!/^[0-9a-f]{32}$/.test(accountId)) throw new Error("CF_ACCOUNT_ID must be 32 hex characters");
  const ns = namespaceId ? `, namespaceId: "${namespaceId}"` : "";
  const s = start.toISOString();
  const e = end.toISOString();
  return `query IdleCost {
  viewer {
    accounts(filter: { accountTag: "${accountId}" }) {
      periodic: durableObjectsPeriodicGroups(
        limit: 10000
        filter: { datetimeMinute_geq: "${s}", datetimeMinute_lt: "${e}"${ns} }
      ) {
        sum { activeTime cpuTime inboundWebsocketMsgCount outboundWebsocketMsgCount }
      }
      invocations: durableObjectsInvocationsAdaptiveGroups(
        limit: 10000
        filter: { datetime_geq: "${s}", datetime_lt: "${e}"${ns} }
      ) {
        sum { requests }
      }
    }
  }
}`;
}

export interface Usage {
  /** Microseconds the objects were awake (billed duration). */
  activeTimeUs: number;
  cpuTimeUs: number;
  inboundWebsocketMsgs: number;
  outboundWebsocketMsgs: number;
  /** Requests as analytics count them (incoming WebSocket messages 1:1, not 20:1). */
  requests: number;
}

export const ZERO_USAGE: Usage = { activeTimeUs: 0, cpuTimeUs: 0, inboundWebsocketMsgs: 0, outboundWebsocketMsgs: 0, requests: 0 };

export function addUsage(a: Usage, b: Usage): Usage {
  return {
    activeTimeUs: a.activeTimeUs + b.activeTimeUs,
    cpuTimeUs: a.cpuTimeUs + b.cpuTimeUs,
    inboundWebsocketMsgs: a.inboundWebsocketMsgs + b.inboundWebsocketMsgs,
    outboundWebsocketMsgs: a.outboundWebsocketMsgs + b.outboundWebsocketMsgs,
    requests: a.requests + b.requests,
  };
}

const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);

/** Sums one GraphQL answer; throws with the API's own error messages when it reports any. */
export function parseAnalytics(answer: unknown): Usage {
  const a = answer as {
    errors?: { message?: string }[] | null;
    data?: { viewer?: { accounts?: { periodic?: { sum?: Record<string, unknown> }[]; invocations?: { sum?: Record<string, unknown> }[] }[] } };
  };
  if (a?.errors && a.errors.length > 0) {
    throw new Error(`GraphQL Analytics API: ${a.errors.map((e) => e.message ?? "error").join("; ")}`);
  }
  const accounts = a?.data?.viewer?.accounts;
  if (!Array.isArray(accounts)) throw new Error("GraphQL Analytics API: unexpected answer (no accounts)");
  let usage = { ...ZERO_USAGE };
  for (const acc of accounts) {
    for (const g of acc.periodic ?? []) {
      usage = addUsage(usage, {
        activeTimeUs: num(g.sum?.activeTime),
        cpuTimeUs: num(g.sum?.cpuTime),
        inboundWebsocketMsgs: num(g.sum?.inboundWebsocketMsgCount),
        outboundWebsocketMsgs: num(g.sum?.outboundWebsocketMsgCount),
        requests: 0,
      });
    }
    for (const g of acc.invocations ?? []) usage = addUsage(usage, { ...ZERO_USAGE, requests: num(g.sum?.requests) });
  }
  return usage;
}

export interface CostReport {
  hours: number;
  connections: number;
  usage: Usage;
  /** Per always-on connection, per month (730 h), extrapolated from the window. */
  perConnectionMonth: {
    activeSeconds: number;
    durationGbS: number;
    durationUsd: number;
    /** Upper bound: counts every request 1:1, though incoming WebSocket messages bill at 20:1. */
    requests: number;
    requestsUsd: number;
    totalUsd: number;
  };
  /** The same connection if its object never slept (an SSE stream held by the object itself). */
  awakeBaseline: { durationGbS: number; durationUsd: number };
  /** Share of the month the object was awake. */
  awakeFraction: number;
  verdict: "hibernates" | "partly-awake" | "always-awake";
}

export function computeCost(usage: Usage, connections: number, hours: number): CostReport {
  const scale = HOURS_PER_MONTH / hours / connections;
  const activeSeconds = (usage.activeTimeUs / 1e6) * scale;
  const durationGbS = activeSeconds * PRICING.gbPerObject;
  const durationUsd = (durationGbS * PRICING.durationUsdPerMillionGbS) / 1e6;
  const requests = usage.requests * scale;
  const requestsUsd = (requests * PRICING.requestUsdPerMillion) / 1e6;
  const monthSeconds = HOURS_PER_MONTH * 3600;
  const baselineGbS = monthSeconds * PRICING.gbPerObject;
  const awakeFraction = activeSeconds / monthSeconds;
  return {
    hours,
    connections,
    usage,
    perConnectionMonth: {
      activeSeconds,
      durationGbS,
      durationUsd,
      requests,
      requestsUsd,
      totalUsd: durationUsd + requestsUsd,
    },
    awakeBaseline: { durationGbS: baselineGbS, durationUsd: (baselineGbS * PRICING.durationUsdPerMillionGbS) / 1e6 },
    awakeFraction,
    verdict: awakeFraction < 0.01 ? "hibernates" : awakeFraction < 0.5 ? "partly-awake" : "always-awake",
  };
}

const usd = (n: number) => `$${n < 0.01 ? n.toFixed(6) : n.toFixed(4)}`;

export function formatReport(r: CostReport): string {
  const p = r.perConnectionMonth;
  const verdicts = {
    hibernates: "The bridge works: the object slept while the streams idled (awake under 1% of the time).",
    "partly-awake":
      "Inconclusive: the object was awake for part of the window. Check for alarms, pings that wake it, or traffic during the run.",
    "always-awake":
      "The bridge does NOT hibernate: the object stayed awake as if it held the streams itself. Use the direct WebSocket fallback (PLAN §10).",
  } as const;
  return [
    `Window: ${r.hours} h, ${r.connections} connection(s).`,
    `Measured: ${(r.usage.activeTimeUs / 1e6).toFixed(1)} s awake, ${r.usage.cpuTimeUs} µs CPU, ` +
      `${r.usage.requests} requests, ${r.usage.inboundWebsocketMsgs} WebSocket messages in, ${r.usage.outboundWebsocketMsgs} out.`,
    `Per always-on connection per month (730 h, marginal, before the included allowances):`,
    `  duration  ${p.activeSeconds.toFixed(1)} s awake = ${p.durationGbS.toFixed(2)} GB-s = ${usd(p.durationUsd)}`,
    `  requests  ${p.requests.toFixed(0)} (upper bound) = ${usd(p.requestsUsd)}`,
    `  total     ${usd(p.totalUsd)}`,
    `If the object never slept: ${r.awakeBaseline.durationGbS.toFixed(0)} GB-s = ${usd(r.awakeBaseline.durationUsd)} per connection per month.`,
    `Awake ${(r.awakeFraction * 100).toFixed(3)}% of the time. ${verdicts[r.verdict]}`,
  ].join("\n");
}

/**
 * The wait before reconnect number `attempt` (0 for the first after a drop; reset by `ready`):
 * a random time between half and all of `min(30 s, retry × 2^attempt)`, never under 1 s
 * (PROTOCOL §6).
 */
export function backoffMs(attempt: number, random: () => number = Math.random, retryMs = 5000): number {
  const d = Math.min(30_000, retryMs * 2 ** Math.max(0, attempt));
  return Math.round(Math.max(1000, d / 2 + random() * (d / 2)));
}
