// Measures what an always-on, idle stream costs on a deployed relay (PLAN §10). See
// docs/IDLE-COST.md. Run with Node 22.18+ (type stripping):
//
//   pnpm --filter ./relay idle-cost -- --relay https://<your relay> --connections 10 --hours 24
//
// It creates one account per connection (each always-on user has their own Durable Object), holds a
// signed SSE stream open for each for the whole window, reconnecting as a client would, and logs
// heartbeats and reconnects. Then, when CF_ACCOUNT_ID and CF_API_TOKEN (an Analytics-read token) are
// in the environment, it asks Cloudflare's GraphQL Analytics API what the Durable Objects used in
// that window and prints the cost per connection per month. Neither value is stored or printed.
// SIGNUP_TOKEN, when the relay requires one, is read from the environment too.

import { generateDeviceKey, signRequest, type DeviceKey } from "../src/canonical.ts";
import {
  GRAPHQL_ENDPOINT,
  ZERO_USAGE,
  addUsage,
  backoffMs,
  buildQuery,
  computeCost,
  formatReport,
  parseAnalytics,
  parseArgs,
  slices,
} from "./idle-cost-lib.ts";

declare const process: {
  argv: string[];
  env: Record<string, string | undefined>;
  exit(code?: number): never;
};

const DEAD_AFTER_MS = 70_000;
const SUMMARY_EVERY_MS = 10 * 60_000;

function log(...parts: unknown[]): void {
  console.log(new Date().toISOString(), ...parts);
}

async function createAccount(relay: string, i: number): Promise<DeviceKey> {
  const { privateKey, publicKey } = await generateDeviceKey();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (process.env.SIGNUP_TOKEN) headers.Authorization = `Bearer ${process.env.SIGNUP_TOKEN}`;
  const res = await fetch(`${relay}/v1/accounts`, {
    method: "POST",
    headers,
    body: JSON.stringify({ deviceName: `idle-cost-${i}`, publicKey }),
  });
  if (res.status !== 201) throw new Error(`account creation failed: ${res.status} ${await res.text()}`);
  const { deviceId } = (await res.json()) as { deviceId: string };
  return { deviceId, privateKey };
}

interface Counters {
  heartbeats: number;
  reconnects: number;
  events: number;
  terminal: number;
}

/** Holds one stream open until `signal` aborts, reconnecting on drops (PROTOCOL §6). */
async function hold(relay: string, i: number, key: DeviceKey, signal: AbortSignal, c: Counters): Promise<void> {
  let lastEventId: string | null = null;
  let skewMs = 0;
  let attempt = 0;
  while (!signal.aborted) {
    const url = `${relay}/v1/stream`;
    const headers: Record<string, string> = {
      Accept: "text/event-stream",
      ...(await signRequest(key, "GET", url, undefined, { time: Date.now() + skewMs })),
    };
    if (lastEventId) headers["Last-Event-ID"] = lastEventId;
    const inner = new AbortController();
    const onAbort = () => inner.abort();
    signal.addEventListener("abort", onAbort);
    let reason = "ended";
    try {
      const res = await fetch(url, { headers, signal: inner.signal });
      if (res.status === 401) {
        const body = (await res.json().catch(() => ({}))) as { error?: string; serverTime?: number };
        if (body.error === "clock_skew" && body.serverTime) {
          skewMs = body.serverTime - Date.now();
          log(`conn ${i}: clock skew ${skewMs} ms, retrying with the server's time`);
          continue;
        }
        log(`conn ${i}: refused (401), stopping`);
        c.terminal++;
        return;
      }
      if (res.status !== 200 || !res.body) throw new Error(`status ${res.status}`);
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let lastByte = Date.now();
      const watchdog = setInterval(() => {
        if (Date.now() - lastByte > DEAD_AFTER_MS) {
          reason = "no bytes for 70 s";
          inner.abort();
        }
      }, 5000);
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          lastByte = Date.now();
          buffer += decoder.decode(value, { stream: true });
          let end: number;
          while ((end = buffer.indexOf("\n\n")) >= 0) {
            const block = buffer.slice(0, end);
            buffer = buffer.slice(end + 2);
            if (block.startsWith(": hb")) {
              c.heartbeats++;
              continue;
            }
            const id = /^id: (.*)$/m.exec(block)?.[1];
            if (id) lastEventId = id;
            const event = /^event: (.*)$/m.exec(block)?.[1];
            const data = /^data: (.*)$/m.exec(block)?.[1];
            if (event === "ready") attempt = 0;
            if (event === "hook") c.events++;
            if (event === "resync" && data) lastEventId = String((JSON.parse(data) as { after: number }).after);
            if (event === "closed" && data) {
              const code = (JSON.parse(data) as { code: number }).code;
              reason = `closed ${code}`;
              if (code === 4401 || code === 4409) {
                log(`conn ${i}: closed with ${code}, stopping`);
                c.terminal++;
                return;
              }
            }
          }
        }
      } finally {
        clearInterval(watchdog);
      }
    } catch (e) {
      if (signal.aborted) return;
      if (reason === "ended") reason = e instanceof Error ? e.message : "error";
    } finally {
      signal.removeEventListener("abort", onAbort);
    }
    if (signal.aborted) return;
    c.reconnects++;
    const wait = backoffMs(attempt);
    attempt++;
    log(`conn ${i}: ${reason}; reconnecting in ${wait} ms (Last-Event-ID ${lastEventId ?? "none"})`);
    await new Promise((r) => setTimeout(r, wait));
  }
}

async function analyse(start: Date, end: Date, connections: number, namespaceId?: string): Promise<void> {
  const accountId = process.env.CF_ACCOUNT_ID;
  const token = process.env.CF_API_TOKEN;
  if (!accountId || !token) {
    log("CF_ACCOUNT_ID and CF_API_TOKEN aren't set: skipping the analytics query. To analyse later:");
    log(`  idle-cost -- --relay <url> --connections ${connections} --start ${start.toISOString()} --end ${end.toISOString()}`);
    return;
  }
  if (!namespaceId) log("No --namespace-id: summing every Durable Object namespace on the account.");
  let usage = { ...ZERO_USAGE };
  for (const s of slices(start, end)) {
    const res = await fetch(GRAPHQL_ENDPOINT, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ query: buildQuery(accountId, s.start, s.end, namespaceId) }),
    });
    if (!res.ok) throw new Error(`GraphQL Analytics API answered ${res.status}`);
    usage = addUsage(usage, parseAnalytics(await res.json()));
  }
  const hours = (end.getTime() - start.getTime()) / 3_600_000;
  console.log(`\n${formatReport(computeCost(usage, connections, hours))}`);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.analyzeOnly) {
    await analyse(args.analyzeOnly.start, args.analyzeOnly.end, args.connections, args.namespaceId);
    return;
  }
  const info = (await (await fetch(`${args.relay}/v1/info`)).json()) as { version: string; protocol: number };
  log(`relay ${args.relay}: version ${info.version}, protocol ${info.protocol}`);

  const keys: DeviceKey[] = [];
  for (let i = 0; i < args.connections; i++) keys.push(await createAccount(args.relay, i));
  log(`created ${keys.length} account(s); holding ${keys.length} stream(s) for ${args.hours} h`);

  const stop = new AbortController();
  const counters: Counters = { heartbeats: 0, reconnects: 0, events: 0, terminal: 0 };
  const start = new Date();
  const summary = setInterval(() => log("summary", JSON.stringify(counters)), SUMMARY_EVERY_MS);
  const holders = keys.map((k, i) => hold(args.relay, i, k, stop.signal, counters));
  await new Promise((r) => setTimeout(r, args.hours * 3_600_000));
  stop.abort();
  await Promise.allSettled(holders);
  clearInterval(summary);
  const end = new Date();
  const expected = Math.floor((end.getTime() - start.getTime()) / 15_000) * args.connections;
  log("done", JSON.stringify({ ...counters, expectedHeartbeats: expected, start: start.toISOString(), end: end.toISOString() }));
  log("Analytics lag a few minutes behind; if the numbers look short, re-run with --start/--end later.");
  await analyse(start, end, args.connections, args.namespaceId);
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
