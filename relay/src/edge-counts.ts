// Counting at the edge (PROTOCOL §4, §9): a forged signature, a failed endpoint check or a screen
// drop is counted in the Worker's memory and written to the account's Durable Object at most once a
// minute per hook per Worker instance, never once per request. A hook's URL is public (providers are
// handed it), so a flood of junk must not wake and write the account's object on every request.
//
// The counts are approximate by design: what an instance counted after its last write and never
// wrote (it was evicted) is lost. `/v1/audit` reads what was written.

import { accountStub } from "./auth.ts";

/** How often one instance writes one hook's counts. */
export const EDGE_FLUSH_MS = 60_000;
let flushMs = EDGE_FLUSH_MS;
/** Hooks one instance keeps counts for; past it, the oldest entry is written out and forgotten. */
const MAX_ENTRIES = 1024;

export type EdgeKind = "verify.failed" | "screen.dropped";

interface Entry {
  accountId: string;
  kind: EdgeKind;
  hookId: string;
  name: string | null;
  count: number;
  writtenAt: number;
}

const counts = new Map<string, Entry>();

function write(env: Env, ctx: ExecutionContext, e: Entry): void {
  const n = e.count;
  if (n === 0) return;
  e.count = 0;
  const stub = accountStub(env, e.accountId);
  const p = e.kind === "verify.failed" ? stub.recordFailures(e.hookId, n) : stub.countAudit("screen.dropped", e.hookId, e.name, n);
  ctx.waitUntil(Promise.resolve(p).catch(() => {}));
}

/**
 * Counts one occurrence. The first for a hook in an instance is written at once (so a single
 * failure shows up in the audit log), later ones once `EDGE_FLUSH_MS` has passed since the last write.
 */
export function countAtEdge(
  env: Env,
  ctx: ExecutionContext,
  accountId: string,
  kind: EdgeKind,
  hookId: string,
  name: string | null = null,
): void {
  const key = `${kind}\n${hookId}`;
  let e = counts.get(key);
  if (!e) {
    if (counts.size >= MAX_ENTRIES) {
      const [oldest, entry] = counts.entries().next().value as [string, Entry];
      write(env, ctx, entry);
      counts.delete(oldest);
    }
    e = { accountId, kind, hookId, name, count: 0, writtenAt: 0 };
    counts.set(key, e);
  }
  e.count++;
  e.name = name;
  const now = Date.now();
  if (now - e.writtenAt >= flushMs) {
    e.writtenAt = now;
    write(env, ctx, e);
  }
}

/** For tests: forgets every pending count, and sets how often counts are written (0: every time). */
export function resetEdgeCounts(every = EDGE_FLUSH_MS): void {
  counts.clear();
  flushMs = every;
}
