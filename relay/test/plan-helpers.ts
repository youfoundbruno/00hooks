// Helpers for the plan and entitlement tests: the Worker called with configuration on top of the
// test env (PLANS, entitlement keys, …), the edge's Rate Limiting bindings out of the way.

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import worker from "../src/index.ts";
import { signRequest } from "../src/canonical.ts";
import { utf8 } from "../src/encoding.ts";
import { BASE, randomTestIp, type TestDevice } from "./helpers.ts";

/** A Rate Limiting binding that always lets through: the edge's limits aren't what these tests pin. */
const open = { limit: async () => ({ success: true }) } as unknown as RateLimit;

/** The test env with `vars` on top, and the edge's bindings out of the way. */
export function withVars(vars: Record<string, string | undefined>): Env {
  return { ...env, HOOK_LIMIT: open, RECEIVE_IP_LIMIT: open, API_IP_LIMIT: open, ...vars } as Env;
}

export async function call(e: Env, path: string, init: RequestInit = {}): Promise<Response> {
  const req = new Request(BASE + path, init);
  if (!req.headers.has("CF-Connecting-IP")) req.headers.set("CF-Connecting-IP", randomTestIp());
  const ctx = createExecutionContext();
  const res = await worker.fetch(req, e, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

export async function signedWith(e: Env, dev: TestDevice, method: string, path: string, body?: unknown): Promise<Response> {
  const bytes = body === undefined ? undefined : utf8(JSON.stringify(body));
  const sig = await signRequest(dev, method, BASE + path, bytes);
  return call(e, path, { method, headers: { ...(bytes ? { "Content-Type": "application/json" } : {}), ...sig }, body: bytes });
}

export const post = (e: Env, hookId: string, payload: unknown = { n: Math.random() }) =>
  call(e, `/h/${hookId}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });

