// The 00hooks relay Worker: routes, signed-request checks, and the SSE bridge's front half.
// The contract is docs/PROTOCOL.md at the repository root.

import { createAccount, createEnrolment, listDevices, redeemEnrolment, revokeDevice } from "./accounts.ts";
import { authenticate, type Caller } from "./auth.ts";
import { isId } from "./encoding.ts";
import { HttpError, json, notFound, readLimited, tooLarge } from "./http.ts";
import { createHook, deleteHook, getHook, listHooks, patchHook, rotateHook } from "./hooks.ts";
import { receive } from "./receive.ts";
import { ack, openStream } from "./stream.ts";
import { VERSION } from "./version.ts";

// The main module may export only handlers and Durable Object classes: workerd refuses anything
// else (a plain constant here stops the Worker from starting).
export { AccountObject } from "./account-object.ts";

const PROTOCOL_VERSION = 1;
/** Management requests are small JSON; anything bigger is refused before it's hashed. */
const API_BODY_LIMIT = 64 * 1024;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await route(request, env, ctx);
    } catch (e) {
      if (e instanceof HttpError) return e.response;
      // Never echo the exception: it could quote a payload or a secret.
      console.error("relay error", e instanceof Error ? e.name : "unknown");
      return json({ error: "internal", message: "The relay failed to handle this request." }, 500);
    }
  },
} satisfies ExportedHandler<Env>;

async function route(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // Webhook deliveries.
  const h = /^\/h\/([^/]+)\/?$/.exec(path);
  if (h) {
    if (method !== "POST" && method !== "PUT" && method !== "PATCH") return notFound();
    return receive(request, env, ctx, h[1]!);
  }

  if (!path.startsWith("/v1/")) return notFound();

  if (path === "/v1/info" && method === "GET") {
    return json({ version: VERSION, protocol: PROTOCOL_VERSION, signupOpen: !env.SIGNUP_TOKEN, serverTime: Date.now() });
  }

  const body = await readLimited(request, API_BODY_LIMIT);
  if (body === null) return tooLarge();

  // Unsigned: account creation and enrolment redemption.
  if (path === "/v1/accounts" && method === "POST") return createAccount(request, env, body);
  if (path === "/v1/enrolments/redeem" && method === "POST") return redeemEnrolment(request, env, body);

  const signed = (): Promise<Caller> => authenticate(request, env, ctx, body);
  const origin = url.origin;

  if (path === "/v1/enrolments" && method === "POST") return createEnrolment(env, await signed());
  if (path === "/v1/devices" && method === "GET") return listDevices(env, await signed());
  const dev = /^\/v1\/devices\/([^/]+)$/.exec(path);
  if (dev && method === "DELETE") {
    const caller = await signed();
    return isId("dev", dev[1]) ? revokeDevice(env, caller, dev[1]) : notFound();
  }

  if (path === "/v1/hooks") {
    if (method === "POST") return createHook(env, await signed(), origin, body);
    if (method === "GET") return listHooks(env, await signed(), origin);
    return notFound();
  }
  const hk = /^\/v1\/hooks\/([^/]+)(\/rotate)?$/.exec(path);
  if (hk) {
    const id = hk[1]!;
    const rotate = hk[2] !== undefined;
    if (rotate && method !== "POST") return notFound();
    if (!rotate && method !== "GET" && method !== "PATCH" && method !== "DELETE") return notFound();
    const caller = await signed();
    if (!isId("hk", id)) return notFound();
    if (rotate) return rotateHook(env, caller, id);
    if (method === "GET") return getHook(env, caller, origin, id);
    if (method === "PATCH") return patchHook(env, caller, origin, id, body);
    return deleteHook(env, caller, id);
  }

  if (path === "/v1/stream" && method === "GET") return openStream(request, env, await signed());
  if (path === "/v1/ack" && method === "POST") return ack(env, await signed(), body);

  return notFound();
}
