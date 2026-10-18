// The 00hooks relay Worker: routes, signed-request checks, and the SSE bridge's front half.
// The contract is docs/PROTOCOL.md at the repository root.

import { createAccount, createEnrolment, listDevices, putSealKey, redeemEnrolment, revokeDevice, signupOpen } from "./accounts.ts";
import { listEvents, readAudit } from "./audit.ts";
import { authenticate, deviceAsPrincipal, type Caller, type Principal } from "./auth.ts";
import { importRelayKey } from "./envelope.ts";
import { describeError } from "./describe-error.ts";
import { isId } from "./encoding.ts";
import { HttpError, error, forbidden, json, notFound, readLimited, tooLarge, unavailable } from "./http.ts";
import { clientKey } from "./ip.ts";
import { pruneD1 } from "./prune.ts";
import { RATE_LIMIT_PERIOD_S } from "./receive.ts";
import { createHook, deleteHook, getHook, getScreen, listHooks, patchHook, putScreen, rotateHook } from "./hooks.ts";
import { dropHeld, dropHeldBulk, listHeld, releaseHeld, screenInfo, screenKeyFor } from "./held.ts";
import { authenticateKey, createKey, deviceOnly, listKeys, presentsKey, revokeKey, type Scope } from "./keys.ts";
import { confirmPhone, createPairing, listPhones, openPhoneSocket, redeemPairing, unpairSelf } from "./phone.ts";
import { PHONE_PROTOCOL } from "./phone-object.ts";
import { receive, receiveGet } from "./receive.ts";
import { ack, openStream } from "./stream.ts";
import { PROTOCOLS, STREAM_PROTOCOL, VERSION } from "./version.ts";

// The main module may export only handlers and Durable Object classes: workerd refuses anything
// else (a plain constant here stops the Worker from starting).
export { AccountObject } from "./account-object.ts";
export { PhoneObject } from "./phone-object.ts";

/** Management requests are small JSON; anything bigger is refused before it's hashed. */
const API_BODY_LIMIT = 64 * 1024;
/** A hook's screen (PROTOCOL §4b) carries up to 200 rules with fingerprints. */
const SCREEN_BODY_LIMIT = 512 * 1024;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await route(request, env, ctx);
    } catch (e) {
      if (e instanceof HttpError) return e.response;
      // Never echo the exception to the client, and log only a scrubbed cause: quoted text is
      // removed (a parse error can quote a payload) and the message is capped.
      console.error("relay error", describeError(e));
      return json({ error: "internal", message: "The relay failed to handle this request." }, 500);
    }
  },

  /** The daily cron trigger (wrangler.jsonc): deletes D1 rows past their use. */
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(pruneD1(env, Date.now()).catch((e: unknown) => console.error("prune failed", describeError(e))));
  },
} satisfies ExportedHandler<Env>;

async function route(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // Webhook deliveries.
  const h = /^\/h\/([^/]+)\/?$/.exec(path);
  if (h) {
    // GET is only ever an endpoint check (Meta's verify token), answered by the presets that have one.
    if (method === "GET") return receiveGet(request, env, ctx, h[1]!);
    if (method !== "POST" && method !== "PUT" && method !== "PATCH") return notFound();
    return receive(request, env, ctx, h[1]!);
  }

  if (!path.startsWith("/v1/")) return notFound();

  if (path === "/v1/info" && method === "GET") {
    // The relay's envelope-signing key: clients pin it at login and check every envelope with it.
    const relayKey = (await importRelayKey(env.RELAY_SIGNING_KEY))?.publicKey ?? null;
    return json({
      version: VERSION,
      protocol: STREAM_PROTOCOL,
      protocols: PROTOCOLS,
      signupOpen: signupOpen(env),
      relayKey,
      serverTime: Date.now(),
      ...screenInfo(env),
      phone: { protocol: PHONE_PROTOCOL },
    });
  }

  // Per client address, before the body is read or anything is looked up (PROTOCOL §2): a flood of
  // management requests costs the sender their budget, not the relay a database read each.
  if (!env.API_IP_LIMIT) return unavailable();
  if (!(await env.API_IP_LIMIT.limit({ key: clientKey(request) })).success) {
    return error(429, "rate_limited", "Too many requests from this address; slow down.", {}, { "Retry-After": String(RATE_LIMIT_PERIOD_S) });
  }

  const isScreenPut = method === "PUT" && /^\/v1\/hooks\/[^/]+\/screen$/.test(path);
  const body = await readLimited(request, isScreenPut ? SCREEN_BODY_LIMIT : API_BODY_LIMIT);
  if (body === null) return tooLarge();

  // Unsigned: account creation and enrolment redemption.
  if (path === "/v1/accounts" && method === "POST") return createAccount(request, env, body);
  if (path === "/v1/enrolments/redeem" && method === "POST") return redeemEnrolment(request, env, body);
  if (path === "/v1/phone/pair" && method === "POST") return redeemPairing(request, env, body);

  // A device's signature may do anything its account may; an API key only what its scopes allow,
  // and never what only a device may (the stream, acks, enrolments, sealing keys, keys themselves).
  // A phone may use only the phone routes (PROTOCOL §10).
  const notPhone = (c: Caller): Caller => {
    if (c.kind === "phone") throw new HttpError(forbidden("A phone may use only the phone routes."));
    return c;
  };
  const signed = async (): Promise<Caller> => (presentsKey(request) ? deviceOnly() : notPhone(await authenticate(request, env, ctx, body)));
  const scoped = async (scope: Scope): Promise<Principal> =>
    presentsKey(request)
      ? authenticateKey(request, env, ctx, scope)
      : deviceAsPrincipal(notPhone(await authenticate(request, env, ctx, body)));
  const origin = url.origin;

  // The phone routes: a node device, a phone, or either; a pending phone only where `pending` says.
  const phoneRoute = async (allow: { device: boolean; phone: boolean; pending?: boolean }): Promise<Caller> => {
    if (presentsKey(request)) deviceOnly();
    const c = await authenticate(request, env, ctx, body);
    if (c.kind === "phone" && !allow.phone) throw new HttpError(forbidden("Only a node device can do this, not a phone."));
    if (c.kind !== "phone" && !allow.device) throw new HttpError(forbidden("Only a phone can do this."));
    if (c.kind === "phone" && c.pendingUntil !== null && !allow.pending) {
      throw new HttpError(forbidden("This phone isn't confirmed by its node yet."));
    }
    return c;
  };
  if (path.startsWith("/v1/phone/")) {
    if (path === "/v1/phone/pairings" && method === "POST") return createPairing(env, await phoneRoute({ device: true, phone: false }), body);
    if (path === "/v1/phone/devices" && method === "GET") return listPhones(env, await phoneRoute({ device: true, phone: false }));
    const cf = /^\/v1\/phone\/devices\/([^/]+)\/confirm$/.exec(path);
    if (cf && method === "POST") return confirmPhone(env, await phoneRoute({ device: true, phone: false }), cf[1]!);
    if (path === "/v1/phone/self" && method === "DELETE") return unpairSelf(env, await phoneRoute({ device: false, phone: true, pending: true }));
    if (path === "/v1/phone/socket" && method === "GET") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return error(426, "invalid", "The phone socket is a WebSocket: send Upgrade: websocket.", { field: "Upgrade" }, { Upgrade: "websocket" });
      }
      return openPhoneSocket(env, await phoneRoute({ device: true, phone: true, pending: true }));
    }
    return notFound();
  }

  if (path === "/v1/enrolments" && method === "POST") return createEnrolment(env, await signed());
  if (path === "/v1/devices" && method === "GET") return listDevices(env, await scoped("devices:write"));
  const dev = /^\/v1\/devices\/([^/]+)(\/seal-key)?$/.exec(path);
  if (dev && dev[2] && method === "PUT") {
    const caller = await signed();
    return isId("dev", dev[1]) ? putSealKey(env, caller, dev[1]!, body) : notFound();
  }
  if (dev && !dev[2] && method === "DELETE") {
    const caller = await scoped("devices:write");
    return isId("dev", dev[1]) ? revokeDevice(env, caller, dev[1]) : notFound();
  }

  if (path === "/v1/keys") {
    if (method === "POST") return createKey(env, await signed(), body);
    if (method === "GET") return listKeys(env, await signed());
    return notFound();
  }
  const key = /^\/v1\/keys\/([^/]+)$/.exec(path);
  if (key && method === "DELETE") return revokeKey(env, await signed(), key[1]!);

  if (path === "/v1/audit" && method === "GET") return readAudit(env, await scoped("audit:read"), url);
  if (path === "/v1/events" && method === "GET") return listEvents(env, await scoped("events:read"), url);

  if (path === "/v1/hooks") {
    if (method === "POST") return createHook(env, await scoped("hooks:write"), origin, body);
    if (method === "GET") return listHooks(env, await scoped("hooks:read"), origin);
    return notFound();
  }
  const sc = /^\/v1\/hooks\/([^/]+)\/screen$/.exec(path);
  if (sc) {
    if (method !== "GET" && method !== "PUT") return notFound();
    const caller = await scoped(method === "GET" ? "hooks:read" : "hooks:write");
    if (!isId("hk", sc[1])) return notFound();
    return method === "GET" ? getScreen(env, caller, sc[1]!) : putScreen(env, caller, sc[1]!, body);
  }
  if (path === "/v1/screen/key" && method === "GET") return screenKeyFor(env, await signed());
  if (path === "/v1/held" && method === "GET") return listHeld(env, await scoped("events:read"));
  if (path === "/v1/held" && method === "DELETE") return dropHeldBulk(env, await scoped("hooks:write"), url);
  const hd = /^\/v1\/held\/([^/]+)(\/release)?$/.exec(path);
  if (hd) {
    const release = hd[2] !== undefined;
    if (release ? method !== "POST" : method !== "DELETE") return notFound();
    const caller = await scoped("hooks:write");
    if (!isId("evt", hd[1])) return notFound();
    return release ? releaseHeld(env, caller, hd[1]!) : dropHeld(env, caller, hd[1]!);
  }

  const hk = /^\/v1\/hooks\/([^/]+)(\/rotate)?$/.exec(path);
  if (hk) {
    const id = hk[1]!;
    const rotate = hk[2] !== undefined;
    if (rotate && method !== "POST") return notFound();
    if (!rotate && method !== "GET" && method !== "PATCH" && method !== "DELETE") return notFound();
    // Rotating returns the new secret: `hooks:secrets`, never `hooks:write` alone (PROTOCOL §9).
    const caller = await scoped(rotate ? "hooks:secrets" : method === "GET" ? "hooks:read" : "hooks:write");
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

