// `POST /v1/phone/push` (PROTOCOL §10.7): a node asks the relay to wake one of its phones through
// APNs. The node keeps the phone's device token (the phone sends it sealed to its node) and decides
// what to push; the relay checks the phone is the node's, applies its limits, and sends a fixed,
// opaque alert. It stores no token, and nothing from the request but the kind, the ref and the
// sealed preview reaches the payload. Kept out of index.ts: the main module may export only
// handlers and Durable Object classes.

import { apnsConfig, providerToken, sendToApns, type ApnsConfig, type ApnsResult } from "./apns.ts";
import { phoneStub, type Caller } from "./auth.ts";
import { isId } from "./encoding.ts";
import { HttpError, error, invalid, json, parseJsonObject } from "./http.ts";
import { isStandardBase64 } from "./phone-object.ts";

export const PUSH_KINDS = ["approval", "ask", "finished", "handoff", "reconnect", "task", "done", "drive"] as const;
export type PushKind = (typeof PUSH_KINDS)[number];

/** The alert for each kind: fixed texts, so nothing the node or an agent wrote is shown by Apple. */
export const PUSH_TEXTS: Record<PushKind, { title: string; body: string; category: string }> = {
  approval: { title: "An agent needs you", body: "Approval needed.", category: "APPROVAL" },
  ask: { title: "An agent needs you", body: "It asked you something.", category: "ASK" },
  finished: { title: "An agent finished", body: "Open the app to see what it did.", category: "FINISHED" },
  handoff: { title: "Continue on your phone", body: "A conversation was handed to this phone.", category: "HANDOFF" },
  reconnect: { title: "Your Mac is back online", body: "Open the app to reconnect.", category: "RECONNECT" },
  task: { title: "Something needs you", body: "An agent left you a task.", category: "TASK" },
  done: { title: "Done", body: "A task from a meeting is done.", category: "DONE" },
  drive: { title: "Your Mac needs you", body: "Open 00next on your Mac to decide.", category: "DRIVE" },
};

/** The largest sealed preview (`preview.ct`, in base64 characters): the payload stays well under APNs' 4 KiB. */
export const PREVIEW_CT_MAX = 1400;

export interface PushPreview {
  at: number;
  enc: string;
  ct: string;
  sig: string;
}

export interface PushRequest {
  device: string;
  token: string;
  environment?: "sandbox" | "production";
  kind: PushKind;
  ref: string;
  preview?: PushPreview;
}

const FIELDS = new Set(["device", "token", "environment", "kind", "ref", "preview"]);
const PREVIEW_FIELDS = new Set(["at", "enc", "ct", "sig"]);

const bad = (field: string, message: string) => new HttpError(invalid(field, message));

/** Checks the body's shape; throws `400 invalid` naming the first field that is wrong. */
export function parsePushRequest(body: Uint8Array): PushRequest {
  const input = parseJsonObject(body);
  for (const k of Object.keys(input)) {
    // The unknown field is named only when it is a plain word: nothing else from the body is echoed.
    if (!FIELDS.has(k)) throw bad(/^[A-Za-z0-9_-]{1,40}$/.test(k) ? k : "body", "A push request has only device, token, environment, kind, ref and preview.");
  }
  if (!isId("dev", input.device)) throw bad("device", "device must be a phone's device id.");
  const token = input.token;
  if (typeof token !== "string" || token.length < 32 || token.length > 400 || token.length % 2 !== 0 || !/^[0-9a-f]+$/.test(token)) {
    throw bad("token", "token must be the APNs device token in lowercase hex (32 to 400 characters, an even number).");
  }
  const environment = input.environment;
  if (environment !== undefined && environment !== "sandbox" && environment !== "production") {
    throw bad("environment", "environment must be sandbox or production.");
  }
  const kind = input.kind;
  if (typeof kind !== "string" || !(PUSH_KINDS as readonly string[]).includes(kind)) {
    throw bad("kind", `kind must be one of ${PUSH_KINDS.join(", ")}.`);
  }
  const ref = input.ref;
  if (typeof ref !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(ref)) throw bad("ref", "ref must be 22 characters of unpadded base64url.");
  const out: PushRequest = { device: input.device, token, kind: kind as PushKind, ref };
  if (environment !== undefined) out.environment = environment;
  if (input.preview !== undefined) out.preview = previewField(input.preview);
  return out;
}

function previewField(v: unknown): PushPreview {
  const fail = () =>
    bad(
      "preview",
      `preview must be { at, enc, ct, sig }: an integer time in ms, a 43-character base64url enc, a standard base64 ct of at most ${PREVIEW_CT_MAX} characters and an 86-character base64url sig.`,
    );
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw fail();
  const p = v as Record<string, unknown>;
  const keys = Object.keys(p);
  if (keys.length !== PREVIEW_FIELDS.size || keys.some((k) => !PREVIEW_FIELDS.has(k))) throw fail();
  if (typeof p.at !== "number" || !Number.isSafeInteger(p.at) || p.at < 0) throw fail();
  if (typeof p.enc !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(p.enc)) throw fail();
  if (!isStandardBase64(p.ct) || p.ct.length > PREVIEW_CT_MAX) throw fail();
  if (typeof p.sig !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(p.sig)) throw fail();
  return { at: p.at, enc: p.enc, ct: p.ct, sig: p.sig };
}

/**
 * The APNs payload, built here only: the fixed alert for the kind, `mutable-content` so the phone's
 * extension can open the sealed preview, and `zn` with the kind, the ref and the preview as given.
 */
export function pushPayload(kind: PushKind, ref: string, preview?: PushPreview): string {
  const t = PUSH_TEXTS[kind];
  return JSON.stringify({
    aps: { alert: { title: t.title, body: t.body }, sound: "default", category: t.category, "mutable-content": 1, "thread-id": kind },
    zn: { v: 1, kind, ref, ...(preview ? { p: { at: preview.at, enc: preview.enc, ct: preview.ct, sig: preview.sig } } : {}) },
  });
}

/** What the PhoneObject decided about a push before anything is sent. */
export type PushAdmission =
  | { ok: true }
  | { ok: false; status: 200; reason: "unavailable" | "environment" | "online" }
  | { ok: false; status: 403 }
  | { ok: false; status: 429; retryAfter: number };

/** `POST /v1/phone/push` (a node device). */
export async function pushToPhone(env: Env, caller: Caller, body: Uint8Array): Promise<Response> {
  const req = parsePushRequest(body);
  const config = await apnsConfig(env);
  const admission = await phoneStub(env, caller.accountId).admitPush({
    node: caller.deviceId,
    phone: req.device,
    kind: req.kind,
    available: config !== null,
    relayEnvironment: config?.environment ?? null,
    requestedEnvironment: req.environment ?? null,
  });
  if (!admission.ok) {
    if (admission.status === 403) return error(403, "forbidden", "That phone isn't paired with this device.");
    if (admission.status === 429) {
      return error(
        429,
        "rate_limited",
        "Too many pushes to this phone; try again later.",
        { retryAfter: admission.retryAfter },
        { "Retry-After": String(admission.retryAfter) },
      );
    }
    return json({ sent: false, reason: admission.reason });
  }
  // Admitted, so available: counted against the phone's limits from here, whatever APNs answers.
  return send(config!, req);
}

/** What a `429` from APNs is passed on with. */
export const APNS_RETRY_AFTER_S = 60;

async function send(config: ApnsConfig, req: PushRequest): Promise<Response> {
  const payload = pushPayload(req.kind, req.ref, req.preview);
  const apnsReq = { token: req.token, collapseId: req.kind, payload };
  let now = Date.now();
  let result: ApnsResult = await sendToApns(config, await providerToken(config, now), apnsReq, now);
  if (result.kind === "provider_token") {
    // APNs called the token expired or invalid: mint a fresh one and try once more.
    now = Date.now();
    result = await sendToApns(config, await providerToken(config, now, true), apnsReq, now);
  }
  // Logs carry the kind, statuses and sizes only: never the token or the payload.
  switch (result.kind) {
    case "sent":
      return json({ sent: true });
    case "unregistered":
      return json({ sent: false, reason: "unregistered" });
    case "rate_limited":
      console.warn("phone push: APNs rate limited", req.kind);
      return error(
        429,
        "rate_limited",
        "Apple's push service is limiting this relay; try again later.",
        { retryAfter: APNS_RETRY_AFTER_S },
        { "Retry-After": String(APNS_RETRY_AFTER_S) },
      );
    case "provider_token":
      console.error("phone push: APNs refused the provider token twice", req.kind);
      return error(502, "push_failed", "Apple's push service refused the relay's credentials.");
    case "failed":
      console.error("phone push failed", req.kind, result.status, result.reason ?? "-", payload.length);
      return error(502, "push_failed", "Apple's push service didn't accept the push.");
  }
}
