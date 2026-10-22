// How a hook's deliveries are answered and to whom they go (PROTOCOL §3): a static response the
// relay sends the provider instead of `{"received": …}`, and the one device that alone receives
// the hook's events. Both are set with `PATCH /v1/hooks/<id>` and kept in the hook's D1 row.

import { isId } from "./encoding.ts";
import { HttpError, invalid, json } from "./http.ts";
import { SPECS, type Preset } from "./presets.ts";

/**
 * The routing `eventType` of an event sent by `POST /v1/test/<hookId>` (src/test-event.ts). Runners
 * show it, and run only the automations that name this kind.
 */
export const TEST_EVENT_TYPE = "00hooks.test";

/** A fixed answer for the provider. Bounded, and only types a browser won't run as a page. */
export interface StaticResponse {
  status: number;
  contentType: StaticContentType;
  body: string;
}

export const STATIC_CONTENT_TYPES = ["text/plain", "application/json", "application/xml", "text/xml"] as const;
export type StaticContentType = (typeof STATIC_CONTENT_TYPES)[number];
/** Bytes of UTF-8: an answer is an acknowledgement, not a page. */
export const STATIC_BODY_MAX_BYTES = 4096;

function field(name: string, message: string): never {
  throw new HttpError(invalid(name, message));
}

/**
 * Validates `response` from a PATCH: null clears it. Only 2xx statuses (anything else makes a
 * provider retry, which the relay would dedupe and answer again: a loop for nothing), only text,
 * JSON or XML (never HTML: the relay's origin must not serve pages someone wrote), at most 4 KiB.
 * A preset whose provider reads the relay's own answer (Twilio's TwiML) can't take one.
 */
export function parseStaticResponse(raw: unknown, preset: Preset): StaticResponse | null {
  if (raw === null) return null;
  if (SPECS[preset].notice === "twiml") {
    field("response", "Twilio deliveries are answered with TwiML, so this hook can't have a static response.");
  }
  if (typeof raw !== "object" || Array.isArray(raw)) field("response", "response must be an object or null.");
  const v = raw as Record<string, unknown>;
  for (const k of Object.keys(v)) {
    if (k !== "status" && k !== "contentType" && k !== "body") field("response", "response takes only status, contentType and body.");
  }
  const status = v.status ?? 200;
  if (typeof status !== "number" || !Number.isInteger(status) || status < 200 || status > 299 || status === 204 || status === 205) {
    field("response.status", "response.status must be a 2xx status that carries a body (200 to 299, not 204 or 205).");
  }
  const contentType = v.contentType ?? "text/plain";
  if (typeof contentType !== "string" || !(STATIC_CONTENT_TYPES as readonly string[]).includes(contentType)) {
    field("response.contentType", `response.contentType must be one of ${STATIC_CONTENT_TYPES.join(", ")}.`);
  }
  const body = v.body ?? "";
  if (typeof body !== "string" || new TextEncoder().encode(body).byteLength > STATIC_BODY_MAX_BYTES) {
    field("response.body", `response.body must be text of at most ${STATIC_BODY_MAX_BYTES} bytes.`);
  }
  if (contentType === "application/json") {
    try {
      JSON.parse(body as string);
    } catch {
      field("response.body", "response.body must be valid JSON for application/json.");
    }
  }
  return { status: status as number, contentType: contentType as StaticContentType, body: body as string };
}

export function staticResponseOf(stored: string | null | undefined): StaticResponse | null {
  if (!stored) return null;
  try {
    return JSON.parse(stored) as StaticResponse;
  } catch {
    return null;
  }
}

/**
 * The answer to an accepted delivery (stored, a duplicate, or dropped by the screen, which must
 * look the same): the hook's static response when it has one, otherwise the usual JSON.
 */
export function deliveryAnswer(stored: string | null | undefined, fallback: Record<string, unknown>): Response {
  const r = staticResponseOf(stored);
  if (!r) return json(fallback);
  return new Response(r.body, {
    status: r.status,
    headers: {
      "Content-Type": `${r.contentType}; charset=utf-8`,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      // Nothing in it may run or load anything, whatever a browser makes of it.
      "Content-Security-Policy": "default-src 'none'; sandbox",
    },
  });
}

/**
 * Validates `deliverTo` from a PATCH: an active node device of the account with a sealing key (a
 * device without one could read nothing sealed to it), or null for every device.
 */
export async function parseDeliverTo(env: Env, accountId: string, raw: unknown): Promise<string | null> {
  if (raw === null) return null;
  if (typeof raw !== "string" || !isId("dev", raw)) field("deliverTo", "deliverTo must be a device id, or null for every device.");
  const row = await env.DB.prepare(
    "SELECT id FROM devices WHERE id = ? AND account_id = ? AND kind = 'device' AND revoked_at IS NULL AND seal_key IS NOT NULL",
  )
    .bind(raw, accountId)
    .first<{ id: string }>();
  if (!row) field("deliverTo", "deliverTo must be an active device of this account that has a sealing key.");
  return row.id;
}
