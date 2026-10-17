// Provider presets (PROTOCOL §3): how a hook's deliveries are verified, deduplicated, typed, and
// which headers are kept. Every check runs over the raw bytes, before anything is parsed, and every
// comparison of a signature or token is constant-time.

import {
  concatBytes,
  constantTimeEqual,
  fromBase64,
  fromHex,
  hmac,
  randomBytes,
  sha256Hex,
  toBase64,
  toBase64Url,
  utf8,
} from "./encoding.ts";
import { HttpError, invalid } from "./http.ts";

export const PRESETS = ["github", "standard-webhooks", "hmac", "token", "unverified"] as const;
export type Preset = (typeof PRESETS)[number];

/** The non-secret part of a hook's verification, as stored and as returned in `Hook.verify`. */
export interface VerifyConfig {
  preset: Preset;
  header?: string;
  algorithm?: "sha256" | "sha1";
  encoding?: "hex" | "base64";
  prefix?: string;
}

/** Standard Webhooks and its timestamp tolerance, in seconds. */
export const TIMESTAMP_TOLERANCE_S = 300;

const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$/;

function field(name: string, message: string): never {
  throw new HttpError(invalid(name, message));
}

/**
 * Validates a `Verify` object from a create request. Returns the stored config and, when the
 * caller supplied one, its secret (otherwise the relay generates it).
 */
export function parseVerify(raw: unknown): { config: VerifyConfig; secret: string | null } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) field("verify", "verify must be an object.");
  const v = raw as Record<string, unknown>;
  const preset = v.preset;
  if (typeof preset !== "string" || !(PRESETS as readonly string[]).includes(preset)) {
    field("verify.preset", `verify.preset must be one of ${PRESETS.join(", ")}.`);
  }
  const p = preset as Preset;
  let secret: string | null = null;
  if (v.secret !== undefined) {
    if (p === "unverified") field("verify.secret", "The unverified preset takes no secret.");
    if (typeof v.secret !== "string" || v.secret.length < 8 || v.secret.length > 512) {
      field("verify.secret", "verify.secret must be a string of 8 to 512 characters.");
    }
    secret = v.secret;
    if (p === "standard-webhooks" && !standardWebhooksKey(secret)) {
      field("verify.secret", "verify.secret must be whsec_ followed by base64 (at least 16 bytes).");
    }
  }
  const config: VerifyConfig = { preset: p };
  if (p === "hmac") {
    if (typeof v.header !== "string" || !HEADER_NAME.test(v.header)) {
      field("verify.header", "verify.header must be a header name.");
    }
    config.header = v.header.toLowerCase();
    const algorithm = v.algorithm ?? "sha256";
    if (algorithm !== "sha256" && algorithm !== "sha1") field("verify.algorithm", "verify.algorithm must be sha256 or sha1.");
    config.algorithm = algorithm;
    const encoding = v.encoding ?? "hex";
    if (encoding !== "hex" && encoding !== "base64") field("verify.encoding", "verify.encoding must be hex or base64.");
    config.encoding = encoding;
    if (v.prefix !== undefined) {
      if (typeof v.prefix !== "string" || v.prefix.length > 32) field("verify.prefix", "verify.prefix must be a short string.");
      if (v.prefix) config.prefix = v.prefix;
    }
  } else if (p === "token") {
    const header = v.header ?? "authorization";
    if (typeof header !== "string" || !HEADER_NAME.test(header)) field("verify.header", "verify.header must be a header name.");
    config.header = header.toLowerCase();
  }
  return { config, secret };
}

export function presetTakesSecret(p: Preset): boolean {
  return p !== "unverified";
}

/** A fresh signing secret: 32 random bytes, in the form the provider expects. */
export function generateSecret(p: Preset): string {
  const bytes = randomBytes(32);
  return p === "standard-webhooks" ? `whsec_${toBase64(bytes)}` : toBase64Url(bytes);
}

function standardWebhooksKey(secret: string): Uint8Array<ArrayBuffer> | null {
  if (!secret.startsWith("whsec_")) return null;
  const key = fromBase64(secret.slice("whsec_".length));
  return key && key.byteLength >= 16 ? key : null;
}

export interface Delivery {
  body: Uint8Array<ArrayBuffer>;
  headers: Headers;
  /** Unix ms. */
  now: number;
}

export interface Verdict {
  ok: boolean;
  verified: boolean;
  /**
   * Per-hook replay keys, empty for presets that don't dedupe. A delivery is a duplicate when any of
   * them was seen before; all of them are marked in the same transaction as the append.
   */
  dedupeKeys: string[];
  /** The provider's event type, capped at 200 characters. Signed or not: see `EVENT_TYPE_SOURCE`. */
  eventType: string | null;
}

/** Event types are labels: anything longer is cut. */
export const EVENT_TYPE_MAX = 200;

/**
 * Where a preset's `eventType` comes from (PROTOCOL §5): `signed` when the provider's signature covers
 * it, `claimed` when it is an unsigned header (GitHub signs only the body, so `X-GitHub-Event` is the
 * sender's claim), `none` when the preset never sets one.
 */
export const EVENT_TYPE_SOURCE: Record<Preset, "signed" | "claimed" | "none"> = {
  github: "claimed",
  "standard-webhooks": "signed",
  hmac: "none",
  token: "none",
  unverified: "none",
};

const REFUSED: Verdict = { ok: false, verified: false, dedupeKeys: [], eventType: null };

/**
 * Verifies one delivery. `secrets` holds every secret that is currently valid (the current one, and
 * the previous one during a rotation's overlap), and any of them may match.
 */
export async function verifyDelivery(config: VerifyConfig, secrets: string[], d: Delivery): Promise<Verdict> {
  switch (config.preset) {
    case "github":
      return verifyGithub(secrets, d);
    case "standard-webhooks":
      return verifyStandardWebhooks(secrets, d);
    case "hmac":
      return verifyHmac(config, secrets, d);
    case "token":
      return verifyToken(config, secrets, d);
    case "unverified":
      return { ok: true, verified: false, dedupeKeys: [], eventType: null };
  }
}

async function anySecret(secrets: string[], check: (s: string) => Promise<boolean>): Promise<boolean> {
  // Check every secret, not just until the first match, so timing doesn't reveal which one matched.
  let ok = false;
  for (const s of secrets) ok = (await check(s)) || ok;
  return ok;
}

async function verifyGithub(secrets: string[], d: Delivery): Promise<Verdict> {
  const header = d.headers.get("x-hub-signature-256") ?? "";
  if (!header.startsWith("sha256=")) return REFUSED;
  const given = fromHex(header.slice("sha256=".length));
  if (!given || given.byteLength !== 32) return REFUSED;
  const ok = await anySecret(secrets, async (s) => constantTimeEqual(await hmac("SHA-256", utf8(s), d.body), given));
  if (!ok) return REFUSED;
  // GitHub's HMAC covers the body only: `X-GitHub-Delivery` and `X-GitHub-Event` are unsigned. The
  // body mark is always written, so a captured delivery can't be replayed under a new delivery id;
  // the delivery mark keeps GitHub's own retries (same id) answered as duplicates too.
  const delivery = d.headers.get("x-github-delivery");
  const keys = [`body:${await sha256Hex(d.body)}`];
  if (delivery) keys.unshift(`delivery:${delivery.slice(0, 200)}`);
  return {
    ok: true,
    verified: true,
    dedupeKeys: keys,
    eventType: d.headers.get("x-github-event")?.slice(0, EVENT_TYPE_MAX) ?? null,
  };
}

async function verifyStandardWebhooks(secrets: string[], d: Delivery): Promise<Verdict> {
  const id = d.headers.get("webhook-id");
  const ts = d.headers.get("webhook-timestamp");
  const sigs = d.headers.get("webhook-signature");
  if (!id || !ts || !sigs || !/^\d{1,12}$/.test(ts)) return REFUSED;
  if (Math.abs(d.now / 1000 - Number(ts)) > TIMESTAMP_TOLERANCE_S) return REFUSED;
  const signed = concatBytes(utf8(`${id}.${ts}.`), d.body);
  const given = sigs
    .split(" ")
    .filter((s) => s.startsWith("v1,"))
    .map((s) => fromBase64(s.slice(3)))
    .filter((b): b is Uint8Array<ArrayBuffer> => b !== null);
  if (given.length === 0) return REFUSED;
  const ok = await anySecret(secrets, async (s) => {
    const key = standardWebhooksKey(s);
    if (!key) return false;
    const expected = await hmac("SHA-256", key, signed);
    let match = false;
    for (const g of given) match = constantTimeEqual(expected, g) || match;
    return match;
  });
  if (!ok) return REFUSED;
  // The id, the timestamp and the body are all signed: a replay under a new id needs a new signature.
  return { ok: true, verified: true, dedupeKeys: [`id:${id.slice(0, 200)}`], eventType: jsonType(d.body) };
}

function jsonType(body: Uint8Array): string | null {
  try {
    const v = JSON.parse(new TextDecoder().decode(body)) as unknown;
    if (typeof v === "object" && v !== null && typeof (v as { type?: unknown }).type === "string") {
      return ((v as { type: string }).type).slice(0, EVENT_TYPE_MAX);
    }
  } catch {
    // Not JSON: the event simply has no type.
  }
  return null;
}

async function verifyHmac(config: VerifyConfig, secrets: string[], d: Delivery): Promise<Verdict> {
  let value = d.headers.get(config.header!) ?? "";
  const prefix = config.prefix ?? "";
  if (!value.startsWith(prefix)) return REFUSED;
  value = value.slice(prefix.length).trim();
  const given = config.encoding === "base64" ? fromBase64(value) : fromHex(value);
  if (!given) return REFUSED;
  const algorithm = config.algorithm === "sha1" ? "SHA-1" : "SHA-256";
  const ok = await anySecret(secrets, async (s) => constantTimeEqual(await hmac(algorithm, utf8(s), d.body), given));
  if (!ok) return REFUSED;
  return { ok: true, verified: true, dedupeKeys: [`body:${await sha256Hex(d.body)}`], eventType: null };
}

async function verifyToken(config: VerifyConfig, secrets: string[], d: Delivery): Promise<Verdict> {
  const header = config.header ?? "authorization";
  const value = d.headers.get(header) ?? "";
  let presented = value;
  if (header === "authorization") {
    const space = value.indexOf(" ");
    if (space < 0 || value.slice(0, space).toLowerCase() !== "bearer") return REFUSED;
    presented = value.slice(space + 1).trim();
  }
  const given = utf8(presented);
  const ok = await anySecret(secrets, async (s) => constantTimeEqual(utf8(s), given));
  if (!ok) return REFUSED;
  return { ok: true, verified: true, dedupeKeys: [], eventType: null };
}

const COMMON_HEADERS = ["content-type", "user-agent"];
// Signature headers are never kept: once verified they are no use to a reader, and a stored
// signature next to its body is a ready-made replay.
const PRESET_HEADERS: Record<Preset, string[]> = {
  github: [
    "x-github-event",
    "x-github-delivery",
    "x-github-hook-id",
    "x-github-hook-installation-target-id",
    "x-github-hook-installation-target-type",
  ],
  "standard-webhooks": ["webhook-id", "webhook-timestamp"],
  // The hmac preset's own header is its signature: never kept.
  hmac: [],
  // The token header *is* the secret: never kept.
  token: [],
  unverified: [],
};
const NEVER_KEPT = new Set([
  "cookie",
  "authorization",
  "proxy-authorization",
  "set-cookie",
  "x-hub-signature",
  "x-hub-signature-256",
  "webhook-signature",
]);

/** A header that carries this hook's signature or token, whatever the preset calls it. */
function isCredentialHeader(config: VerifyConfig, name: string): boolean {
  return NEVER_KEPT.has(name) || ((config.preset === "hmac" || config.preset === "token") && name === config.header);
}

/**
 * The headers an event keeps: the preset's allowlist, lowercased; never cookies, credentials or
 * signatures. Every kept header is the sender's claim: none is covered by a signature.
 */
export function keptHeaders(config: VerifyConfig, headers: Headers): Record<string, string> {
  const names = [...COMMON_HEADERS, ...PRESET_HEADERS[config.preset]];
  const out: Record<string, string> = {};
  for (const n of names) {
    if (isCredentialHeader(config, n)) continue;
    const v = headers.get(n);
    if (v !== null) out[n] = v.slice(0, 1024);
  }
  return out;
}
