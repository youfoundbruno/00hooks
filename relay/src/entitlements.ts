// Overblast entitlements (PROTOCOL §2b): a signed statement, issued by Overblast, that a workspace's
// 00hooks account comes with a plan until a time. The relay pins the issuer's public keys
// (`ENTITLEMENT_PUBLIC_KEYS`) and checks every token against them; a relay without the keys takes
// no entitlements at all.
//
// A token is `ent1.` + base64url(payload JSON) + `.` + base64url(Ed25519 signature over the ASCII
// bytes of `ent1.<payload-b64url>`), unpadded. The payload:
//
//   { "v": 1, "iss": "overblast", "aud": "00hooks", "ws": "<workspace id>",
//     "sub": { "acc": "<account id>" } | { "dev": "<device signing key, base64url>" },
//     "plan": "overblast", "limits"?: { …the keys of PLANS… }, "iat": <s>, "exp": <s>, "jti": "…" }

import { fromBase64, isId, utf8 } from "./encoding.ts";
import { HttpError, error, invalid } from "./http.ts";
import { isPlanName, knownPlan, parseLimits, type Limits } from "./plans.ts";

export const ENTITLEMENT_PREFIX = "ent1.";
export const ENTITLEMENT_ISSUER = "overblast";
export const ENTITLEMENT_AUDIENCE = "00hooks";
/** A token longer than this is refused before anything is decoded. */
export const MAX_TOKEN_CHARS = 4096;
/** How far in the future an `iat` may be (clock differences). */
export const IAT_SKEW_S = 300;

export interface Entitlement {
  ws: string;
  sub: { acc: string } | { dev: string };
  plan: string;
  limits: Partial<Limits> | null;
  iat: number;
  exp: number;
  jti: string;
}

/** The pinned keys, imported once per isolate per configuration. Empty: entitlements are off. */
let keysCache: { raw: string | undefined; keys: Promise<CryptoKey[]> } | null = null;

export function entitlementsOn(env: Env): boolean {
  return pinnedKeyStrings(env.ENTITLEMENT_PUBLIC_KEYS).length > 0;
}

function pinnedKeyStrings(raw: string | undefined): string[] {
  if (!raw || raw.trim() === "") return [];
  try {
    const v = JSON.parse(raw) as unknown;
    if (!Array.isArray(v)) return [];
    return v.filter((k): k is string => typeof k === "string" && /^[A-Za-z0-9_-]{43}$/.test(k));
  } catch {
    return [];
  }
}

function pinnedKeys(env: Env): Promise<CryptoKey[]> {
  const raw = env.ENTITLEMENT_PUBLIC_KEYS;
  if (keysCache && keysCache.raw === raw) return keysCache.keys;
  const keys = (async () => {
    const out: CryptoKey[] = [];
    for (const k of pinnedKeyStrings(raw)) {
      const bytes = fromBase64(k);
      if (!bytes || bytes.byteLength !== 32) continue;
      try {
        out.push(await crypto.subtle.importKey("raw", bytes, { name: "Ed25519" }, false, ["verify"]));
      } catch {
        // Not a key: left out.
      }
    }
    return out;
  })();
  keysCache = { raw, keys };
  return keys;
}

/** One fixed refusal for every way a token can be wrong, so the answer says nothing of which. */
const refused = () => new HttpError(error(403, "forbidden", "This entitlement isn't valid for this relay."));
const expired = () => new HttpError(error(403, "forbidden", "This entitlement has expired; get a fresh one."));

const B64URL = /^[A-Za-z0-9_-]+$/;

/**
 * Verifies an entitlement token against the pinned keys and returns its payload. Refuses (403) a
 * token that is malformed, signed by none of the keys, for another issuer or audience, for a plan
 * the relay doesn't know, or expired. The subject is checked by the caller (it depends on the route).
 */
export async function verifyEntitlement(env: Env, token: unknown, now: number): Promise<Entitlement> {
  if (!entitlementsOn(env)) throw new HttpError(invalid("entitlement", "This relay takes no entitlements."));
  if (typeof token !== "string" || token.length > MAX_TOKEN_CHARS || !token.startsWith(ENTITLEMENT_PREFIX)) throw refused();
  const rest = token.slice(ENTITLEMENT_PREFIX.length);
  const dot = rest.indexOf(".");
  if (dot <= 0 || rest.indexOf(".", dot + 1) !== -1) throw refused();
  const payloadB64 = rest.slice(0, dot);
  const sigB64 = rest.slice(dot + 1);
  // Unpadded base64url only: one spelling per token.
  if (!B64URL.test(payloadB64) || !B64URL.test(sigB64) || sigB64.length !== 86) throw refused();
  const sig = fromBase64(sigB64);
  const payloadBytes = fromBase64(payloadB64);
  if (!sig || sig.byteLength !== 64 || !payloadBytes) throw refused();
  const signedBytes = utf8(`${ENTITLEMENT_PREFIX}${payloadB64}`);
  let ok = false;
  for (const key of await pinnedKeys(env)) {
    // Every key is tried: rotation keeps the old and new ones pinned side by side.
    if (await crypto.subtle.verify("Ed25519", key, sig, signedBytes)) ok = true;
  }
  if (!ok) throw refused();

  let p: Record<string, unknown>;
  try {
    const v = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(payloadBytes)) as unknown;
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw refused();
    p = v as Record<string, unknown>;
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw refused();
  }
  if (p.v !== 1 || p.iss !== ENTITLEMENT_ISSUER || p.aud !== ENTITLEMENT_AUDIENCE) throw refused();
  const ws = p.ws;
  if (typeof ws !== "string" || ws.length < 1 || ws.length > 128 || !/^[A-Za-z0-9_.:-]+$/.test(ws)) throw refused();
  const sub = parseSubject(p.sub);
  if (!sub) throw refused();
  if (!isPlanName(p.plan) || !knownPlan(env, p.plan)) throw refused();
  let limits: Partial<Limits> | null = null;
  if (p.limits !== undefined && p.limits !== null) {
    limits = parseLimits(p.limits);
    if (!limits) throw refused();
  }
  const iat = p.iat;
  const exp = p.exp;
  if (typeof iat !== "number" || typeof exp !== "number" || !Number.isSafeInteger(iat) || !Number.isSafeInteger(exp) || exp <= iat) {
    throw refused();
  }
  if (typeof p.jti !== "string" || p.jti.length < 1 || p.jti.length > 128) throw refused();
  const nowS = Math.floor(now / 1000);
  if (iat > nowS + IAT_SKEW_S) throw refused();
  if (exp <= nowS) throw expired();
  return { ws, sub, plan: p.plan, limits, iat, exp, jti: p.jti };
}

function parseSubject(v: unknown): Entitlement["sub"] | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length !== 1) return null;
  if (keys[0] === "acc" && isId("acc", o.acc)) return { acc: o.acc as string };
  if (keys[0] === "dev" && typeof o.dev === "string" && /^[A-Za-z0-9_-]{43}$/.test(o.dev)) return { dev: o.dev };
  return null;
}

/** Whether a D1 error is the unique workspace index losing: the workspace belongs to another account. */
export function workspaceTaken(e: unknown): boolean {
  return e instanceof Error && /UNIQUE constraint failed: accounts\.entitlement_ws/.test(e.message);
}

export const workspaceConflict = () =>
  new HttpError(error(409, "conflict", "This Overblast workspace is already linked to another 00hooks account.", { field: "entitlement" }));
