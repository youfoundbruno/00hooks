// Firebase Cloud Messaging, HTTP v1 (PROTOCOL §10.7): Android's side of phone push, made like
// apns.ts. The relay holds the operator's Google service account and nothing else of a push: the
// registration token comes with each request from the phone's node and is never stored, and the
// message is built from fixed texts in phone-push.ts, never from what the node sent.

import { pemBody } from "./apns.ts";
import { toBase64Url, utf8 } from "./encoding.ts";

/** Google's OAuth2 token endpoint. Not configurable (the service account's `token_uri` is ignored). */
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
/** The FCM host. Not configurable: a setting that could point pushes elsewhere would be a leak. */
export const FCM_HOST = "https://fcm.googleapis.com";
/** The one scope the relay asks for: sending messages, nothing else of the project. */
export const FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
/** How long the signed assertion is good for (Google takes at most an hour). */
export const ASSERTION_LIFETIME_S = 3600;
/** An access token is fetched again this long before Google says it expires. */
export const ACCESS_TOKEN_MARGIN_MS = 5 * 60_000;
/** The largest service-account JSON taken (a real one is about 2.3 KB). */
const SERVICE_ACCOUNT_MAX = 16_384;

export interface FcmConfig {
  key: CryptoKey;
  projectId: string;
  clientEmail: string;
  /** The service account's key id, sent as the assertion's `kid` when it has one. */
  keyId: string | null;
  /** What the token cache is keyed on: a rotated key, account or project takes effect at once. */
  cacheKey: string;
}

interface ServiceAccount {
  pem: string;
  projectId: string;
  clientEmail: string;
  keyId: string | null;
}

/** The fields the relay uses from `FCM_SERVICE_ACCOUNT`, or null when it isn't a well-formed service account. */
export function parseServiceAccount(raw: string | undefined): ServiceAccount | null {
  if (!raw || raw.length > SERVICE_ACCOUNT_MAX) return null;
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (o.type !== "service_account") return null;
  const { project_id: projectId, client_email: clientEmail, private_key: pem, private_key_id: keyId } = o;
  // Google's project id rules; it goes into the request path, so nothing else is taken.
  if (typeof projectId !== "string" || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)) return null;
  if (typeof clientEmail !== "string" || clientEmail.length > 254 || !/^[^\s@"\\]+@[^\s@"\\]+$/.test(clientEmail)) return null;
  // PKCS#8 only ("PRIVATE KEY"); a PKCS#1 "RSA PRIVATE KEY" isn't what Google issues.
  if (typeof pem !== "string" || !/-----BEGIN PRIVATE KEY-----[\s\S]+-----END PRIVATE KEY-----/.test(pem.replace(/\\n/g, "\n"))) return null;
  const kid = typeof keyId === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(keyId) ? keyId : null;
  return { pem, projectId, clientEmail, keyId: kid };
}

/** The imported key for the last PEM seen (one per isolate; the secret rarely changes). */
let importedKey: { pem: string; key: CryptoKey | null } | null = null;

async function importFcmKey(pem: string): Promise<CryptoKey | null> {
  if (importedKey?.pem === pem) return importedKey.key;
  let key: CryptoKey | null = null;
  const der = pemBody(pem);
  if (der) {
    try {
      key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
      // Google's keys are 2048-bit; anything shorter isn't one of theirs.
      const bits = (key.algorithm as { modulusLength?: unknown }).modulusLength;
      if (typeof bits !== "number" || bits < 2048) key = null;
    } catch {
      key = null;
    }
  }
  importedKey = { pem, key };
  return key;
}

/**
 * The relay's FCM configuration, or null when Android push isn't available: `FCM_SERVICE_ACCOUNT` is
 * unset, isn't a service account's JSON with `project_id`, `client_email` and a PKCS#8 `private_key`,
 * or the key doesn't import as an RSA key for RS256.
 */
export async function fcmConfig(env: Env): Promise<FcmConfig | null> {
  const sa = parseServiceAccount(env.FCM_SERVICE_ACCOUNT?.trim());
  if (!sa) return null;
  const key = await importFcmKey(sa.pem);
  if (!key) return null;
  return {
    key,
    projectId: sa.projectId,
    clientEmail: sa.clientEmail,
    keyId: sa.keyId,
    cacheKey: `${sa.projectId}\n${sa.clientEmail}\n${sa.pem}`,
  };
}

const b64urlJson = (v: unknown) => toBase64Url(utf8(JSON.stringify(v)));

/** Signs the assertion exchanged for an access token: RS256 over `header.claims`, good for an hour. */
export async function mintAssertion(c: Pick<FcmConfig, "key" | "clientEmail" | "keyId">, nowMs: number): Promise<string> {
  const iat = Math.floor(nowMs / 1000);
  const header = c.keyId ? { alg: "RS256", typ: "JWT", kid: c.keyId } : { alg: "RS256", typ: "JWT" };
  const claims = { iss: c.clientEmail, scope: FCM_SCOPE, aud: GOOGLE_TOKEN_URL, iat, exp: iat + ASSERTION_LIFETIME_S };
  const input = `${b64urlJson(header)}.${b64urlJson(claims)}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, c.key, utf8(input)));
  return `${input}.${toBase64Url(sig)}`;
}

/** The access token in use (one per isolate), with what it was fetched for and when it is refreshed. */
let cachedToken: { cacheKey: string; refreshAt: number; fetchedAt: number; token: string } | null = null;
/** A token exchange in flight, so parallel pushes in one isolate share it. */
let pending: { cacheKey: string; promise: Promise<string | null> } | null = null;

/**
 * An OAuth2 access token for `c`: the cached one until shortly before it expires, if it was fetched
 * for the same project, account and key; otherwise (or with `fresh`, after FCM refused it) a new one
 * from Google's token endpoint. Null when Google doesn't give one.
 */
export async function accessToken(c: FcmConfig, nowMs: number, fresh = false): Promise<string | null> {
  if (!fresh && cachedToken && cachedToken.cacheKey === c.cacheKey && nowMs < cachedToken.refreshAt && nowMs >= cachedToken.fetchedAt) {
    return cachedToken.token;
  }
  if (!fresh && pending?.cacheKey === c.cacheKey) return pending.promise;
  const promise = exchange(c, nowMs).finally(() => {
    if (pending?.promise === promise) pending = null;
  });
  pending = { cacheKey: c.cacheKey, promise };
  return promise;
}

async function exchange(c: FcmConfig, nowMs: number): Promise<string | null> {
  const assertion = await mintAssertion(c, nowMs);
  let res: Response;
  try {
    res = await fetch(GOOGLE_TOKEN_URL, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }).toString(),
    });
  } catch {
    return null;
  }
  if (res.status !== 200) {
    await res.body?.cancel().catch(() => {});
    console.error("phone push: Google's token endpoint refused the service account", res.status);
    return null;
  }
  let body: { access_token?: unknown; expires_in?: unknown };
  try {
    body = (await res.json()) as typeof body;
  } catch {
    return null;
  }
  const token = body.access_token;
  const expiresIn = body.expires_in;
  // It goes into a header: printable ASCII only.
  if (typeof token !== "string" || !/^[\x21-\x7e]{1,4096}$/.test(token)) return null;
  const lifetimeMs = typeof expiresIn === "number" && Number.isFinite(expiresIn) && expiresIn > 0 ? Math.min(expiresIn, ASSERTION_LIFETIME_S) * 1000 : 0;
  cachedToken = { cacheKey: c.cacheKey, fetchedAt: nowMs, refreshAt: nowMs + Math.max(0, lifetimeMs - ACCESS_TOKEN_MARGIN_MS), token };
  return token;
}

/** Forgets the cached token and key (tests). */
export function resetFcmCache(): void {
  cachedToken = null;
  pending = null;
  importedKey = null;
}

/** What FCM answered, reduced to what the relay acts on. */
export type FcmResult =
  | { kind: "sent" }
  | { kind: "unregistered" }
  | { kind: "access_token" }
  | { kind: "rate_limited" }
  | { kind: "failed"; status: number; reason: string | null };

interface FcmError {
  status: string | null;
  errorCode: string | null;
  tokenField: boolean;
}

/** The parts of FCM's error body the relay acts on: plain upper-case words only, nothing else kept. */
async function errorOf(res: Response): Promise<FcmError> {
  const out: FcmError = { status: null, errorCode: null, tokenField: false };
  const word = (v: unknown) => (typeof v === "string" && /^[A-Z_]{1,64}$/.test(v) ? v : null);
  try {
    const body = (await res.json()) as { error?: { status?: unknown; details?: unknown } };
    const e = body.error;
    if (typeof e !== "object" || e === null) return out;
    out.status = word(e.status);
    if (Array.isArray(e.details)) {
      for (const d of e.details as Record<string, unknown>[]) {
        if (typeof d !== "object" || d === null) continue;
        out.errorCode ??= word(d.errorCode);
        // google.rpc.BadRequest: which field was wrong.
        if (Array.isArray(d.fieldViolations) && d.fieldViolations.some((f: { field?: unknown }) => f?.field === "message.token")) out.tokenField = true;
      }
    }
  } catch {
    // Not JSON: nothing to act on.
  }
  return out;
}

export interface FcmRequest {
  /** The registration token; only ever put in the message body. */
  token: string;
  /** The JSON body (`{ "message": … }`), built by the relay. */
  payload: string;
}

/** One POST to FCM. Network errors and redirects are `failed`; nothing is retried here. */
export async function sendToFcm(c: FcmConfig, accessToken: string, req: FcmRequest): Promise<FcmResult> {
  let res: Response;
  try {
    res = await fetch(`${FCM_HOST}/v1/projects/${c.projectId}/messages:send`, {
      method: "POST",
      redirect: "manual",
      headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json" },
      body: req.payload,
    });
  } catch {
    return { kind: "failed", status: 0, reason: null };
  }
  if (res.status === 200) {
    await res.body?.cancel().catch(() => {});
    return { kind: "sent" };
  }
  const e = await errorOf(res);
  const reason = e.errorCode ?? e.status;
  // The token is gone (404 UNREGISTERED), belongs to another project (SENDER_ID_MISMATCH), or
  // isn't a token (INVALID_ARGUMENT naming `message.token`). Any other INVALID_ARGUMENT is ours.
  if (res.status === 404 || e.errorCode === "UNREGISTERED" || e.errorCode === "SENDER_ID_MISMATCH") return { kind: "unregistered" };
  if (res.status === 400 && (e.errorCode === "INVALID_ARGUMENT" || e.status === "INVALID_ARGUMENT") && e.tokenField) return { kind: "unregistered" };
  if (res.status === 401) return { kind: "access_token" };
  if (res.status === 429) return { kind: "rate_limited" };
  return { kind: "failed", status: res.status, reason };
}
