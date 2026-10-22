// Apple Push Notification service (PROTOCOL §10.7): the relay's configuration, its ES256 provider
// token, and the one request it sends. The relay holds the operator's APNs key and nothing else of
// a push: the device token comes with each request from the phone's node and is never stored, and
// the payload is built from fixed texts here, never from what the node sent.

import { fromBase64, toBase64Url, utf8 } from "./encoding.ts";

export type ApnsEnvironment = "sandbox" | "production";

/** The APNs hosts. Not configurable: a setting that could point pushes elsewhere would be a leak. */
export const APNS_HOSTS: Record<ApnsEnvironment, string> = {
  production: "https://api.push.apple.com",
  sandbox: "https://api.sandbox.push.apple.com",
};

/** A provider token is reused this long. APNs refuses tokens older than an hour, and refreshes more often than every 20 minutes. */
export const TOKEN_REUSE_MS = 50 * 60_000;

export interface ApnsConfig {
  key: CryptoKey;
  keyId: string;
  teamId: string;
  topic: string;
  environment: ApnsEnvironment;
  /** What the token cache is keyed on: a rotated key, key id or team takes effect at once. */
  cacheKey: string;
}

/** Strips the PEM armour (BEGIN/END lines), whitespace and `\n` escapes, and decodes the rest. */
export function pemBody(pem: string): Uint8Array<ArrayBuffer> | null {
  const text = pem
    .replace(/\\n/g, "\n")
    .replace(/-----(BEGIN|END) [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  if (text.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) return null;
  return fromBase64(text);
}

/** The imported key for the last PEM seen (one per isolate; the secret rarely changes). */
let importedKey: { pem: string; key: CryptoKey | null } | null = null;

async function importApnsKey(pem: string): Promise<CryptoKey | null> {
  if (importedKey?.pem === pem) return importedKey.key;
  let key: CryptoKey | null = null;
  const der = pemBody(pem);
  if (der) {
    try {
      key = await crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    } catch {
      key = null;
    }
  }
  importedKey = { pem, key };
  return key;
}

/**
 * The relay's APNs configuration, or null when push isn't available: one of `APNS_KEY`,
 * `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_TOPIC` is missing or malformed, `APNS_ENVIRONMENT` is neither
 * `sandbox` nor `production` (unset is `production`), or the key doesn't import as a P-256 key.
 */
export async function apnsConfig(env: Env): Promise<ApnsConfig | null> {
  const pem = env.APNS_KEY;
  const keyId = env.APNS_KEY_ID?.trim();
  const teamId = env.APNS_TEAM_ID?.trim();
  const topic = env.APNS_TOPIC?.trim();
  const rawEnv = env.APNS_ENVIRONMENT?.trim() || "production";
  if (!pem || !keyId || !teamId || !topic) return null;
  if (!/^[A-Za-z0-9]{10}$/.test(keyId) || !/^[A-Za-z0-9]{10}$/.test(teamId)) return null;
  if (!/^[A-Za-z0-9._-]{1,255}$/.test(topic)) return null;
  if (rawEnv !== "sandbox" && rawEnv !== "production") return null;
  const key = await importApnsKey(pem);
  if (!key) return null;
  return { key, keyId, teamId, topic, environment: rawEnv, cacheKey: `${keyId}\n${teamId}\n${pem}` };
}

const b64urlJson = (v: unknown) => toBase64Url(utf8(JSON.stringify(v)));

/** Signs a fresh provider token: ES256 over `header.claims` (WebCrypto's raw r‖s is JOSE's form). */
export async function mintProviderToken(c: Pick<ApnsConfig, "key" | "keyId" | "teamId">, nowMs: number): Promise<string> {
  const input = `${b64urlJson({ alg: "ES256", kid: c.keyId })}.${b64urlJson({ iss: c.teamId, iat: Math.floor(nowMs / 1000) })}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, c.key, utf8(input)));
  return `${input}.${toBase64Url(sig)}`;
}

/** The token in use (one per isolate), with what it was minted for and when. */
let cachedToken: { cacheKey: string; mintedAt: number; token: string } | null = null;

/**
 * The provider token for `c`: the cached one while it is younger than 50 minutes and was minted for
 * the same key, key id and team; otherwise (or with `fresh`, after APNs called it expired) a new one.
 */
export async function providerToken(c: ApnsConfig, nowMs: number, fresh = false): Promise<string> {
  if (!fresh && cachedToken && cachedToken.cacheKey === c.cacheKey && nowMs - cachedToken.mintedAt < TOKEN_REUSE_MS && nowMs >= cachedToken.mintedAt) {
    return cachedToken.token;
  }
  const token = await mintProviderToken(c, nowMs);
  cachedToken = { cacheKey: c.cacheKey, mintedAt: nowMs, token };
  return token;
}

/** Forgets the cached token and key (tests). */
export function resetApnsCache(): void {
  cachedToken = null;
  importedKey = null;
}

/** What APNs answered, reduced to what the relay acts on. */
export type ApnsResult =
  | { kind: "sent" }
  | { kind: "unregistered" }
  | { kind: "provider_token" }
  | { kind: "rate_limited" }
  | { kind: "failed"; status: number; reason: string | null };

/** APNs' `reason`, when it is one of its plain words (anything else isn't kept, even for a log). */
async function reasonOf(res: Response): Promise<string | null> {
  try {
    const body = (await res.json()) as { reason?: unknown };
    return typeof body.reason === "string" && /^[A-Za-z]{1,64}$/.test(body.reason) ? body.reason : null;
  } catch {
    return null;
  }
}

const UNREGISTERED_REASONS = new Set(["BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered"]);
const PROVIDER_TOKEN_REASONS = new Set(["ExpiredProviderToken", "InvalidProviderToken"]);

export interface ApnsRequest {
  /** The device token, lowercase hex; only ever put in the request path. */
  token: string;
  /** `apns-collapse-id`: the push kind. */
  collapseId: string;
  /** The JSON body, built by the relay. */
  payload: string;
}

/** One POST to APNs. Network errors and redirects are `failed`; nothing is retried here. */
export async function sendToApns(c: ApnsConfig, jwt: string, req: ApnsRequest, nowMs: number): Promise<ApnsResult> {
  let res: Response;
  try {
    res = await fetch(`${APNS_HOSTS[c.environment]}/3/device/${req.token}`, {
      method: "POST",
      redirect: "manual",
      headers: {
        authorization: `bearer ${jwt}`,
        "apns-topic": c.topic,
        "apns-push-type": "alert",
        "apns-priority": "10",
        "apns-expiration": String(Math.floor(nowMs / 1000) + 86_400),
        "apns-collapse-id": req.collapseId,
        "content-type": "application/json",
      },
      body: req.payload,
    });
  } catch {
    return { kind: "failed", status: 0, reason: null };
  }
  if (res.status === 200) {
    await res.body?.cancel().catch(() => {});
    return { kind: "sent" };
  }
  const reason = await reasonOf(res);
  if (res.status === 410) return { kind: "unregistered" };
  if (res.status === 400 && reason !== null && UNREGISTERED_REASONS.has(reason)) return { kind: "unregistered" };
  if (res.status === 403 && reason !== null && PROVIDER_TOKEN_REASONS.has(reason)) return { kind: "provider_token" };
  if (res.status === 429) return { kind: "rate_limited" };
  return { kind: "failed", status: res.status, reason };
}
