// Hook signing secrets at rest: AES-256-GCM under SECRETS_KEY, with the hook id as associated data
// so a sealed secret can't be moved to another hook's row. They can't be hashed: the relay has to
// recompute the provider's signature.

import { concatBytes, fromBase64, randomBytes, toBase64Url, utf8 } from "./encoding.ts";

const VERSION = "v1.";

async function key(secretsKey: string): Promise<CryptoKey> {
  const raw = fromBase64(secretsKey ?? "");
  if (!raw || raw.byteLength !== 32) throw new Error("SECRETS_KEY must be 32 bytes, base64");
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function sealSecret(secretsKey: string, hookId: string, secret: string): Promise<string> {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: utf8(hookId) },
    await key(secretsKey),
    utf8(secret),
  );
  return VERSION + toBase64Url(concatBytes(iv, new Uint8Array(ct)));
}

export async function openSecret(secretsKey: string, hookId: string, sealed: string): Promise<string> {
  if (!sealed.startsWith(VERSION)) throw new Error("unknown sealed-secret version");
  const raw = fromBase64(sealed.slice(VERSION.length));
  if (!raw || raw.byteLength < 13) throw new Error("malformed sealed secret");
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: raw.subarray(0, 12), additionalData: utf8(hookId) },
    await key(secretsKey),
    raw.subarray(12),
  );
  return new TextDecoder().decode(pt);
}

/** HMAC-SHA256 under HASH_PEPPER, hex: for enrolment codes and client IPs. */
export async function pepperedHash(pepper: string, value: string): Promise<string> {
  const k = await crypto.subtle.importKey("raw", utf8(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, utf8(value)));
  let s = "";
  for (const x of sig) s += x.toString(16).padStart(2, "0");
  return s;
}
