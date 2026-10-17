// The signed-request scheme of PROTOCOL §1, shared by the relay (which verifies), the tests and the
// idle-cost script (which sign). Pure WebCrypto, no Workers-only APIs.

import { fromBase64, sha256Hex, toBase64Url, randomBytes, utf8 } from "./encoding.ts";

export const SIGNATURE_VERSION = "00hooks-v1";

export const HEADER_DEVICE = "X-00h-Device";
export const HEADER_TIME = "X-00h-Time";
export const HEADER_NONCE = "X-00h-Nonce";
export const HEADER_SIGNATURE = "X-00h-Signature";

export interface CanonicalParts {
  /** The `X-00h-Device` value: signed, so a signature can't be presented as another device's. */
  deviceId: string;
  /**
   * Exactly the Host header: lowercase, IPv6 in brackets, `:port` only when it isn't the scheme's
   * default. `new URL(…).host` gives exactly that.
   */
  host: string;
  method: string;
  /** The path and query exactly as sent. */
  pathAndQuery: string;
  time: string;
  nonce: string;
  /** Hex SHA-256 of the raw body, or of the empty string. */
  bodySha256: string;
}

export function canonicalString(p: CanonicalParts): string {
  return [
    SIGNATURE_VERSION,
    p.deviceId,
    p.host.toLowerCase(),
    p.method.toUpperCase(),
    p.pathAndQuery,
    p.time,
    p.nonce,
    p.bodySha256,
  ].join("\n");
}

export async function bodyHash(body: Uint8Array<ArrayBuffer> | undefined): Promise<string> {
  return sha256Hex(body ?? new Uint8Array(0));
}

/** 22 base64url characters: 128 random bits. */
export function newNonce(): string {
  return toBase64Url(randomBytes(16));
}

export interface DeviceKey {
  deviceId: string;
  privateKey: CryptoKey;
}

/** Generates an Ed25519 key pair; returns the private key and the raw public key as base64url. */
export async function generateDeviceKey(): Promise<{ privateKey: CryptoKey; publicKey: string }> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
  return { privateKey: pair.privateKey, publicKey: toBase64Url(raw) };
}

/**
 * The four signing headers for one request. `url` is the full URL being requested; `body` the exact
 * bytes that will be sent.
 */
export async function signRequest(
  key: DeviceKey,
  method: string,
  url: string,
  body?: Uint8Array<ArrayBuffer>,
  opts: { time?: number; nonce?: string } = {},
): Promise<Record<string, string>> {
  const u = new URL(url);
  const time = String(opts.time ?? Date.now());
  const nonce = opts.nonce ?? newNonce();
  const canonical = canonicalString({
    deviceId: key.deviceId,
    host: u.host,
    method,
    pathAndQuery: u.pathname + u.search,
    time,
    nonce,
    bodySha256: await bodyHash(body),
  });
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", key.privateKey, utf8(canonical)));
  return {
    [HEADER_DEVICE]: key.deviceId,
    [HEADER_TIME]: time,
    [HEADER_NONCE]: nonce,
    [HEADER_SIGNATURE]: toBase64Url(sig),
  };
}

/** Unpadded base64url (RFC 4648 §5 without `=`), as PROTOCOL §1 requires, of exactly `chars` chars. */
export function isUnpaddedBase64Url(s: string, chars: number): boolean {
  return s.length === chars && /^[A-Za-z0-9_-]+$/.test(s);
}

/** Imports a raw Ed25519 public key given as unpadded base64url (43 chars); null otherwise. */
export async function importPublicKey(publicKey: string): Promise<CryptoKey | null> {
  // Strict, so one key has one spelling (the uniqueness of keys is checked on the string).
  if (!isUnpaddedBase64Url(publicKey, 43)) return null;
  const raw = fromBase64(publicKey);
  // …and canonical: the last character's unused bits are zero.
  if (!raw || raw.byteLength !== 32 || toBase64Url(raw) !== publicKey) return null;
  try {
    return await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    return null;
  }
}
