// Byte encodings, hashing and comparisons. Pure WebCrypto: this file also runs under Node (the
// idle-cost script imports it), so it touches nothing Workers-specific.

const enc = new TextEncoder();

export function utf8(s: string): Uint8Array<ArrayBuffer> {
  return enc.encode(s) as Uint8Array<ArrayBuffer>;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.byteLength;
  }
  return out;
}

export function toHex(bytes: ArrayBuffer | Uint8Array): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/** Decodes lowercase or uppercase hex; null when it isn't hex. */
export function fromHex(s: string): Uint8Array<ArrayBuffer> | null {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decodes standard or URL-safe base64, padded or not; null when it isn't base64. */
export function fromBase64(s: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(s)) return null;
  let t = s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (t.length % 4 === 1) return null;
  t += "=".repeat((4 - (t.length % 4)) % 4);
  try {
    const bin = atob(t);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export async function sha256Hex(data: Uint8Array<ArrayBuffer>): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", data));
}

export async function hmac(
  algorithm: "SHA-256" | "SHA-1",
  key: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: algorithm }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

/**
 * Compares two byte strings in time that depends only on their lengths. Every comparison of a
 * secret, a signature or a token goes through here.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  const lengthsMatch = a.byteLength === b.byteLength;
  // Compare against itself when the lengths differ, so the work done doesn't depend on content.
  const other = lengthsMatch ? b : a;
  let diff = lengthsMatch ? 0 : 1;
  for (let i = 0; i < a.byteLength; i++) diff |= a[i]! ^ other[i]!;
  return diff === 0;
}

export function constantTimeEqualStrings(a: string, b: string): boolean {
  return constantTimeEqual(utf8(a), utf8(b));
}

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

const CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz";

/** Crockford base32, lowercase, no padding. */
export function toCrockford(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD[(value << (5 - bits)) & 31];
  return out;
}

export type IdPrefix = "acc" | "dev" | "hk" | "evt" | "enr" | "key";

/** A new random id: the prefix, `_`, and 128 random bits in Crockford base32 (26 chars). */
export function newId(prefix: IdPrefix): string {
  return `${prefix}_${toCrockford(randomBytes(16))}`;
}

export function isId(prefix: IdPrefix, s: unknown): s is string {
  return typeof s === "string" && new RegExp(`^${prefix}_[0-9a-hjkmnp-tv-z]{26}$`).test(s);
}
