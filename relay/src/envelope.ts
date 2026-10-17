// Sealing (PLAN §4.4, PROTOCOL §5): each event's body and kept headers are sealed with HPKE (RFC 9180:
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode) to every device's X25519
// key, and every envelope is signed with the relay's own Ed25519 key, so a device knows the event
// came from its relay and that the metadata beside the ciphertext (hook, seq, verified…) is what the
// relay saw.
//
// Pure WebCrypto plus hpke-js: no Workers-only API, so the interop script runs this exact file under
// Node (`relay/scripts/seal-interop.ts`) and the Rust client opens what it makes.

import { CipherSuite } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/dhkem-x25519";
import { concatBytes, fromBase64, sha256Hex, toBase64, toBase64Url, utf8 } from "./encoding.ts";

export const SUITE = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

/** HPKE `info`: binds every envelope to this protocol and version. */
export const SEAL_INFO = "00hooks seal v1";
/** The relay's signature over an envelope starts with this line. */
export const ENVELOPE_SIG_VERSION = "00hooks-envelope-v1";

/** `sealed` in an event (PROTOCOL §5). */
export interface Sealed {
  /** The device sealing key's id: `kid(publicKey)`. */
  kid: string;
  /** The HPKE encapsulated key, unpadded base64url (43 chars). */
  enc: string;
  /** The ciphertext, standard padded base64. */
  ct: string;
}

/** What is sealed: everything about the delivery that is content rather than routing metadata. */
export interface SealedContent {
  headers: Record<string, string>;
  contentType: string | null;
  /** Strict hooks only: the public URL the relay was reached at (Twilio signs it). */
  url?: string;
  /** The relay answered this delivery with the hook's offline notice (PROTOCOL §4a). */
  notice?: true;
  body: Uint8Array;
}

/** The metadata the relay signs with each envelope (the event's plaintext fields). */
export interface EnvelopeMeta {
  deviceId: string;
  seq: number;
  id: string;
  hookId: string;
  receivedAt: number;
  verified: boolean;
  strict: boolean;
  preset: string;
  eventType: string | null;
}

/** A device sealing key's id: the first 16 bytes of SHA-256("00hooks-seal-kid-v1\n" ‖ key), base64url. */
export async function sealKid(publicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", concatBytes(utf8("00hooks-seal-kid-v1\n"), publicKey)));
  return toBase64Url(digest.subarray(0, 16));
}

/** Parses a device's sealing key: unpadded base64url of a 32-byte X25519 public key, in its one spelling. */
export function parseSealKey(s: unknown): Uint8Array<ArrayBuffer> | null {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(s)) return null;
  const raw = fromBase64(s);
  if (!raw || raw.byteLength !== 32 || toBase64Url(raw) !== s) return null;
  // The all-zero point (and other low-order points) would make every seal readable by anyone.
  if (raw.every((b) => b === 0)) return null;
  return raw;
}

/** HPKE associated data: the hook, the seq and the event id, so stored ciphertexts can't be moved. */
export function sealAad(hookId: string, seq: number, id: string): Uint8Array<ArrayBuffer> {
  return utf8(`00hooks-seal-v1\n${hookId}\n${seq}\n${id}`);
}

/**
 * The sealed plaintext: the JSON of everything but the body, a newline, then the body's raw bytes.
 * JSON never holds a raw newline, so the first one is the boundary.
 */
export function encodeContent(c: SealedContent): Uint8Array<ArrayBuffer> {
  const meta: Record<string, unknown> = { headers: c.headers, contentType: c.contentType };
  if (c.url !== undefined) meta.url = c.url;
  if (c.notice) meta.notice = true;
  return concatBytes(utf8(JSON.stringify(meta)), utf8("\n"), c.body);
}

export function decodeContent(pt: Uint8Array): SealedContent {
  const nl = pt.indexOf(0x0a);
  if (nl < 0) throw new Error("sealed content has no boundary");
  const meta = JSON.parse(new TextDecoder().decode(pt.subarray(0, nl))) as {
    headers: Record<string, string>;
    contentType: string | null;
    url?: string;
    notice?: boolean;
  };
  return {
    headers: meta.headers,
    contentType: meta.contentType,
    ...(meta.url !== undefined ? { url: meta.url } : {}),
    ...(meta.notice === true ? { notice: true as const } : {}),
    body: pt.slice(nl + 1),
  };
}

/** Seals `plaintext` to one device key. */
export async function sealTo(
  publicKey: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<{ enc: Uint8Array<ArrayBuffer>; ct: Uint8Array<ArrayBuffer> }> {
  const recipientPublicKey = await SUITE.kem.deserializePublicKey(publicKey);
  const { ct, enc } = await SUITE.seal({ recipientPublicKey, info: utf8(SEAL_INFO) }, plaintext, aad);
  return { enc: new Uint8Array(enc), ct: new Uint8Array(ct) };
}

/** Opens an envelope with a device's private key (the relay never does this; tests and tools do). */
export async function openWith(privateKey: Uint8Array, enc: Uint8Array, ct: Uint8Array, aad: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const recipientKey = await SUITE.kem.deserializePrivateKey(privateKey);
  return new Uint8Array(await SUITE.open({ recipientKey, enc, info: utf8(SEAL_INFO) }, ct, aad));
}

/**
 * The string the relay signs for one envelope: these lines joined with `\n`. The event type is
 * base64url of its UTF-8 (`-` for none), so no value can contain the separator.
 */
export async function envelopeSigString(meta: EnvelopeMeta, sealed: { kid: string; enc: string; ct: Uint8Array }): Promise<string> {
  return [
    ENVELOPE_SIG_VERSION,
    meta.deviceId,
    String(meta.seq),
    meta.id,
    meta.hookId,
    String(meta.receivedAt),
    meta.verified ? "1" : "0",
    meta.strict ? "1" : "0",
    meta.preset,
    meta.eventType === null ? "-" : toBase64Url(utf8(meta.eventType)),
    sealed.kid,
    sealed.enc,
    await sha256Hex(sealed.ct as Uint8Array<ArrayBuffer>),
  ].join("\n");
}

const PKCS8_ED25519_PREFIX = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

export interface RelayKey {
  privateKey: CryptoKey;
  /** Unpadded base64url of the raw Ed25519 public key (43 chars), as `/v1/info` publishes it. */
  publicKey: string;
}

/**
 * Imports `RELAY_SIGNING_KEY`: a 32-byte Ed25519 seed, base64 (either alphabet). Null when it's
 * missing or malformed; the relay then refuses to take deliveries (it fails closed).
 */
export async function importRelayKey(seedB64: string | undefined): Promise<RelayKey | null> {
  const seed = seedB64 ? fromBase64(seedB64.trim()) : null;
  if (!seed || seed.byteLength !== 32) return null;
  const privateKey = await crypto.subtle.importKey("pkcs8", concatBytes(PKCS8_ED25519_PREFIX, seed), { name: "Ed25519" }, true, ["sign"]);
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  if (!jwk.x) return null;
  return { privateKey, publicKey: jwk.x };
}

export interface SealedEnvelope {
  deviceId: string;
  kid: string;
  enc: string;
  /** Raw ciphertext bytes (stored as a BLOB; base64 on the wire). */
  ct: Uint8Array<ArrayBuffer>;
  /** The relay's signature, unpadded base64url (86 chars). */
  sig: string;
}

/** Seals one event to one device and signs the envelope. */
export async function sealEnvelope(
  relay: RelayKey,
  device: { deviceId: string; kid: string; publicKey: Uint8Array },
  meta: Omit<EnvelopeMeta, "deviceId">,
  plaintext: Uint8Array,
): Promise<SealedEnvelope> {
  const { enc, ct } = await sealTo(device.publicKey, plaintext, sealAad(meta.hookId, meta.seq, meta.id));
  const encB64 = toBase64Url(enc);
  const toSign = await envelopeSigString({ ...meta, deviceId: device.deviceId }, { kid: device.kid, enc: encB64, ct });
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", relay.privateKey, utf8(toSign)));
  return { deviceId: device.deviceId, kid: device.kid, enc: encB64, ct, sig: toBase64Url(sig) };
}

/** The event message of PROTOCOL §5 for one device's envelope. */
export function eventMessage(meta: Omit<EnvelopeMeta, "deviceId">, env: { kid: string; enc: string; ct: Uint8Array; sig: string }): string {
  return JSON.stringify({
    seq: meta.seq,
    id: meta.id,
    hookId: meta.hookId,
    receivedAt: meta.receivedAt,
    verified: meta.verified,
    strict: meta.strict,
    preset: meta.preset,
    eventType: meta.eventType,
    sealed: { kid: env.kid, enc: env.enc, ct: toBase64(env.ct) } satisfies Sealed,
    sig: env.sig,
  });
}
