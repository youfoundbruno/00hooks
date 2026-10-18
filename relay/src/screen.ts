// The screen at the edge (PLAN §6a, PROTOCOL §4b): cheap, deterministic checks on a delivery after
// its signature verified and before it is stored or streamed. A hook's screen is a list of rules,
// pushed by a device; the first rule that holds decides `pass`, `quarantine` (held at the relay,
// not streamed until released) or `drop` (answered 200, never stored).
//
// What it reads: the sender's address, network (ASN) and country from Cloudflare (`request.cf`),
// headers, the size, and, unless the hook is strict, the body: its shape hash, a MinHash of its
// text, and fields and headers whose values the rules hold only as keyed hashes. `contains` (on a
// field or a header), `pattern` and `similar text` read the words, so a device may push them only
// with `consent.words`. Nothing read here is stored: a decision keeps the rule's id and a count.
//
// What one delivery can cost is bounded whatever the screen and the payload: a screen is compiled
// once per isolate; patterns run on a linear-time matcher (`screen-pattern.ts`); a path reads at
// most 64 values; and the hashing, pattern steps and walking of one delivery have a budget, past
// which the delivery is held (`~over-budget`) rather than screened further.
//
// The harness's half is `cli/hooks-screen`; both compute words, shapes, signatures, domains and
// keyed hashes alike, held to `fixtures/screen.v1.json`.

import { fromBase64, hmac, sha256Hex, toBase64Url, utf8 } from "./encoding.ts";
import { HttpError, invalid } from "./http.ts";
import { expandIpv6 } from "./ip.ts";
import { codePoints, compilePattern, patternWeight, PatternError, type CompiledPattern, type Steps } from "./screen-pattern.ts";

export type Verdict = "pass" | "quarantine" | "drop";
const VERDICTS: readonly Verdict[] = ["pass", "quarantine", "drop"];

export const MAX_RULES = 200;
export const MAX_CONDITIONS = 20;
export const MAX_LIST = 1000;
export const MAX_TOKENS = 10_000;
const SHINGLE = 5;
const MAX_DEPTH = 32;
const MAX_FIELDS = 2000;
const MAX_ITEMS = 50;
export const SLOTS = 64;
export const DEFAULT_THRESHOLD = 0.8;
/** What a pattern reads of a value at the edge: its first 2,048 characters (code points). */
export const EDGE_PATTERN_INPUT = 2048;
/** The most the different patterns of one screen weigh together (`screen-pattern.ts`). */
export const MAX_SCREEN_PATTERN_WEIGHT = 4000;

export type Condition =
  | { on: "ip"; in: string[]; not?: boolean; preset?: string }
  | { on: "asn"; in: number[]; not?: boolean }
  | { on: "country"; in: string[]; not?: boolean }
  | { on: "header"; name: string; op: "present" | "absent" }
  | { on: "header"; name: string; op: "is"; hashes: string[] }
  | { on: "header"; name: string; op: "contains"; value: string }
  | { on: "size"; op: "gt" | "lt"; bytes: number }
  | { on: "field"; path: string; op: "is" | "domain_is" | "one_of"; hashes: string[]; not?: boolean }
  | { on: "field"; path: string; op: "contains"; words: string; not?: boolean }
  | { on: "field"; path: string; op: "pattern"; pattern: string; not?: boolean }
  | { on: "field"; path: string; op: "similar_text"; signature: string; threshold?: number; not?: boolean }
  | { on: "similar"; shape?: string; text?: string; threshold?: number };

export interface EdgeRule {
  id: string;
  verdict: Verdict;
  any?: boolean;
  conditions: Condition[];
}

export interface EdgeScreen {
  rules: EdgeRule[];
  /** The person agreed that the relay reads words for `contains`, `pattern` and `similar text`. */
  consent: { words: boolean };
}

// ── words, shapes and signatures (the same as cli/hooks-screen) ─────────────────────────────────

/** Compares strings by code point (UTF-16 order differs above the surrogates). */
export function cmpCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done || y.done) return x.done && y.done ? 0 : x.done ? -1 : 1;
    const cx = x.value.codePointAt(0)!;
    const cy = y.value.codePointAt(0)!;
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** A body as fields read it: JSON, else a form's fields (repeated names as lists), else UTF-8 text, else null. */
export function parsePayload(body: Uint8Array, contentType: string | null): unknown {
  if (body.byteLength === 0) return null;
  let text: string | null = null;
  try {
    // Keep a byte-order mark: it isn't JSON, as for the harness.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body);
  } catch {
    text = null;
  }
  if (text !== null) {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      // not JSON
    }
  }
  if (contentType && contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of new URLSearchParams(text ?? new TextDecoder().decode(body))) {
      const prev = out[k];
      if (prev === undefined) out[k] = v;
      else if (Array.isArray(prev)) prev.push(v);
      else out[k] = [prev, v];
    }
    return out;
  }
  return text;
}

/** Every string of a payload, keys in code-point order, joined by spaces. */
export function itemText(payload: unknown): string {
  const parts: string[] = [];
  const walk = (v: unknown, depth: number) => {
    if (typeof v === "string") parts.push(v);
    else if (Array.isArray(v)) {
      if (depth < MAX_DEPTH) for (const i of v) walk(i, depth + 1);
    } else if (isObject(v)) {
      if (depth < MAX_DEPTH) for (const k of Object.keys(v).sort(cmpCodePoints)) walk(v[k], depth + 1);
    }
  };
  walk(payload, 0);
  return parts.join(" ");
}

const WORD = /[\p{Alphabetic}\p{N}]/u;

/** Lower-cased runs of letters and digits, at most MAX_TOKENS. */
export function tokens(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  for (const ch of s) {
    if (WORD.test(ch)) cur += ch;
    else if (cur) {
      out.push(cur.toLowerCase());
      cur = "";
      if (out.length >= MAX_TOKENS) return out;
    }
  }
  if (cur && out.length < MAX_TOKENS) out.push(cur.toLowerCase());
  return out;
}

export function shingles(t: string[]): string[] {
  if (t.length === 0) return [];
  if (t.length < SHINGLE) return [t.join(" ")];
  const out: string[] = [];
  for (let i = 0; i + SHINGLE <= t.length; i++) out.push(t.slice(i, i + SHINGLE).join(" "));
  return out;
}

export function fmix32(h: number): number {
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h >>> 0;
}

const rotl = (x: number, r: number) => ((x << r) | (x >>> (32 - r))) >>> 0;

/** MurmurHash3, x86 32-bit. */
export function murmur3(data: Uint8Array, seed = 0): number {
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  let h = seed >>> 0;
  const n = data.length & ~3;
  for (let i = 0; i < n; i += 4) {
    let k = (data[i]! | (data[i + 1]! << 8) | (data[i + 2]! << 16) | (data[i + 3]! << 24)) >>> 0;
    k = Math.imul(rotl(Math.imul(k, c1) >>> 0, 15), c2) >>> 0;
    h ^= k;
    h = (Math.imul(rotl(h >>> 0, 13), 5) + 0xe6546b64) >>> 0;
  }
  let k = 0;
  const tail = data.length & 3;
  for (let i = 0; i < tail; i++) k |= data[n + i]! << (8 * i);
  if (tail) {
    k = Math.imul(rotl(Math.imul(k >>> 0, c1) >>> 0, 15), c2) >>> 0;
    h ^= k;
  }
  h ^= data.length;
  return fmix32(h >>> 0);
}

const SEEDS: number[] = Array.from({ length: SLOTS }, (_, i) => fmix32(Math.imul(0x9e3779b9, i + 1) >>> 0));

/** The MinHash signature of a text; null when it has no words. */
export function signatureOf(text: string): Uint32Array | null {
  const sh = shingles(tokens(text));
  if (sh.length === 0) return null;
  const mins = new Uint32Array(SLOTS).fill(0xffffffff);
  for (const s of sh) {
    const base = murmur3(utf8(s));
    for (let i = 0; i < SLOTS; i++) {
      const h = fmix32((base ^ SEEDS[i]!) >>> 0);
      if (h < mins[i]!) mins[i] = h;
    }
  }
  return mins;
}

export function encodeSignature(sig: Uint32Array): string {
  const bytes = new Uint8Array(SLOTS * 4);
  const view = new DataView(bytes.buffer);
  for (let i = 0; i < SLOTS; i++) view.setUint32(i * 4, sig[i]!, false);
  return toBase64Url(bytes);
}

export function decodeSignature(s: string): Uint32Array | null {
  if (typeof s !== "string" || s.length !== 342 || !/^[A-Za-z0-9_-]+$/.test(s)) return null;
  const bytes = fromBase64(s);
  if (!bytes || bytes.byteLength !== SLOTS * 4) return null;
  const view = new DataView(bytes.buffer);
  const out = new Uint32Array(SLOTS);
  for (let i = 0; i < SLOTS; i++) out[i] = view.getUint32(i * 4, false);
  return out;
}

export function similarity(a: Uint32Array, b: Uint32Array): number {
  let same = 0;
  for (let i = 0; i < SLOTS; i++) if (a[i] === b[i]) same++;
  return same / SLOTS;
}

function typeName(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  switch (typeof v) {
    case "boolean":
      return "boolean";
    case "number":
      return "number";
    case "string":
      return "string";
    default:
      return "object";
  }
}

/** The payload's shape: field paths and their types, hashed (hex SHA-256). */
export async function shapeHash(payload: unknown): Promise<string> {
  const fields = new Map<string, Set<string>>();
  const visit = (v: unknown, path: string, depth: number) => {
    if (path !== "payload") {
      if (!fields.has(path) && fields.size >= MAX_FIELDS) return;
      let set = fields.get(path);
      if (!set) fields.set(path, (set = new Set()));
      set.add(typeName(v));
    }
    if (depth >= MAX_DEPTH) return;
    if (isObject(v)) {
      for (const k of Object.keys(v).sort(cmpCodePoints)) visit(v[k], `${path}.${k}`, depth + 1);
    } else if (Array.isArray(v)) {
      for (const item of v.slice(0, MAX_ITEMS)) visit(item, `${path}[]`, depth + 1);
    }
  };
  visit(payload, "payload", 0);
  const lines = [...fields].map(([p, t]) => `${p}:${[...t].sort().join("|")}`).sort(cmpCodePoints);
  return sha256Hex(utf8(lines.join("\n")));
}

// ── fields ──────────────────────────────────────────────────────────────────────────────────────

function splitPath(rest: string): string[] {
  const out: string[] = [];
  for (const dotted of rest.split(".").filter((s) => s.length > 0)) {
    let s = dotted;
    let i: number;
    while ((i = s.indexOf("[]")) >= 0) {
      if (i > 0) out.push(s.slice(0, i));
      out.push("[]");
      s = s.slice(i + 2);
    }
    if (s) out.push(s);
  }
  return out;
}

export function validPath(path: unknown): path is string {
  if (typeof path !== "string" || path.length > 300 || /[\u0000-\u001f\u007f]/.test(path)) return false;
  if (path === "payload" || path.startsWith("payload.") || path.startsWith("payload[]")) return true;
  return /^headers\.[A-Za-z0-9_-]+$/.test(path);
}

function scalarText(v: unknown): string | null {
  if (typeof v === "string") return v;
  if (typeof v === "boolean") return String(v);
  if (typeof v === "number") return Number.isFinite(v) ? JSON.stringify(v) : null;
  return null;
}

/** The values of one path the edge reads: the first 64, in document order. */
export const MAX_VALUES = 64;

/**
 * The values at a catalogue path (`payload.a[].b`, `headers.name`): at most `max`, in document
 * order. `visit` is told of every node the walk passes, so a delivery's budget can count them.
 */
export function valuesAt(payload: unknown, headers: Headers, path: string, max = MAX_VALUES, visit: () => void = () => {}): string[] {
  if (path.startsWith("headers.")) {
    const v = headers.get(path.slice("headers.".length));
    return v === null ? [] : [v];
  }
  if (!path.startsWith("payload")) return [];
  const parts = splitPath(path.slice("payload".length));
  const out: string[] = [];
  // Depth first is document order: every value of a0 before any of a1.
  const walk = (v: unknown, i: number): void => {
    visit();
    if (i === parts.length) {
      const s = scalarText(v);
      if (s !== null) out.push(s);
      return;
    }
    const part = parts[i]!;
    if (part === "[]") {
      if (!Array.isArray(v)) return;
      for (const x of v) {
        if (out.length >= max) return;
        walk(x, i + 1);
      }
    } else if (isObject(v) && Object.hasOwn(v, part)) walk(v[part], i + 1);
  };
  walk(payload, 0);
  return out;
}

export const fold = (v: string) => v.trim().toLowerCase();

/** The domain of an address or URL, as the harness reads it. */
export function domainOf(raw: string): string {
  const v = raw.trim().toLowerCase();
  let host: string;
  const at = v.lastIndexOf("@");
  if (at >= 0 && !v.includes("://")) host = v.slice(at + 1);
  else if (v.includes("://")) {
    const rest = v.slice(v.indexOf("://") + 3);
    const ends = ["/", "?", "#"].map((c) => rest.indexOf(c)).filter((i) => i >= 0);
    let authority = rest.slice(0, ends.length ? Math.min(...ends) : rest.length);
    authority = authority.slice(authority.lastIndexOf("@") + 1);
    if (authority.startsWith("[")) {
      const e = authority.indexOf("]");
      host = e >= 0 ? authority.slice(0, e + 1) : authority;
    } else {
      const c = authority.lastIndexOf(":");
      host = c >= 0 ? authority.slice(0, c) : authority;
    }
  } else host = v;
  // Without the trailing dots (a loop: a regular expression here is quadratic on a run of dots).
  let end = host.length;
  while (end > 0 && host.charCodeAt(end - 1) === 0x2e) end--;
  return host.slice(0, end);
}

/** The longest domain the edge reads, in UTF-8 bytes, and its most labels (as DNS has them). */
export const MAX_DOMAIN_BYTES = 253;
export const MAX_DOMAIN_LABELS = 127;

/** The domain and every parent of it; none for a domain longer than DNS allows (it never matches). */
export function domainSuffixes(domain: string): string[] {
  if (domain.length > MAX_DOMAIN_BYTES || utf8(domain).byteLength > MAX_DOMAIN_BYTES) return [];
  let labels = 1;
  for (let i = 0; i < domain.length; i++) if (domain.charCodeAt(i) === 0x2e) labels++;
  if (labels > MAX_DOMAIN_LABELS) return [];
  const out: string[] = [];
  let d = domain;
  for (;;) {
    if (d) out.push(d);
    const i = d.indexOf(".");
    if (i < 0) return out;
    d = d.slice(i + 1);
  }
}

const fieldInput = (path: string, normalised: string) => utf8(`00hooks-screen-field-v1\n${path}\n${normalised}`);

/** The screen key as a `CryptoKey`: imported once for a delivery, not once per hash. */
export function importScreenKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

/** HMAC-SHA256 under the screen key of `00hooks-screen-field-v1\n<path>\n<value>`, 16 bytes, base64url. */
export async function keyedHash(key: Uint8Array<ArrayBuffer> | CryptoKey, path: string, normalised: string): Promise<string> {
  const k = key instanceof Uint8Array ? await importScreenKey(key) : key;
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k, fieldInput(path, normalised)));
  return toBase64Url(mac.subarray(0, 16));
}

/** The account's screen key: devices hash field values with it, and the relay hashes what arrives. */
export async function screenKey(pepper: string, accountId: string): Promise<Uint8Array<ArrayBuffer>> {
  return hmac("SHA-256", utf8(pepper), utf8(`screen-key:${accountId}`));
}

/** The account's screen key, ready to hash with, for one delivery. */
export async function screenCryptoKey(pepper: string, accountId: string): Promise<CryptoKey> {
  return importScreenKey(await screenKey(pepper, accountId));
}

/**
 * Whether a pattern can run at the edge: it is in the subset the relay's linear-time matcher takes
 * (`screen-pattern.ts`: no back-references or look-around, at most 200 characters, a weight of at
 * most 250 once its repeats are counted). The harness checks the same.
 */
export function edgeSafePattern(pattern: string): boolean {
  try {
    patternWeight(pattern);
    return true;
  } catch {
    return false;
  }
}

// ── parsing what a device pushes ────────────────────────────────────────────────────────────────

const bad = (field: string, message: string): never => {
  throw new HttpError(invalid(field, message));
};

const HASH = /^[A-Za-z0-9_-]{22}$/;

function parseNet(s: unknown): Net | null {
  if (typeof s !== "string" || s.length > 64) return null;
  const [a, p, extra] = s.trim().split("/");
  if (extra !== undefined || a === undefined) return null;
  const v4 = parseIpv4(a);
  const v6 = v4 ? null : a.includes(":") ? expandIpv6(a) : null;
  if (!v4 && !v6) return null;
  const max = v4 ? 32 : 128;
  const prefix = p === undefined ? max : /^\d{1,3}$/.test(p) ? Number(p) : NaN;
  if (!(prefix >= 0 && prefix <= max)) return null;
  return { v4: v4 !== null, bits: v4 ?? v6!.flatMap((g) => [g >> 8, g & 255]), prefix };
}

interface Net {
  v4: boolean;
  /** The address's bytes. */
  bits: number[];
  prefix: number;
}

function parseIpv4(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const b = m.slice(1).map(Number);
  return b.every((x) => x <= 255) ? b : null;
}

function ipBytes(ip: string | null): { v4: boolean; bytes: number[] } | null {
  if (!ip) return null;
  const v4 = parseIpv4(ip.trim());
  if (v4) return { v4: true, bytes: v4 };
  const g = expandIpv6(ip.trim());
  if (!g) return null;
  // An IPv4-mapped IPv6 address is the IPv4 client.
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    return { v4: true, bytes: [g[6]! >> 8, g[6]! & 255, g[7]! >> 8, g[7]! & 255] };
  }
  return { v4: false, bytes: g.flatMap((x) => [x >> 8, x & 255]) };
}

function inNet(ip: { v4: boolean; bytes: number[] }, n: Net): boolean {
  if (ip.v4 !== n.v4) return false;
  let left = n.prefix;
  for (let i = 0; left > 0; i++, left -= 8) {
    const mask = left >= 8 ? 0xff : (0xff << (8 - left)) & 0xff;
    if ((ip.bytes[i]! & mask) !== (n.bits[i]! & mask)) return false;
  }
  return true;
}

function list<T>(v: unknown, field: string, each: (x: unknown) => T | null): T[] {
  if (!Array.isArray(v) || v.length === 0 || v.length > MAX_LIST) bad(field, `${field} is a list of 1 to ${MAX_LIST} entries.`);
  return (v as unknown[]).map((x) => each(x) ?? bad(field, `${field} has an entry it can't read.`));
}

function threshold(v: unknown, field: string): number | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== "number" || !(v >= 0.5 && v <= 1)) bad(field, "A similarity threshold is from 0.5 to 1.");
  return v as number;
}

const hashList = (v: unknown, field: string) => list(v, field, (x) => (typeof x === "string" && HASH.test(x) ? x : null));

function parseCondition(raw: unknown, field: string): Condition {
  if (!isObject(raw)) return bad(field, "A condition is an object.");
  const not = raw.not === undefined ? undefined : raw.not === true ? true : raw.not === false ? false : bad(`${field}.not`, "not is true or false.");
  const withNot = <T extends object>(c: T): T => (not ? { ...c, not: true } : c);
  switch (raw.on) {
    case "ip": {
      const nets = list(raw.in, `${field}.in`, (x) => (parseNet(x) ? (x as string).trim() : null));
      const preset = raw.preset === undefined ? undefined : typeof raw.preset === "string" && /^[a-z0-9-]{1,32}$/.test(raw.preset) ? raw.preset : bad(`${field}.preset`, "A preset is a short name.");
      return withNot({ on: "ip", in: nets, ...(preset ? { preset } : {}) });
    }
    case "asn":
      return withNot({ on: "asn", in: list(raw.in, `${field}.in`, (x) => (Number.isInteger(x) && (x as number) >= 0 && (x as number) <= 4294967295 ? (x as number) : null)) });
    case "country":
      return withNot({ on: "country", in: list(raw.in, `${field}.in`, (x) => (typeof x === "string" && /^[A-Za-z]{2}$/.test(x) ? x.toUpperCase() : null)) });
    case "header": {
      const name = typeof raw.name === "string" && /^[A-Za-z0-9_-]{1,100}$/.test(raw.name) ? raw.name.toLowerCase() : bad(`${field}.name`, "A header name is letters, digits, - or _.");
      const op = raw.op;
      if (op === "is") {
        // Held as keyed hashes, as a field's `is` is (path `headers.<name>`): never the value.
        if (raw.value !== undefined) return bad(`${field}.value`, "A header's is travels as keyed hashes (hashes over headers.<name>), as a field's does; the relay keeps no header value.");
        return { on: "header", name, op, hashes: hashList(raw.hashes, `${field}.hashes`) };
      }
      if (op === "contains") {
        const value = typeof raw.value === "string" && raw.value.trim().length > 0 && raw.value.length <= 1000 ? raw.value.trim().toLowerCase() : bad(`${field}.value`, "A header condition needs a value.");
        return { on: "header", name, op, value };
      }
      if (op === "present" || op === "absent") return { on: "header", name, op };
      return bad(`${field}.op`, "A header's op is present, absent, is or contains.");
    }
    case "size": {
      if (raw.op !== "gt" && raw.op !== "lt") return bad(`${field}.op`, "A size's op is gt or lt.");
      const bytes = Number.isInteger(raw.bytes) && (raw.bytes as number) >= 0 ? (raw.bytes as number) : bad(`${field}.bytes`, "bytes is a whole number.");
      return { on: "size", op: raw.op, bytes };
    }
    case "field": {
      const path = validPath(raw.path) ? raw.path : bad(`${field}.path`, "A field is payload.… or headers.….");
      switch (raw.op) {
        case "is":
        case "domain_is":
        case "one_of":
          return withNot({ on: "field", path, op: raw.op, hashes: hashList(raw.hashes, `${field}.hashes`) });
        case "contains": {
          const words = typeof raw.words === "string" && raw.words.length <= 1000 && tokens(raw.words).length > 0 ? raw.words : bad(`${field}.words`, "contains needs words.");
          return withNot({ on: "field", path, op: "contains", words });
        }
        case "pattern": {
          if (typeof raw.pattern !== "string") return bad(`${field}.pattern`, "A pattern is text.");
          try {
            patternWeight(raw.pattern);
          } catch (e) {
            if (!(e instanceof PatternError)) throw e;
            return bad(`${field}.pattern`, `This pattern can't run at the edge: ${e.message}. The edge takes a linear-time subset (PROTOCOL §4b).`);
          }
          return withNot({ on: "field", path, op: "pattern", pattern: raw.pattern });
        }
        case "similar_text": {
          const signature = typeof raw.signature === "string" && decodeSignature(raw.signature) ? raw.signature : bad(`${field}.signature`, "A signature is 342 base64url characters.");
          const t = threshold(raw.threshold, `${field}.threshold`);
          return withNot({ on: "field", path, op: "similar_text", signature, ...(t !== undefined ? { threshold: t } : {}) });
        }
        default:
          return bad(`${field}.op`, "A field's op is is, domain_is, one_of, contains, pattern or similar_text.");
      }
    }
    case "similar": {
      const shape = raw.shape === undefined ? undefined : typeof raw.shape === "string" && /^[0-9a-f]{64}$/.test(raw.shape) ? raw.shape : bad(`${field}.shape`, "A shape is 64 hex characters.");
      const text = raw.text === undefined || raw.text === null ? undefined : typeof raw.text === "string" && decodeSignature(raw.text) ? raw.text : bad(`${field}.text`, "A text fingerprint is 342 base64url characters.");
      if (!shape && !text) return bad(field, "A similarity condition needs a shape or a text fingerprint.");
      const t = threshold(raw.threshold, `${field}.threshold`);
      return { on: "similar", ...(shape ? { shape } : {}), ...(text ? { text } : {}), ...(t !== undefined ? { threshold: t } : {}) };
    }
    default:
      return bad(`${field}.on`, "A condition is on ip, asn, country, header, size, field or similar.");
  }
}

const needsWords = (c: Condition) =>
  (c.on === "field" && (c.op === "contains" || c.op === "pattern" || c.op === "similar_text")) || (c.on === "header" && c.op === "contains");

/** Reads a hook's screen as a device pushed it (`PUT /v1/hooks/<id>/screen`); throws `invalid`. */
export function parseScreen(raw: unknown): EdgeScreen | null {
  if (raw === null) return null;
  if (!isObject(raw)) return bad("screen", "screen is an object or null.");
  const consent = isObject(raw.consent) && raw.consent.words === true;
  if (!Array.isArray(raw.rules) || raw.rules.length > MAX_RULES) return bad("screen.rules", `rules is a list of at most ${MAX_RULES}.`);
  const ids = new Set<string>();
  const rules = raw.rules.map((r, i): EdgeRule => {
    const f = `screen.rules[${i}]`;
    if (!isObject(r)) return bad(f, "A rule is an object.");
    const id = typeof r.id === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(r.id) && !ids.has(r.id) ? r.id : bad(`${f}.id`, "A rule's id is 1 to 64 letters, digits, - or _, and unique.");
    ids.add(id);
    const verdict = VERDICTS.includes(r.verdict as Verdict) ? (r.verdict as Verdict) : bad(`${f}.verdict`, "A verdict is pass, quarantine or drop.");
    if (!Array.isArray(r.conditions) || r.conditions.length === 0 || r.conditions.length > MAX_CONDITIONS) {
      return bad(`${f}.conditions`, `A rule has 1 to ${MAX_CONDITIONS} conditions.`);
    }
    const conditions = r.conditions.map((c, j) => parseCondition(c, `${f}.conditions[${j}]`));
    if (!consent && conditions.some(needsWords)) {
      return bad("screen.consent", "contains (on a field or a header), pattern and similar_text rules make the relay read words; send consent.words to allow it.");
    }
    return { id, verdict, ...(r.any === true ? { any: true } : {}), conditions };
  });
  const weights = new Map<string, number>();
  for (const r of rules) for (const c of r.conditions) if (c.on === "field" && c.op === "pattern") weights.set(c.pattern, patternWeight(c.pattern));
  if ([...weights.values()].reduce((s, w) => s + w, 0) > MAX_SCREEN_PATTERN_WEIGHT) {
    return bad("screen.rules", `The patterns of one screen weigh at most ${MAX_SCREEN_PATTERN_WEIGHT} together, once their repeats are counted (each different pattern once).`);
  }
  return { rules, consent: { words: consent && rules.some((r) => r.conditions.some(needsWords)) } };
}

// ── compiling, once per isolate ─────────────────────────────────────────────────────────────────

type Check =
  | { on: "ip"; nets: Net[]; not: boolean }
  | { on: "asn"; in: Set<number>; not: boolean }
  | { on: "country"; in: Set<string>; not: boolean }
  | { on: "header"; name: string; op: "present" | "absent" }
  /** `plain`: a value stored before header values became hashes, until the screen is pushed again. */
  | { on: "header"; name: string; op: "is"; path: string; hashes: Set<string>; plain: string | null }
  | { on: "header"; name: string; op: "contains"; value: string }
  | { on: "size"; op: "gt" | "lt"; bytes: number }
  | { on: "field"; path: string; not: boolean; op: "hash"; domain: boolean; hashes: Set<string> }
  | { on: "field"; path: string; not: boolean; op: "contains"; words: string[] }
  /** `re` is null for a pattern stored before the subset that it isn't in: it never holds. */
  | { on: "field"; path: string; not: boolean; op: "pattern"; re: CompiledPattern | null }
  | { on: "field"; path: string; not: boolean; op: "similar_text"; signature: Uint32Array | null; threshold: number }
  | { on: "similar"; shape: string | undefined; text: Uint32Array | null | undefined; threshold: number };

export interface CompiledScreen {
  rules: { id: string; verdict: Verdict; any: boolean; checks: Check[] }[];
}

/** A screen as kept, made ready to run: networks parsed, patterns compiled, hashes in sets. */
export function compileScreen(screen: EdgeScreen): CompiledScreen {
  const patterns = new Map<string, CompiledPattern | null>();
  const pattern = (p: string) => {
    if (!patterns.has(p)) {
      let re: CompiledPattern | null = null;
      try {
        re = compilePattern(p);
      } catch {
        re = null;
      }
      patterns.set(p, re);
    }
    return patterns.get(p)!;
  };
  const check = (c: Condition): Check => {
    const not = "not" in c && c.not === true;
    switch (c.on) {
      case "ip":
        return { on: "ip", nets: c.in.map(parseNet).filter((n): n is Net => n !== null), not };
      case "asn":
        return { on: "asn", in: new Set(c.in), not };
      case "country":
        return { on: "country", in: new Set(c.in.map((x) => x.toUpperCase())), not };
      case "header":
        if (c.op === "is") {
          const legacy = (c as { value?: unknown }).value;
          return { on: "header", name: c.name, op: "is", path: `headers.${c.name}`, hashes: new Set(c.hashes ?? []), plain: typeof legacy === "string" ? legacy : null };
        }
        if (c.op === "contains") return { on: "header", name: c.name, op: "contains", value: c.value };
        return { on: "header", name: c.name, op: c.op };
      case "size":
        return { on: "size", op: c.op, bytes: c.bytes };
      case "field":
        return fieldCheck(c, not);
      case "similar":
        return { on: "similar", shape: c.shape, text: c.text ? decodeSignature(c.text) : undefined, threshold: c.threshold ?? DEFAULT_THRESHOLD };
    }
  };
  const fieldCheck = (c: Extract<Condition, { on: "field" }>, not: boolean): Check => {
    switch (c.op) {
      case "is":
      case "one_of":
      case "domain_is":
        return { on: "field", path: c.path, not, op: "hash", domain: c.op === "domain_is", hashes: new Set(c.hashes) };
      case "contains":
        return { on: "field", path: c.path, not, op: "contains", words: tokens(c.words) };
      case "pattern":
        return { on: "field", path: c.path, not, op: "pattern", re: pattern(c.pattern) };
      case "similar_text":
        return { on: "field", path: c.path, not, op: "similar_text", signature: decodeSignature(c.signature), threshold: c.threshold ?? DEFAULT_THRESHOLD };
    }
  };
  return { rules: screen.rules.map((r) => ({ id: r.id, verdict: r.verdict, any: r.any === true, checks: r.conditions.map(check) })) };
}

/** Compiled screens kept by an isolate: at most this many, and this much stored JSON among them. */
export const MAX_CACHED_SCREENS = 256;
const MAX_CACHED_CHARS = 4 * 1024 * 1024;
const cached = new Map<string, { screen: CompiledScreen; size: number }>();
let cachedChars = 0;

/**
 * The hook's screen, compiled, from the JSON its row keeps: compiled once per isolate, keyed by the
 * hook and a hash of that JSON (so a new screen is a new entry), least recently used out first.
 */
export async function screenFor(hookId: string, stored: string | null | undefined): Promise<CompiledScreen | null> {
  if (!stored) return null;
  const id = `${hookId}:${await sha256Hex(utf8(stored))}`;
  const hit = cached.get(id);
  if (hit) {
    cached.delete(id);
    cached.set(id, hit);
    return hit.screen;
  }
  const screen = compileScreen(JSON.parse(stored) as EdgeScreen);
  if (stored.length <= MAX_CACHED_CHARS) {
    cached.set(id, { screen, size: stored.length });
    cachedChars += stored.length;
    while (cached.size > MAX_CACHED_SCREENS || cachedChars > MAX_CACHED_CHARS) {
      const [oldest, entry] = cached.entries().next().value!;
      cached.delete(oldest);
      cachedChars -= entry.size;
    }
  }
  return screen;
}

/** How many compiled screens this isolate keeps (for tests). */
export const cachedScreens = () => cached.size;

// ── deciding ────────────────────────────────────────────────────────────────────────────────────

/** The most bytes one delivery's keyed hashes read (the HMAC input, path and value). */
export const MAX_HASHED_BYTES = 256 * 1024;
/** The most steps one delivery's patterns and `contains` comparisons take. */
export const MAX_SCREEN_STEPS = 2_000_000;
/** The most payload nodes one delivery's field paths pass. */
export const MAX_WALK = 1_000_000;
/** The rule a delivery is held under when screening it would cost more than the budget. */
export const OVER_BUDGET_RULE = "~over-budget";

class OverBudget extends Error {}

export interface Delivery {
  ip: string | null;
  asn: number | null;
  country: string | null;
  headers: Headers;
  body: Uint8Array;
  contentType: string | null;
  /** A strict hook: the relay never parses its body, so body conditions don't hold. */
  strict: boolean;
  /** The account's screen key, imported once for this delivery. */
  key: CryptoKey;
}

/** What the conditions read, worked out at most once, and the delivery's budget. */
class View implements Steps {
  private payloadValue: unknown;
  private parsed = false;
  private shapeValue: Promise<string> | null = null;
  private textSig: Uint32Array | null | undefined;
  private hashed = 0;
  private steps = 0;
  private walked = 0;
  private readonly values = new Map<string, string[]>();
  private readonly hashes = new Map<string, Promise<string>>();
  private readonly words = new Map<string, string[]>();
  private readonly sigs = new Map<string, Uint32Array | null>();
  private readonly points = new Map<string, Int32Array>();
  private readonly matched = new Map<CompiledPattern, Map<string, boolean>>();
  readonly ip: { v4: boolean; bytes: number[] } | null;
  readonly d: Delivery;
  constructor(d: Delivery) {
    this.d = d;
    this.ip = ipBytes(d.ip);
  }
  payload(): unknown {
    if (this.d.strict) return undefined;
    if (!this.parsed) {
      this.payloadValue = parsePayload(this.d.body, this.d.contentType);
      this.parsed = true;
    }
    return this.payloadValue;
  }
  shape(): Promise<string> | null {
    if (this.d.strict) return null;
    return (this.shapeValue ??= shapeHash(this.payload()));
  }
  text(): Uint32Array | null {
    if (this.d.strict) return null;
    if (this.textSig === undefined) this.textSig = signatureOf(itemText(this.payload()));
    return this.textSig;
  }
  step(n: number): void {
    this.steps += n;
    if (this.steps > MAX_SCREEN_STEPS) throw new OverBudget();
  }
  valuesAt(path: string): string[] {
    let v = this.values.get(path);
    if (v === undefined) {
      const payload = path.startsWith("headers.") ? undefined : this.payload();
      v = valuesAt(payload, this.d.headers, path, MAX_VALUES, () => {
        if (++this.walked > MAX_WALK) throw new OverBudget();
      });
      this.values.set(path, v);
    }
    return v;
  }
  /** A keyed hash, once per (path, value); the bytes it reads count against the budget. */
  hash(path: string, normalised: string): Promise<string> {
    const memo = `${path}\n${normalised}`;
    let h = this.hashes.get(memo);
    if (h === undefined) {
      const input = fieldInput(path, normalised);
      this.hashed += input.byteLength;
      if (this.hashed > MAX_HASHED_BYTES) throw new OverBudget();
      h = crypto.subtle.sign("HMAC", this.d.key, input).then((mac) => toBase64Url(new Uint8Array(mac).subarray(0, 16)));
      this.hashes.set(memo, h);
    }
    return h;
  }
  tokens(value: string): string[] {
    let t = this.words.get(value);
    if (t === undefined) this.words.set(value, (t = tokens(value)));
    return t;
  }
  signature(value: string): Uint32Array | null {
    let s = this.sigs.get(value);
    if (s === undefined) this.sigs.set(value, (s = signatureOf(value)));
    return s;
  }
  matches(re: CompiledPattern, value: string): boolean {
    let seen = this.matched.get(re);
    if (!seen) this.matched.set(re, (seen = new Map()));
    let m = seen.get(value);
    if (m === undefined) {
      let cps = this.points.get(value);
      if (!cps) this.points.set(value, (cps = codePoints(value, EDGE_PATTERN_INPUT)));
      seen.set(value, (m = re.test(cps, this)));
    }
    return m;
  }
}

async function holds(c: Check, v: View): Promise<boolean> {
  const d = v.d;
  switch (c.on) {
    case "ip":
      return v.ip !== null && c.nets.some((n) => inNet(v.ip!, n)) !== c.not;
    case "asn":
      return d.asn !== null && c.in.has(d.asn) !== c.not;
    case "country":
      return d.country !== null && c.in.has(d.country.toUpperCase()) !== c.not;
    case "header": {
      const h = d.headers.get(c.name);
      switch (c.op) {
        case "present":
          return h !== null;
        case "absent":
          return h === null;
        case "contains":
          return h !== null && h.toLowerCase().includes(c.value);
        case "is": {
          if (h === null) return false;
          const folded = fold(h);
          if (c.plain !== null && folded === c.plain) return true;
          return c.hashes.size > 0 && c.hashes.has(await v.hash(c.path, folded));
        }
      }
      return false;
    }
    case "size":
      return c.op === "gt" ? d.body.byteLength > c.bytes : d.body.byteLength < c.bytes;
    case "field": {
      if (!c.path.startsWith("headers.") && v.payload() === undefined) return false;
      const values = v.valuesAt(c.path);
      if (values.length === 0) return false;
      let any = false;
      for (const value of values) {
        if (await fieldHolds(c, value, v)) {
          any = true;
          break;
        }
      }
      return any !== c.not;
    }
    case "similar": {
      if (c.shape) {
        const s = v.shape();
        if (s === null || (await s) !== c.shape) return false;
      }
      if (c.text === undefined) return true;
      const mine = v.text();
      return mine !== null && c.text !== null && similarity(mine, c.text) >= c.threshold;
    }
  }
}

async function fieldHolds(c: Extract<Check, { on: "field" }>, value: string, v: View): Promise<boolean> {
  switch (c.op) {
    case "hash":
      if (!c.domain) return c.hashes.has(await v.hash(c.path, fold(value)));
      for (const s of domainSuffixes(domainOf(value))) if (c.hashes.has(await v.hash(c.path, s))) return true;
      return false;
    case "contains": {
      const want = c.words;
      const have = v.tokens(value);
      for (let i = 0; i + want.length <= have.length; i++) {
        let j = 0;
        while (j < want.length && have[i + j] === want[j]) j++;
        v.step(j + 1);
        if (j === want.length) return true;
      }
      return false;
    }
    case "pattern":
      return c.re !== null && v.matches(c.re, value);
    case "similar_text": {
      const mine = v.signature(value);
      return mine !== null && c.signature !== null && similarity(mine, c.signature) >= c.threshold;
    }
  }
}

/**
 * The first rule that holds for a delivery, or null (pass). A delivery whose screening would cost
 * more than the budget (hashing, pattern steps, the walk) is held under `~over-budget`.
 */
export async function decide(screen: CompiledScreen, d: Delivery): Promise<{ verdict: Verdict; rule: string } | null> {
  const view = new View(d);
  try {
    for (const r of screen.rules) {
      let ok: boolean;
      if (r.any) {
        ok = false;
        for (const c of r.checks) {
          if (await holds(c, view)) {
            ok = true;
            break;
          }
        }
      } else {
        ok = true;
        for (const c of r.checks) {
          if (!(await holds(c, view))) {
            ok = false;
            break;
          }
        }
      }
      if (ok) return { verdict: r.verdict, rule: r.id };
    }
  } catch (e) {
    if (e instanceof OverBudget) return { verdict: "quarantine", rule: OVER_BUDGET_RULE };
    throw e;
  }
  return null;
}
