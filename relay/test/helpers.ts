// Test helpers: a signing client, account setup, and an incremental SSE reader.

import { env, exports } from "cloudflare:workers";
import { expect } from "vitest";
import type { AccountObject } from "../src/account-object.ts";
import type { PhoneObject } from "../src/phone-object.ts";
import { generateDeviceKey, signRequest, type DeviceKey } from "../src/canonical.ts";
import { concatBytes, fromBase64, toBase64, toBase64Url, toHex, utf8 } from "../src/encoding.ts";
import { SUITE, decodeContent, envelopeSigString, heldAad, openWith, sealAad, sealKid, type SealedContent } from "../src/envelope.ts";

export const BASE = "https://relay.test";

const worker = (exports as unknown as { default: Fetcher }).default;

export function fetchRelay(path: string, init: RequestInit = {}): Promise<Response> {
  return worker.fetch(new Request(BASE + path, init));
}

/** A device's X25519 sealing key pair, raw. */
export interface SealPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  /** The base64url public key, as `sealKey` sends it. */
  text: string;
  kid: string;
}

export async function newSealPair(): Promise<SealPair> {
  const pair = await SUITE.kem.generateKeyPair();
  const publicKey = new Uint8Array(await SUITE.kem.serializePublicKey(pair.publicKey));
  const privateKey = new Uint8Array(await SUITE.kem.serializePrivateKey(pair.privateKey));
  return { publicKey, privateKey, text: toBase64Url(publicKey), kid: await sealKid(publicKey) };
}

export interface TestDevice extends DeviceKey {
  accountId: string;
  publicKey: string;
  /** Null for a device created without a sealing key. */
  seal: SealPair | null;
}

export async function newAccount(name = "laptop", opts: { seal?: boolean } = {}): Promise<TestDevice> {
  const { privateKey, publicKey } = await generateDeviceKey();
  const seal = opts.seal === false ? null : await newSealPair();
  const res = await fetchRelay("/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ deviceName: name, publicKey, ...(seal ? { sealKey: seal.text } : {}) }),
  });
  expect(res.status).toBe(201);
  const { accountId, deviceId } = (await res.json()) as { accountId: string; deviceId: string };
  return { accountId, deviceId, privateKey, publicKey, seal };
}

/** A random address in 198.18.0.0/15 (reserved for testing). */
export function randomTestIp(): string {
  const b = crypto.getRandomValues(new Uint8Array(3));
  return `198.${18 + (b[0]! & 1)}.${b[1]}.${b[2]}`;
}

/** Adds a second device to `dev`'s account through an enrolment code. */
export async function enrolDevice(dev: TestDevice, name = "desktop", opts: { seal?: boolean } = {}): Promise<TestDevice> {
  const { code } = (await (await signed(dev, "POST", "/v1/enrolments")).json()) as { code: string };
  const { privateKey, publicKey } = await generateDeviceKey();
  const seal = opts.seal === false ? null : await newSealPair();
  const res = await fetchRelay("/v1/enrolments/redeem", {
    method: "POST",
    // A fresh address each time, so the per-address redemption limit never couples tests.
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": randomTestIp() },
    body: JSON.stringify({ code, deviceName: name, publicKey, ...(seal ? { sealKey: seal.text } : {}) }),
  });
  expect(res.status).toBe(200);
  const { accountId, deviceId } = (await res.json()) as { accountId: string; deviceId: string };
  return { accountId, deviceId, privateKey, publicKey, seal };
}

export async function signed(
  dev: DeviceKey,
  method: string,
  path: string,
  body?: unknown,
  opts: { headers?: Record<string, string>; time?: number; nonce?: string } = {},
): Promise<Response> {
  const bytes = body === undefined ? undefined : utf8(JSON.stringify(body));
  const sig = await signRequest(dev, method, BASE + path, bytes, { time: opts.time, nonce: opts.nonce });
  return fetchRelay(path, {
    method,
    headers: { ...(bytes ? { "Content-Type": "application/json" } : {}), ...sig, ...opts.headers },
    body: bytes,
  });
}

export interface CreatedHook {
  hook: { id: string; url: string; [k: string]: unknown };
  url: string;
  secret?: string;
}

export async function createHook(dev: DeviceKey, verify: Record<string, unknown>, name = "test"): Promise<CreatedHook> {
  const res = await signed(dev, "POST", "/v1/hooks", { name, verify });
  expect(res.status).toBe(201);
  return (await res.json()) as CreatedHook;
}

/** Posts an unverified delivery and returns the event id. */
export async function deliver(hookId: string, payload: unknown, headers: Record<string, string> = {}): Promise<string> {
  const res = await fetchRelay(`/h/${hookId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(payload),
  });
  expect(res.status).toBe(200);
  return ((await res.json()) as { received: string }).received;
}

export function accountObject(accountId: string): DurableObjectStub<AccountObject> {
  const ns = env.ACCOUNT as unknown as DurableObjectNamespace<AccountObject>;
  return ns.get(ns.idFromName(accountId));
}

export interface SseFrame {
  id?: string;
  event?: string;
  data?: string;
  comment?: string;
  retry?: number;
}

/** Reads an SSE response frame by frame. */
export class SseReader {
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private buffer = "";
  private readonly decoder = new TextDecoder();
  done = false;

  constructor(res: Response) {
    this.reader = res.body!.getReader();
  }

  async next(timeoutMs = 3000): Promise<SseFrame | null> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const end = this.buffer.indexOf("\n\n");
      if (end >= 0) {
        const block = this.buffer.slice(0, end);
        this.buffer = this.buffer.slice(end + 2);
        return parseBlock(block);
      }
      if (this.done) return null;
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error("timed out waiting for an SSE frame");
      let timer: ReturnType<typeof setTimeout> | undefined;
      const r = await Promise.race([
        this.reader.read(),
        new Promise<"timeout">((resolve) => (timer = setTimeout(() => resolve("timeout"), remaining))),
      ]);
      clearTimeout(timer);
      if (r === "timeout") throw new Error("timed out waiting for an SSE frame");
      if (r.done) this.done = true;
      else this.buffer += this.decoder.decode(r.value, { stream: true });
    }
  }

  /** The next frame that isn't a heartbeat or `retry`. */
  async nextEvent(timeoutMs = 3000): Promise<SseFrame | null> {
    for (;;) {
      const f = await this.next(timeoutMs);
      if (f === null || f.event !== undefined) return f;
    }
  }

  async cancel(): Promise<void> {
    await this.reader.cancel().catch(() => {});
  }
}

function parseBlock(block: string): SseFrame {
  const f: SseFrame = {};
  for (const line of block.split("\n")) {
    if (line.startsWith(":")) f.comment = line.slice(1).trim();
    else {
      const i = line.indexOf(":");
      const k = i < 0 ? line : line.slice(0, i);
      const v = i < 0 ? "" : line.slice(i + 1).replace(/^ /, "");
      if (k === "id") f.id = v;
      else if (k === "event") f.event = v;
      else if (k === "data") f.data = f.data === undefined ? v : `${f.data}\n${v}`;
      else if (k === "retry") f.retry = Number(v);
    }
  }
  return f;
}

export async function openStream(dev: DeviceKey, lastEventId?: number): Promise<{ res: Response; sse: SseReader }> {
  const headers: Record<string, string> = { Accept: "text/event-stream", "X-00h-Protocol": "2" };
  if (lastEventId !== undefined) headers["Last-Event-ID"] = String(lastEventId);
  const res = await signed(dev, "GET", "/v1/stream", undefined, { headers });
  expect(res.status).toBe(200);
  return { res, sse: new SseReader(res) };
}

export function data<T = Record<string, unknown>>(f: SseFrame | null): T {
  expect(f?.data).toBeDefined();
  return JSON.parse(f!.data!) as T;
}

/** The relay's public key in tests (RELAY_SIGNING_KEY is the seed 00…1f: PROTOCOL §1's example key). */
export const RELAY_PUBLIC_KEY = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";

export interface StreamedEvent {
  seq: number;
  id: string;
  hookId: string;
  receivedAt: number;
  verified: boolean;
  strict: boolean;
  preset: string;
  eventType: string | null;
  /** Released from the screen's hold (PROTOCOL §4b). */
  held?: boolean;
  sealed: { kid: string; enc: string; ct: string };
  sig: string;
}

/**
 * What a device does with a `hook` event: checks the relay's signature over the envelope with the
 * pinned key, then opens it with its sealing key. Throws when either fails.
 */
export async function openEvent(dev: TestDevice, ev: StreamedEvent): Promise<SealedContent & { text: string }> {
  expect(ev.sealed.kid).toBe(dev.seal!.kid);
  const ct = fromBase64(ev.sealed.ct)!;
  const toSign = await envelopeSigString({ ...ev, deviceId: dev.deviceId }, { kid: ev.sealed.kid, enc: ev.sealed.enc, ct });
  const key = await crypto.subtle.importKey("raw", fromBase64(RELAY_PUBLIC_KEY)!, { name: "Ed25519" }, false, ["verify"]);
  if (!(await crypto.subtle.verify("Ed25519", key, fromBase64(ev.sig)!, utf8(toSign)))) throw new Error("bad relay signature");
  const aad = ev.held ? heldAad(ev.hookId, ev.id) : sealAad(ev.hookId, ev.seq, ev.id);
  const pt = await openWith(dev.seal!.privateKey, fromBase64(ev.sealed.enc)!, ct, aad);
  const content = decodeContent(pt);
  return { ...content, text: new TextDecoder().decode(content.body) };
}

// ── phone links (PROTOCOL §10) ──────────────────────────────────────────────

export function phoneObject(accountId: string): DurableObjectStub<PhoneObject> {
  const ns = env.PHONE as unknown as DurableObjectNamespace<PhoneObject>;
  return ns.get(ns.idFromName(accountId));
}

const sha256 = async (b: Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));

/** What a node makes for "Add a phone" (PROTOCOL §10.1): the secret never reaches the relay. */
export interface TestPairing {
  secret: Uint8Array;
  pairingId: string;
  proof: string;
  verifier: string;
}

export async function newPairingSecret(): Promise<TestPairing> {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const pairingId = toBase64Url((await sha256(concatBytes(utf8("00next-pair-id-v1\n"), secret))).subarray(0, 16));
  const proof = toBase64Url(await sha256(concatBytes(utf8("00next-pair-relay-v1\n"), secret)));
  const verifier = toBase64Url(await sha256(utf8(proof)));
  return { secret, pairingId, proof, verifier };
}

/** Registers a pairing for `node`; returns the secret's derived values. */
export async function registerPairing(node: DeviceKey, expiresIn = 10 * 60_000): Promise<TestPairing> {
  const p = await newPairingSecret();
  const res = await signed(node, "POST", "/v1/phone/pairings", { pairingId: p.pairingId, verifier: p.verifier, expiresAt: Date.now() + expiresIn });
  expect(res.status).toBe(201);
  return p;
}

export const PHONE_INFO = "00next phone v1";

/** HPKE-seals (the suite of PROTOCOL §5) with the phone link's info string. */
export async function phoneSeal(recipient: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<{ enc: string; ct: string }> {
  const recipientPublicKey = await SUITE.kem.deserializePublicKey(recipient);
  const { ct, enc } = await SUITE.seal({ recipientPublicKey, info: utf8(PHONE_INFO) }, plaintext, aad);
  return { enc: toBase64Url(new Uint8Array(enc)), ct: toBase64(new Uint8Array(ct)) };
}

export async function phoneOpen(privateKey: Uint8Array, enc: string, ct: string, aad: Uint8Array): Promise<Uint8Array> {
  const recipientKey = await SUITE.kem.deserializePrivateKey(privateKey);
  return new Uint8Array(await SUITE.open({ recipientKey, enc: fromBase64(enc)!, info: utf8(PHONE_INFO) }, fromBase64(ct)!, aad));
}

/** A node: its 00hooks device plus the X25519 key phones seal to. */
export interface TestNode extends TestDevice {
  phoneSeal: SealPair;
}

export async function newNode(name = "mac"): Promise<TestNode> {
  const dev = await newAccount(name);
  return { ...dev, phoneSeal: await newSealPair() };
}

export interface TestPhone extends TestDevice {
  seal: SealPair;
  node: string;
  pairingId: string;
}

/** A phone redeems `pairing` (unsigned); returns the response and, on success, the phone. */
export async function redeemPhone(
  node: TestNode,
  pairing: TestPairing,
  opts: { name?: string; ip?: string; proof?: string } = {},
): Promise<{ res: Response; phone: TestPhone | null }> {
  const { privateKey, publicKey } = await generateDeviceKey();
  const seal = await newSealPair();
  const name = opts.name ?? "Ana's iPhone";
  const hello = await phoneSeal(
    node.phoneSeal.publicKey,
    utf8(JSON.stringify({ type: "pair_hello", name, model: "iPhone", signKey: publicKey, sealKey: seal.text, proof: "x" })),
    utf8(`00next-pair-v1\n${pairing.pairingId}`),
  );
  const res = await fetchRelay("/v1/phone/pair", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": opts.ip ?? randomTestIp() },
    body: JSON.stringify({ pairingId: pairing.pairingId, proof: opts.proof ?? pairing.proof, deviceName: name, publicKey, sealKey: seal.text, hello }),
  });
  if (res.status !== 200) return { res, phone: null };
  const body = (await res.clone().json()) as { deviceId: string; node: string };
  return { res, phone: { accountId: node.accountId, deviceId: body.deviceId, privateKey, publicKey, seal, node: body.node, pairingId: pairing.pairingId } };
}

/** Pairs a phone with `node`; confirmed unless `confirm` is false. */
export async function pairPhone(node: TestNode, opts: { confirm?: boolean; name?: string } = {}): Promise<TestPhone> {
  const pairing = await registerPairing(node);
  const { res, phone } = await redeemPhone(node, pairing, { name: opts.name });
  expect(res.status).toBe(200);
  if (opts.confirm !== false) {
    const c = await signed(node, "POST", `/v1/phone/devices/${phone!.deviceId}/confirm`);
    expect(c.status).toBe(200);
  }
  return phone!;
}

export type Frame = Record<string, unknown> & { t: string };

/** One phone-link socket, as a client sees it. */
export class PhoneSocket {
  readonly frames: Frame[] = [];
  private waiters: (() => void)[] = [];
  closeCode: number | null = null;
  closeReason = "";
  readonly closed: Promise<number>;
  readonly ws: WebSocket;

  constructor(ws: WebSocket) {
    this.ws = ws;
    let resolveClosed!: (code: number) => void;
    this.closed = new Promise((r) => (resolveClosed = r));
    ws.accept();
    ws.addEventListener("message", (e) => {
      const text = typeof e.data === "string" ? e.data : new TextDecoder().decode(e.data as ArrayBuffer);
      let f: Frame;
      try {
        f = JSON.parse(text) as Frame;
      } catch {
        f = { t: "text", text };
      }
      this.frames.push(f);
      this.wake();
    });
    ws.addEventListener("close", (e) => {
      this.closeCode = e.code;
      this.closeReason = e.reason;
      resolveClosed(e.code);
      this.wake();
    });
  }

  private wake(): void {
    const w = this.waiters;
    this.waiters = [];
    for (const f of w) f();
  }

  send(frame: unknown): void {
    this.ws.send(typeof frame === "string" ? frame : JSON.stringify(frame));
  }

  /** The next frame (any type). */
  next(timeoutMs = 3000): Promise<Frame> {
    return this.nextWhere(() => true, timeoutMs);
  }

  /** The first frame that matches, leaving the others queued in order. */
  async nextWhere(match: (f: Frame) => boolean, timeoutMs = 3000): Promise<Frame> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const i = this.frames.findIndex(match);
      if (i >= 0) return this.frames.splice(i, 1)[0]!;
      if (this.closeCode !== null) throw new Error(`socket closed (${this.closeCode} ${this.closeReason})`);
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error(`timed out waiting for a frame; have ${JSON.stringify(this.frames).slice(0, 300)}`);
      let timer: ReturnType<typeof setTimeout> | undefined;
      await new Promise<void>((resolve) => {
        this.waiters.push(resolve);
        timer = setTimeout(resolve, remaining);
      });
      clearTimeout(timer);
    }
  }

  /** The first frame of type `t`, leaving the others queued. */
  nextOf(t: string, timeoutMs = 3000): Promise<Frame> {
    return this.nextWhere((f) => f.t === t, timeoutMs);
  }

  /** Waits a moment and returns what arrived, without failing when nothing did. */
  async drain(ms = 150): Promise<Frame[]> {
    await new Promise((r) => setTimeout(r, ms));
    return this.frames.splice(0);
  }

  async hello(after = 0): Promise<Frame> {
    this.send({ t: "hello", after });
    return this.nextOf("ready");
  }

  close(): void {
    try {
      this.ws.close(1000, "bye");
    } catch {
      // Already closed.
    }
  }
}

/** Opens `dev`'s phone socket (signed upgrade). */
export async function openPhoneSocket(dev: DeviceKey): Promise<PhoneSocket> {
  const res = await signed(dev, "GET", "/v1/phone/socket", undefined, { headers: { Upgrade: "websocket" } });
  expect(res.status).toBe(101);
  return new PhoneSocket(res.webSocket!);
}

/** A phone envelope (PROTOCOL §10.4), sealed to `to`'s key and signed by `from`. */
export async function makeEnvelope(
  from: DeviceKey,
  to: { deviceId: string; sealKey: SealPair },
  plaintext: string,
  opts: { id?: string; push?: string; at?: number } = {},
): Promise<Record<string, unknown>> {
  const id = opts.id ?? toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const at = opts.at ?? Date.now();
  const sealed = await phoneSeal(to.sealKey.publicKey, utf8(plaintext), utf8(`00next-phone-v1\n${from.deviceId}\n${to.deviceId}\n${id}\n${at}`));
  const ct = fromBase64(sealed.ct)!;
  const lines = [
    "00next-phone-envelope-v1",
    from.deviceId,
    to.deviceId,
    id,
    String(at),
    to.sealKey.kid,
    sealed.enc,
    toHex(await crypto.subtle.digest("SHA-256", ct)),
    opts.push ?? "-",
  ].join("\n");
  const sig = toBase64Url(new Uint8Array(await crypto.subtle.sign("Ed25519", from.privateKey, utf8(lines))));
  return {
    v: 1,
    id,
    from: from.deviceId,
    to: to.deviceId,
    at,
    kid: to.sealKey.kid,
    enc: sealed.enc,
    ct: sealed.ct,
    sig,
    ...(opts.push !== undefined ? { push: opts.push } : {}),
  };
}
