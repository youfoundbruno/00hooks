// Test helpers: a signing client, account setup, and an incremental SSE reader.

import { env, exports } from "cloudflare:workers";
import { expect } from "vitest";
import type { AccountObject } from "../src/account-object.ts";
import { generateDeviceKey, signRequest, type DeviceKey } from "../src/canonical.ts";
import { utf8 } from "../src/encoding.ts";

export const BASE = "https://relay.test";

const worker = (exports as unknown as { default: Fetcher }).default;

export function fetchRelay(path: string, init: RequestInit = {}): Promise<Response> {
  return worker.fetch(new Request(BASE + path, init));
}

export interface TestDevice extends DeviceKey {
  accountId: string;
  publicKey: string;
}

export async function newAccount(name = "laptop"): Promise<TestDevice> {
  const { privateKey, publicKey } = await generateDeviceKey();
  const res = await fetchRelay("/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ deviceName: name, publicKey }),
  });
  expect(res.status).toBe(201);
  const { accountId, deviceId } = (await res.json()) as { accountId: string; deviceId: string };
  return { accountId, deviceId, privateKey, publicKey };
}

/** Adds a second device to `dev`'s account through an enrolment code. */
export async function enrolDevice(dev: TestDevice, name = "desktop"): Promise<TestDevice> {
  const { code } = (await (await signed(dev, "POST", "/v1/enrolments")).json()) as { code: string };
  const { privateKey, publicKey } = await generateDeviceKey();
  const res = await fetchRelay("/v1/enrolments/redeem", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, deviceName: name, publicKey }),
  });
  expect(res.status).toBe(200);
  const { accountId, deviceId } = (await res.json()) as { accountId: string; deviceId: string };
  return { accountId, deviceId, privateKey, publicKey };
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
  const headers: Record<string, string> = { Accept: "text/event-stream" };
  if (lastEventId !== undefined) headers["Last-Event-ID"] = String(lastEventId);
  const res = await signed(dev, "GET", "/v1/stream", undefined, { headers });
  expect(res.status).toBe(200);
  return { res, sse: new SseReader(res) };
}

export function data<T = Record<string, unknown>>(f: SseFrame | null): T {
  expect(f?.data).toBeDefined();
  return JSON.parse(f!.data!) as T;
}
