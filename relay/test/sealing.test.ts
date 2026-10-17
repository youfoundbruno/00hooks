// Sealing end to end (PLAN §4.4, PROTOCOL §5): what the relay stores, what each device receives, and
// the relay's signature over every envelope.

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { AccountObject } from "../src/account-object.ts";
import { fromBase64, hmac, toBase64, toBase64Url, toHex, utf8 } from "../src/encoding.ts";
import { openWith, sealAad } from "../src/envelope.ts";
import {
  accountObject,
  createHook,
  data,
  deliver,
  enrolDevice,
  fetchRelay,
  newAccount,
  newSealPair,
  openEvent,
  openStream,
  signed,
  type SseReader,
  type StreamedEvent,
  type TestDevice,
} from "./helpers.ts";

async function nextHook(sse: SseReader): Promise<StreamedEvent> {
  for (;;) {
    const f = await sse.nextEvent();
    if (f?.event === "hook") return data<StreamedEvent>(f);
    if (f === null) throw new Error("stream ended");
  }
}

/** Every value in every table of the account's Durable Object, as bytes. */
async function everyStoredValue(accountId: string): Promise<{ table: string; bytes: Uint8Array }[]> {
  return runInDurableObject(accountObject(accountId), (_o: AccountObject, state) => {
    const sql = state.storage.sql;
    const tables = sql
      .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table'")
      .toArray()
      .map((t) => t.name)
      .filter((n) => !n.startsWith("_cf") && !n.startsWith("sqlite_"));
    const out: { table: string; bytes: Uint8Array }[] = [];
    for (const table of tables) {
      for (const row of sql.exec(`SELECT * FROM "${table}"`).toArray()) {
        for (const v of Object.values(row)) {
          if (typeof v === "string") out.push({ table, bytes: utf8(v) });
          else if (v instanceof ArrayBuffer) out.push({ table, bytes: new Uint8Array(v) });
          else if (v !== null) out.push({ table, bytes: utf8(String(v)) });
        }
      }
    }
    return out;
  });
}

function contains(hay: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

describe("storage holds only ciphertext", () => {
  it("keeps no body, header value or content type in the clear, in the object or in D1", async () => {
    const dev = await newAccount();
    const other = await enrolDevice(dev);
    const { hook, secret } = await createHook(dev, { preset: "github" });
    const marker = "MARKER-7f3a-payload-text";
    const headerMarker = "HDRMARK-91c2";
    const body = JSON.stringify({ secretField: marker, n: 1 });
    const res = await fetchRelay(`/h/${hook.id}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-marker-type",
        "User-Agent": `agent-${headerMarker}`,
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": `delivery-${headerMarker}`,
        "X-Hub-Signature-256": `sha256=${toHex(await hmac("SHA-256", utf8(secret!), utf8(body)))}`,
      },
      body,
    });
    expect(res.status).toBe(200);

    const values = await everyStoredValue(dev.accountId);
    expect(values.length).toBeGreaterThan(0);
    const needles = [marker, headerMarker, "x-marker-type", toBase64(utf8(body)), toBase64(utf8(marker)).slice(0, 16)].map(utf8);
    for (const { table, bytes } of values) {
      for (const n of needles) expect(contains(bytes, n), `${table} holds ${new TextDecoder().decode(n)}`).toBe(false);
    }
    // Two envelopes, one per device, and nothing else holding content.
    const stats = await accountObject(dev.accountId).stats();
    expect(stats).toMatchObject({ events: 1, envelopes: 2 });

    // D1 never sees a payload either.
    for (const table of ["accounts", "devices", "hooks", "enrolments", "api_keys"]) {
      const { results } = await env.DB.prepare(`SELECT * FROM ${table}`).all();
      expect(JSON.stringify(results)).not.toContain(marker);
      expect(JSON.stringify(results)).not.toContain(headerMarker);
    }

    // And both devices open it.
    for (const d of [dev, other]) {
      const { sse } = await openStream(d);
      const opened = await openEvent(d, await nextHook(sse));
      expect(opened.text).toBe(body);
      expect(opened.headers["user-agent"]).toBe(`agent-${headerMarker}`);
      expect(opened.contentType).toBe("application/x-marker-type");
      await sse.cancel();
    }
  });

  it("deletes a device's envelopes once it acknowledges them", async () => {
    const dev = await newAccount();
    const other = await enrolDevice(dev);
    const { hook } = await createHook(dev, { preset: "unverified" });
    await deliver(hook.id, { a: 1 });
    await deliver(hook.id, { a: 2 });
    const stub = accountObject(dev.accountId);
    expect((await stub.stats()).envelopes).toBe(4);
    await signed(dev, "POST", "/v1/ack", { through: 2 });
    // The other device still needs its own; this one's are gone.
    expect(await stub.stats()).toMatchObject({ events: 2, envelopes: 2 });
    await signed(other, "POST", "/v1/ack", { through: 2 });
    expect(await stub.stats()).toMatchObject({ events: 0, envelopes: 0, usage: { events: 0, bytes: 0 } });
  });
});

describe("envelopes", () => {
  it("are sealed to each device's own key, with its kid, and signed by the relay for that device", async () => {
    const a = await newAccount();
    const b = await enrolDevice(a);
    const { hook } = await createHook(a, { preset: "unverified" });
    const id = await deliver(hook.id, { hello: "world" });
    const sa = await openStream(a);
    const sb = await openStream(b);
    const ea = await nextHook(sa.sse);
    const eb = await nextHook(sb.sse);
    expect(ea.id).toBe(id);
    expect(eb.id).toBe(id);
    expect(ea.sealed.kid).toBe(a.seal!.kid);
    expect(eb.sealed.kid).toBe(b.seal!.kid);
    expect(ea.sealed.enc).not.toBe(eb.sealed.enc);
    expect((await openEvent(a, ea)).text).toBe('{"hello":"world"}');
    expect((await openEvent(b, eb)).text).toBe('{"hello":"world"}');
    // a can't open b's envelope.
    await expect(openWith(a.seal!.privateKey, fromBase64(eb.sealed.enc)!, fromBase64(eb.sealed.ct)!, sealAad(eb.hookId, eb.seq, eb.id))).rejects.toThrow();
    // The signature covers the device: b's envelope doesn't verify as a's.
    await expect(openEvent({ ...a, seal: b.seal }, eb)).rejects.toThrow(/relay signature/);
    // …and the metadata: a changed `verified` or event type no longer verifies.
    await expect(openEvent(a, { ...ea, verified: true })).rejects.toThrow(/relay signature/);
    await expect(openEvent(a, { ...ea, eventType: "forged" })).rejects.toThrow(/relay signature/);
    await expect(openEvent(a, { ...ea, seq: ea.seq + 1 })).rejects.toThrow(/relay signature/);
    await sa.sse.cancel();
    await sb.sse.cancel();
  });

  it("reports an event to a device without a sealing key as a no_key gap, and seals to a key added later", async () => {
    const dev = await newAccount("old client", { seal: false });
    const { hook } = await createHook(dev, { preset: "unverified" });
    await deliver(hook.id, { n: 1 });
    expect((await accountObject(dev.accountId).stats()).envelopes).toBe(0);

    // The device adds a key (a client from before protocol 2 logging in again would).
    const seal = await newSealPair();
    const put = await signed(dev, "PUT", `/v1/devices/${dev.deviceId}/seal-key`, { sealKey: seal.text });
    expect(put.status).toBe(200);
    expect(await put.json()).toEqual({ kid: seal.kid });
    const withKey: TestDevice = { ...dev, seal };
    await deliver(hook.id, { n: 2 });

    const { sse } = await openStream(withKey);
    const ready = data<{ sealKid: string }>(await sse.nextEvent());
    expect(ready.sealKid).toBe(seal.kid);
    const gap = await sse.nextEvent();
    expect(gap?.event).toBe("gap");
    expect(data(gap)).toEqual({ from: 1, to: 1, reason: "no_key" });
    expect((await openEvent(withKey, await nextHook(sse))).text).toBe('{"n":2}');
    await sse.cancel();

    const devices = (await (await signed(dev, "GET", "/v1/devices")).json()) as { devices: { sealKid: string | null }[] };
    expect(devices.devices[0]!.sealKid).toBe(seal.kid);
  });

  it("refuses a malformed or low-order sealing key, and another device's key", async () => {
    const dev = await newAccount();
    const other = await enrolDevice(dev);
    const put = (who: TestDevice, target: string, sealKey: unknown) => signed(who, "PUT", `/v1/devices/${target}/seal-key`, { sealKey });
    expect((await put(dev, dev.deviceId, "not a key")).status).toBe(400);
    expect((await put(dev, dev.deviceId, toBase64Url(new Uint8Array(32)))).status).toBe(400);
    // A point of order 8 (from the X25519 low-order list): every seal to it would be readable.
    const lowOrder = new Uint8Array([
      0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c,
      0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
    ]);
    expect((await put(dev, dev.deviceId, toBase64Url(lowOrder))).status).toBe(400);
    // One device can't set another's key: it would be choosing who reads that device's events.
    const r = await put(dev, other.deviceId, (await newSealPair()).text);
    expect(r.status).toBe(403);
    expect(await r.json()).toMatchObject({ error: "forbidden" });
    // Account creation checks it too.
    const res = await fetchRelay("/v1/accounts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ deviceName: "x", publicKey: toBase64Url(crypto.getRandomValues(new Uint8Array(32))), sealKey: toBase64Url(new Uint8Array(32)) }),
    });
    expect(res.status).toBe(400);
  });
});

describe("protocol negotiation and probes", () => {
  it("refuses a stream that doesn't ask for protocol 2, saying which it serves", async () => {
    const dev = await newAccount();
    const res = await signed(dev, "GET", "/v1/stream", undefined, { headers: { Accept: "text/event-stream" } });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid", field: "X-00h-Protocol", protocols: [2] });
    const old = await signed(dev, "GET", "/v1/stream", undefined, { headers: { "X-00h-Protocol": "1" } });
    expect(old.status).toBe(400);
  });

  it("answers a probe with ready and closes, without replacing the live stream", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const live = await openStream(dev);
    await live.sse.nextEvent(); // ready
    const probe = await signed(dev, "GET", "/v1/stream?probe=1", undefined, { headers: { "X-00h-Protocol": "2" } });
    expect(probe.status).toBe(200);
    const text = await probe.text();
    expect(text).toContain("event: ready");
    expect(text).toContain(`"sealKid":"${dev.seal!.kid}"`);
    expect(text).toContain('event: closed\ndata: {"code":1000,"reason":"probe"}');
    // The live stream is still the device's stream: it gets the next event.
    await deliver(hook.id, { after: "probe" });
    expect((await openEvent(dev, await nextHook(live.sse))).text).toBe('{"after":"probe"}');
    await live.sse.cancel();
  });
});
