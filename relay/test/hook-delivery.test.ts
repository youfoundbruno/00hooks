// A hook's static response and its one-device delivery (PROTOCOL §3), renaming a device (§2), and
// the signed test event (`POST /v1/test/<hookId>`, §3).

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import type { AccountObject } from "../src/account-object.ts";
import { describe, expect, it } from "vitest";
import { hmac, toHex, utf8 } from "../src/encoding.ts";
import { PRESETS, verifyDelivery, type VerifyConfig } from "../src/presets.ts";
import { cannotSign, signSample } from "../src/test-event.ts";
import {
  BASE,
  accountObject,
  createHook,
  data,
  deliver,
  enrolDevice,
  fetchRelay,
  newAccount,
  openEvent,
  openStream,
  pairPhone,
  newNode,
  signed,
  type StreamedEvent,
  type TestDevice,
} from "./helpers.ts";

/** The next `hook` event, past `hook-change` notices (hooks made after a device joined are announced). */
async function nextHook(sse: { nextEvent(t?: number): Promise<{ event?: string; data?: string } | null> }, timeoutMs?: number) {
  for (;;) {
    const f = await sse.nextEvent(timeoutMs);
    if (f?.event !== "hook-change") return f;
  }
}

function withKey(token: string, method: string, path: string, body?: unknown) {
  return fetchRelay(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function newKey(dev: TestDevice, scopes: string[]): Promise<string> {
  const res = await signed(dev, "POST", "/v1/keys", { name: "ci", scopes });
  expect(res.status).toBe(201);
  return ((await res.json()) as { token: string }).token;
}

async function githubPost(hookId: string, secret: string, body: string, delivery = crypto.randomUUID()): Promise<Response> {
  const sig = `sha256=${toHex(await hmac("SHA-256", utf8(secret), utf8(body)))}`;
  return fetchRelay(`/h/${hookId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Hub-Signature-256": sig, "X-GitHub-Event": "push", "X-GitHub-Delivery": delivery },
    body,
  });
}

describe("a hook's static response", () => {
  it("answers accepted deliveries, duplicates and screen drops with it, and nothing else", async () => {
    const dev = await newAccount();
    const { hook, secret } = await createHook(dev, { preset: "github" });
    const response = { status: 202, contentType: "application/json", body: '{"ok":true}' };
    const set = await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { response });
    expect(set.status).toBe(200);
    expect(((await set.json()) as { response: unknown }).response).toEqual(response);

    const body = JSON.stringify({ n: 1 });
    const first = await githubPost(hook.id, secret!, body);
    expect(first.status).toBe(202);
    expect(first.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(first.headers.get("x-content-type-options")).toBe("nosniff");
    expect(first.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(await first.text()).toBe('{"ok":true}');
    // A provider's retry gets the same answer.
    const again = await githubPost(hook.id, secret!, body);
    expect(again.status).toBe(202);
    expect(await again.text()).toBe('{"ok":true}');
    // A forgery keeps its 401: the static response is only for accepted deliveries.
    const forged = await githubPost(hook.id, "not the secret at all", JSON.stringify({ n: 2 }));
    expect(forged.status).toBe(401);
    // A screen drop must look like a delivery, so it gets the static response too.
    const screen = { rules: [{ id: "all", verdict: "drop", conditions: [{ on: "size", op: "gt", bytes: 0 }] }], consent: { words: false } };
    expect((await signed(dev, "PUT", `/v1/hooks/${hook.id}/screen`, { screen })).status).toBe(200);
    const dropped = await githubPost(hook.id, secret!, JSON.stringify({ n: 3 }));
    expect(dropped.status).toBe(202);
    expect(await dropped.text()).toBe('{"ok":true}');

    // Cleared: back to the usual JSON.
    expect((await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { response: null })).status).toBe(200);
    const plain = await githubPost(hook.id, secret!, JSON.stringify({ n: 4 }));
    expect(plain.status).toBe(200);
    expect(await plain.json()).toEqual({ received: expect.stringMatching(/^evt_/) });
  });

  it("is bounded: 2xx with a body, text, JSON or XML only (never HTML), at most 4 KiB, valid JSON for JSON", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const bad: [unknown, string][] = [
      [{ status: 302, body: "x" }, "response.status"],
      [{ status: 500, body: "x" }, "response.status"],
      [{ status: 204 }, "response.status"],
      [{ contentType: "text/html", body: "<script>alert(1)</script>" }, "response.contentType"],
      [{ contentType: "image/svg+xml", body: "<svg/>" }, "response.contentType"],
      [{ body: "x".repeat(4097) }, "response.body"],
      [{ contentType: "application/json", body: "{not json" }, "response.body"],
      [{ body: "x", headers: { "Set-Cookie": "a=b" } }, "response"],
      ["ok", "response"],
    ];
    for (const [response, field] of bad) {
      const res = await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { response });
      expect(res.status, JSON.stringify(response)).toBe(400);
      expect(((await res.json()) as { field: string }).field).toBe(field);
    }
    // Defaults: 200, text/plain.
    const ok = await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { response: { body: "thanks" } });
    expect(((await ok.json()) as { response: unknown }).response).toEqual({ status: 200, contentType: "text/plain", body: "thanks" });
    const res = await fetchRelay(`/h/${hook.id}`, { method: "POST", body: "{}" });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(await res.text()).toBe("thanks");
  });

  it("can't be set on a Twilio hook, whose answer is TwiML", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "twilio", secret: "twilio auth token" });
    const res = await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { response: { body: "hi" } });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { field: string }).field).toBe("response");
  });
});

describe("delivering a hook to one device", () => {
  it("seals only to that device; the others pass the event by in silence, and it's gone once that device acknowledges", async () => {
    const laptop = await newAccount("laptop");
    const office = await enrolDevice(laptop, "office");
    const { hook } = await createHook(laptop, { preset: "unverified" });
    const set = await signed(laptop, "PATCH", `/v1/hooks/${hook.id}`, { deliverTo: office.deviceId });
    expect(set.status).toBe(200);
    expect(((await set.json()) as { deliverTo: string }).deliverTo).toBe(office.deviceId);

    const routed = await deliver(hook.id, { n: 1 });
    // Another hook of the account still goes to every device.
    const { hook: other } = await createHook(laptop, { preset: "unverified" });
    const everyone = await deliver(other.id, { n: 2 });

    const stats = await accountObject(laptop.accountId).stats();
    expect(stats.envelopes).toBe(3);

    // The laptop's stream skips the routed event without a gap, and gets the other one.
    const a = await openStream(laptop, 0);
    expect((await a.sse.nextEvent())?.event).toBe("ready");
    const first = await nextHook(a.sse);
    expect(first?.event).toBe("hook");
    expect(data<StreamedEvent>(first).id).toBe(everyone);
    await a.sse.cancel();

    // The office machine gets both, and can open the routed one.
    const b = await openStream(office, 0);
    expect((await b.sse.nextEvent())?.event).toBe("ready");
    const e1 = data<StreamedEvent>(await nextHook(b.sse));
    expect(e1.id).toBe(routed);
    expect((await openEvent(office, e1)).text).toBe('{"n":1}');
    const e2 = data<StreamedEvent>(await nextHook(b.sse));
    expect(e2.id).toBe(everyone);
    await b.sse.cancel();

    // Once the office machine acknowledges it, the routed event is deleted, whatever the laptop has.
    expect((await signed(office, "POST", "/v1/ack", { through: e1.seq })).status).toBe(200);
    const after = await accountObject(laptop.accountId).stats();
    expect(after.events).toBe(1);
    expect(after.usage.events).toBe(1);

    const audit = (await (await signed(laptop, "GET", "/v1/audit")).json()) as { entries: { kind: string; name: string }[] };
    expect(audit.entries.find((e) => e.kind === "hook.delivery")?.name).toBe(office.deviceId);
  });

  it("refuses a device that isn't an active node of the account with a sealing key", async () => {
    const dev = await newAccount();
    const stranger = await newAccount("stranger");
    const keyless = await enrolDevice(dev, "keyless", { seal: false });
    const node = await newNode("mac");
    const phone = await pairPhone(node);
    const { hook } = await createHook(dev, { preset: "unverified" });
    for (const target of [stranger.deviceId, keyless.deviceId, "dev_nope", 7]) {
      const res = await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { deliverTo: target });
      expect(res.status, String(target)).toBe(400);
      expect(((await res.json()) as { field: string }).field).toBe("deliverTo");
    }
    const { hook: nodeHook } = await createHook(node, { preset: "unverified" });
    const res = await signed(node, "PATCH", `/v1/hooks/${nodeHook.id}`, { deliverTo: phone.deviceId });
    expect(res.status).toBe(400);
  });

  it("goes back to every device when its device is revoked, and drops what was routed to it", async () => {
    const laptop = await newAccount("laptop");
    const office = await enrolDevice(laptop, "office");
    const { hook } = await createHook(laptop, { preset: "unverified" });
    await signed(laptop, "PATCH", `/v1/hooks/${hook.id}`, { deliverTo: office.deviceId });
    await deliver(hook.id, { n: 1 });
    expect((await signed(laptop, "DELETE", `/v1/devices/${office.deviceId}`)).status).toBe(204);
    // What only the office machine could read is gone with it.
    expect((await accountObject(laptop.accountId).stats()).events).toBe(0);
    // New deliveries aren't lost: the laptop gets them.
    const id = await deliver(hook.id, { n: 2 });
    const s = await openStream(laptop, 0);
    expect((await s.sse.nextEvent())?.event).toBe("ready");
    expect(data<StreamedEvent>(await nextHook(s.sse)).id).toBe(id);
    await s.sse.cancel();
  });

  it("keeps a held event reviewable by every device, and releases it to the hook's device only", async () => {
    const laptop = await newAccount("laptop");
    const office = await enrolDevice(laptop, "office");
    const { hook } = await createHook(laptop, { preset: "unverified" });
    await signed(laptop, "PATCH", `/v1/hooks/${hook.id}`, { deliverTo: office.deviceId });
    const screen = { rules: [{ id: "hold", verdict: "quarantine", conditions: [{ on: "size", op: "gt", bytes: 0 }] }], consent: { words: false } };
    await signed(laptop, "PUT", `/v1/hooks/${hook.id}/screen`, { screen });
    const id = await deliver(hook.id, { n: 1 });
    expect((await accountObject(laptop.accountId).stats()).held).toBe(1);
    const rel = await signed(laptop, "POST", `/v1/held/${id}/release`);
    expect(rel.status).toBe(200);
    const stats = await accountObject(laptop.accountId).stats();
    expect(stats.envelopes).toBe(1);
    const s = await openStream(laptop, 0);
    expect((await s.sse.nextEvent())?.event).toBe("ready");
    await expect(nextHook(s.sse, 300)).rejects.toThrow(/timed out/);
    await s.sse.cancel();
    const o = await openStream(office, 0);
    expect((await o.sse.nextEvent())?.event).toBe("ready");
    expect(data<StreamedEvent>(await nextHook(o.sse)).id).toBe(id);
    await o.sse.cancel();
  });
});

describe("schema 5", () => {
  it("adds the route columns to an object written before them, keeping its events", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    await deliver(hook.id, { n: 1 });
    const after = await runInDurableObject(accountObject(dev.accountId), (o: AccountObject, state) => {
      const sql = state.storage.sql;
      sql.exec("DROP INDEX IF EXISTS events_route");
      sql.exec("ALTER TABLE events DROP COLUMN route");
      sql.exec("ALTER TABLE held_events DROP COLUMN route");
      sql.exec("UPDATE meta SET value = 4 WHERE key = 'schema'");
      (o as unknown as { migrate(): void }).migrate();
      return {
        schema: sql.exec<{ value: number }>("SELECT value FROM meta WHERE key = 'schema'").one().value,
        events: sql.exec("SELECT route FROM events").toArray(),
        held: sql.exec("SELECT route FROM held_events").toArray(),
        index: sql.exec("SELECT name FROM sqlite_master WHERE name = 'events_route'").toArray().length,
      };
    });
    expect(after).toEqual({ schema: 5, events: [{ route: null }], held: [], index: 1 });
  });
});

describe("renaming a device", () => {
  it("renames by a device or a devices:write key, audits it, and refuses what isn't the account's", async () => {
    const laptop = await newAccount("laptop");
    const office = await enrolDevice(laptop, "office");
    const res = await signed(laptop, "PATCH", `/v1/devices/${office.deviceId}`, { name: "  the Mac in the office " });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { device: unknown }).device).toMatchObject({ id: office.deviceId, name: "the Mac in the office", current: false, kind: "device" });
    const listed = (await (await signed(laptop, "GET", "/v1/devices")).json()) as { devices: { id: string; name: string }[] };
    expect(listed.devices.find((d) => d.id === office.deviceId)?.name).toBe("the Mac in the office");

    const token = await newKey(laptop, ["devices:write"]);
    expect((await withKey(token, "PATCH", `/v1/devices/${laptop.deviceId}`, { name: "laptop 2" })).status).toBe(200);
    const readOnly = await newKey(laptop, ["hooks:read"]);
    expect((await withKey(readOnly, "PATCH", `/v1/devices/${laptop.deviceId}`, { name: "x" })).status).toBe(403);

    for (const name of ["", " ", "x".repeat(101), "bad\u0007name", 3]) {
      const r = await signed(laptop, "PATCH", `/v1/devices/${office.deviceId}`, { name });
      expect(r.status).toBe(400);
    }
    const stranger = await newAccount("stranger");
    expect((await signed(stranger, "PATCH", `/v1/devices/${office.deviceId}`, { name: "mine" })).status).toBe(404);
    await signed(laptop, "DELETE", `/v1/devices/${office.deviceId}`);
    expect((await signed(laptop, "PATCH", `/v1/devices/${office.deviceId}`, { name: "back" })).status).toBe(404);

    const audit = (await (await signed(laptop, "GET", "/v1/audit")).json()) as { entries: { kind: string; subject: string; name: string }[] };
    expect(audit.entries.filter((e) => e.kind === "device.renamed").map((e) => e.name)).toEqual(["laptop 2", "the Mac in the office"]);
  });

  it("lets a node rename its phone, and refuses a phone", async () => {
    const node = await newNode("mac");
    const phone = await pairPhone(node);
    const res = await signed(node, "PATCH", `/v1/devices/${phone.deviceId}`, { name: "my phone" });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { device: { kind: string } }).device.kind).toBe("phone");
    expect((await signed(phone, "PATCH", `/v1/devices/${phone.deviceId}`, { name: "me" })).status).toBe(403);
  });
});

describe("the test event", () => {
  /** A config per preset, as a hook of it would hold (with a secret for the ones that take one). */
  const configs: Record<string, { verify: Record<string, unknown>; signs: boolean }> = {
    github: { verify: { preset: "github" }, signs: true },
    "standard-webhooks": { verify: { preset: "standard-webhooks" }, signs: true },
    "standard-webhooks-ed25519": { verify: { preset: "standard-webhooks-ed25519", publicKey: `whpk_${btoa(String.fromCharCode(...new Uint8Array(32).fill(7)))}` }, signs: false },
    stripe: { verify: { preset: "stripe", secret: "whsec_stripe_test_secret" }, signs: true },
    slack: { verify: { preset: "slack", secret: "slack signing secret" }, signs: true },
    linear: { verify: { preset: "linear", secret: "linear signing secret" }, signs: true },
    shopify: { verify: { preset: "shopify", secret: "shopify signing secret" }, signs: true },
    twilio: { verify: { preset: "twilio", secret: "twilio auth token" }, signs: true },
    meta: { verify: { preset: "meta", secret: "meta app secret" }, signs: true },
    hmac: { verify: { preset: "hmac", header: "X-Sig", algorithm: "sha1", encoding: "base64", prefix: "sha1=" }, signs: true },
    token: { verify: { preset: "token", header: "X-Token" }, signs: true },
    unverified: { verify: { preset: "unverified" }, signs: true },
    calendly: { verify: { preset: "calendly" }, signs: true },
    typeform: { verify: { preset: "typeform" }, signs: true },
    paddle: { verify: { preset: "paddle", secret: "pdl_ntfset_test_secret" }, signs: true },
    twitch: { verify: { preset: "twitch" }, signs: true },
    zoom: { verify: { preset: "zoom", secret: "zoom secret token" }, signs: true },
    pagerduty: { verify: { preset: "pagerduty", secret: "pagerduty secret" }, signs: true },
  };

  it("covers every preset in the table (a new preset must say whether a test can be signed for it)", () => {
    expect(Object.keys(configs).sort()).toEqual([...PRESETS].sort());
  });

  it("signs a sample each preset's own verifier accepts", async () => {
    for (const p of PRESETS) {
      const { verify, signs } = configs[p]!;
      const config = { ...verify } as unknown as VerifyConfig & { secret?: string };
      delete config.secret;
      if (!signs) {
        expect(cannotSign(config)).not.toBeNull();
        continue;
      }
      const secret = p === "standard-webhooks" ? "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw" : "a test secret value";
      const now = Date.now();
      const url = `${BASE}/h/hk_0123456789abcdefghjkmnpqrs`;
      const s = await signSample(config, p === "unverified" ? null : (verify.secret as string | undefined) ?? secret, url, now);
      const secrets = p === "unverified" ? [] : [(verify.secret as string | undefined) ?? secret];
      const v = await verifyDelivery(config, secrets, { body: s.body, headers: s.headers, now, url });
      expect(v.ok, p).toBe(true);
      expect(v.verified, p).toBe(p !== "unverified");
    }
  });

  it("goes through the hook's own path, verified and marked as a test", async () => {
    const dev = await newAccount();
    for (const p of PRESETS) {
      const { verify, signs } = configs[p]!;
      const { hook } = await createHook(dev, verify, `test ${p}`);
      const res = await signed(dev, "POST", `/v1/test/${hook.id}`);
      if (!signs) {
        expect(res.status, p).toBe(409);
        continue;
      }
      expect(res.status, p).toBe(200);
      const out = (await res.json()) as { status: number; answer: { received?: string } | null; eventType: string };
      expect(out.status, p).toBe(200);
      expect(out.eventType).toBe("00hooks.test");
      if (p !== "twilio") expect(out.answer?.received, p).toMatch(/^evt_/);
    }
    const s = await openStream(dev, 0);
    expect((await s.sse.nextEvent())?.event).toBe("ready");
    const seen: StreamedEvent[] = [];
    for (let i = 0; i < PRESETS.length - 1; i++) seen.push(data<StreamedEvent>(await nextHook(s.sse)));
    await s.sse.cancel();
    for (const ev of seen) {
      expect(ev.eventType).toBe("00hooks.test");
      expect(ev.verified).toBe(ev.preset !== "unverified");
      const content = await openEvent(dev, ev);
      expect(content.text).toMatch(/00hooks/);
    }
  });

  it("can't be claimed by a sender: a delivery typed 00hooks.test has no type", async () => {
    const dev = await newAccount();
    const { hook, secret } = await createHook(dev, { preset: "github" });
    const body = JSON.stringify({ n: 1 });
    const sig = `sha256=${toHex(await hmac("SHA-256", utf8(secret!), utf8(body)))}`;
    const res = await fetchRelay(`/h/${hook.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Hub-Signature-256": sig, "X-GitHub-Event": "00hooks.test", "X-GitHub-Delivery": "d1" },
      body,
    });
    expect(res.status).toBe(200);
    const s = await openStream(dev, 0);
    expect((await s.sse.nextEvent())?.event).toBe("ready");
    expect(data<StreamedEvent>(await nextHook(s.sse)).eventType).toBeNull();
    await s.sse.cancel();
  });

  it("refuses a strict hook and needs a device or hooks:secrets", async () => {
    const dev = await newAccount();
    const { hook: strict } = await createHook(dev, { preset: "github", strict: true });
    const r = await signed(dev, "POST", `/v1/test/${strict.id}`);
    expect(r.status).toBe(409);
    expect(((await r.json()) as { message: string }).message).toMatch(/strict/);

    const { hook } = await createHook(dev, { preset: "github" });
    const writer = await newKey(dev, ["hooks:write"]);
    expect((await withKey(writer, "POST", `/v1/test/${hook.id}`)).status).toBe(403);
    const secrets = await newKey(dev, ["hooks:secrets"]);
    expect((await withKey(secrets, "POST", `/v1/test/${hook.id}`)).status).toBe(200);
    const stranger = await newAccount("stranger");
    expect((await signed(stranger, "POST", `/v1/test/${hook.id}`)).status).toBe(404);
    // Nothing secret comes back.
    const { secret } = await createHook(dev, { preset: "github" }, "another");
    const body = await (await signed(dev, "POST", `/v1/test/${hook.id}`)).text();
    expect(body).not.toContain(secret!);
    expect(env.DB).toBeDefined();
  });
});
