// Phone push (PROTOCOL §10.7): `POST /v1/phone/push` through the real Worker and PhoneObject, with
// APNs mocked at the global fetch (nothing leaves the test). The APNs keys are generated here, per
// test: no key file is committed.

import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { APNS_HOSTS, TOKEN_REUSE_MS, apnsConfig, providerToken, resetApnsCache } from "../src/apns.ts";
import { fromBase64, toBase64, toBase64Url, utf8 } from "../src/encoding.ts";
import type { PhoneObject } from "../src/phone-object.ts";
import { PUSH_KINDS, PUSH_TEXTS, type PushKind } from "../src/phone-push.ts";
import {
  enrolDevice,
  fetchRelay,
  newNode,
  newSealPair,
  openPhoneSocket,
  pairPhone,
  phoneObject,
  signed,
  type TestDevice,
  type TestNode,
  type TestPhone,
} from "./helpers.ts";

// ── an APNs key and a mock of Apple's service ───────────────────────────────

interface TestApnsKey {
  pem: string;
  publicKey: CryptoKey;
}

async function newApnsKey(): Promise<TestApnsKey> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  const lines = toBase64(der).match(/.{1,64}/g)!.join("\n");
  return { pem: `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----\n`, publicKey: pair.publicKey };
}

const KEY_ID = "ABC123DEFG";
const TEAM_ID = "TEAM456XYZ";
const TOPIC = "dev.example.phone";
const APNS_VARS = ["APNS_KEY", "APNS_KEY_ID", "APNS_TEAM_ID", "APNS_TOPIC", "APNS_ENVIRONMENT", "PHONE_PUSH_PER_HOUR"] as const;
type Vars = Partial<Record<(typeof APNS_VARS)[number], string>>;
const mutableEnv = env as unknown as Record<string, string | undefined>;

/** Sets the relay's APNs secrets for this test (the Worker and the PhoneObject read the same env). */
async function configure(vars: Vars & { environment?: string } = {}): Promise<TestApnsKey> {
  const key = await newApnsKey();
  const { environment, ...rest } = vars;
  Object.assign(mutableEnv, { APNS_KEY: key.pem, APNS_KEY_ID: KEY_ID, APNS_TEAM_ID: TEAM_ID, APNS_TOPIC: TOPIC, ...rest });
  if (environment !== undefined) mutableEnv.APNS_ENVIRONMENT = environment;
  return key;
}

interface ApnsCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

type ApnsReply = { status: number; reason?: string } | "network";

let fetchSpy: MockInstance<typeof fetch> | null = null;

/** Replaces the global fetch: every call is recorded and answered from `replies` (then 200). */
function mockApns(replies: ApnsReply[] = []): ApnsCall[] {
  const calls: ApnsCall[] = [];
  fetchSpy?.mockRestore();
  fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    const headers: Record<string, string> = {};
    req.headers.forEach((v, k) => (headers[k] = v));
    calls.push({ url: req.url, method: req.method, headers, body: await req.text() });
    const r = replies.shift() ?? { status: 200 };
    if (r === "network") throw new TypeError("network down");
    return r.status === 200
      ? new Response(null, { status: 200, headers: { "apns-id": crypto.randomUUID() } })
      : new Response(JSON.stringify({ reason: r.reason ?? "Whatever" }), { status: r.status, headers: { "content-type": "application/json" } });
  });
  return calls;
}

afterEach(() => {
  for (const k of APNS_VARS) delete mutableEnv[k];
  fetchSpy?.mockRestore();
  fetchSpy = null;
  resetApnsCache();
  vi.restoreAllMocks();
});

// ── requests ────────────────────────────────────────────────────────────────

const TOKEN = "a1b2c3d4".repeat(8);
const REF = "AAAAAAAAAAAAAAAAAAAAAA";

function pushBody(phone: { deviceId: string }, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { device: phone.deviceId, token: TOKEN, kind: "approval", ref: REF, ...extra };
}

async function push(node: TestDevice, body: unknown): Promise<{ status: number; body: Record<string, unknown>; headers: Headers }> {
  const res = await signed(node, "POST", "/v1/phone/push", body);
  return { status: res.status, body: (await res.json()) as Record<string, unknown>, headers: res.headers };
}

async function pushRows(accountId: string): Promise<{ device: string; kind: string; at: number }[]> {
  return runInDurableObject(phoneObject(accountId), (_o: PhoneObject, state) =>
    state.storage.sql.exec<{ device: string; kind: string; at: number }>("SELECT device, kind, at FROM pushes ORDER BY at").toArray(),
  );
}

function preview(): { at: number; enc: string; ct: string; sig: string } {
  return {
    at: 1_760_000_000_000,
    enc: toBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    ct: toBase64(crypto.getRandomValues(new Uint8Array(120))),
    sig: toBase64Url(crypto.getRandomValues(new Uint8Array(64))),
  };
}

/** Decodes a bearer JWT and checks its ES256 signature with `publicKey`. */
async function readJwt(authorization: string, publicKey: CryptoKey): Promise<{ header: Record<string, unknown>; claims: Record<string, unknown>; jwt: string }> {
  expect(authorization).toMatch(/^bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  const jwt = authorization.slice("bearer ".length);
  const [h, c, s] = jwt.split(".") as [string, string, string];
  const sig = fromBase64(s)!;
  expect(sig.byteLength).toBe(64);
  expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, sig, utf8(`${h}.${c}`))).toBe(true);
  const dec = (x: string) => JSON.parse(new TextDecoder().decode(fromBase64(x)!)) as Record<string, unknown>;
  return { header: dec(h), claims: dec(c), jwt };
}

async function nodeWithPhone(): Promise<{ node: TestNode; phone: TestPhone }> {
  const node = await newNode();
  return { node, phone: await pairPhone(node) };
}

// ── tests ───────────────────────────────────────────────────────────────────

describe("/v1/info push", () => {
  /** The push object for iOS alone (Android isn't configured in these tests). */
  const ios = (available: boolean, environment: string | null) => ({
    available,
    environment,
    platforms: { ios: { available, environment }, android: { available: false } },
  });
  const info = async () => ((await (await fetchRelay("/v1/info")).json()) as { phone: { protocol: number; push: unknown } }).phone;

  it("says push is unavailable until the key is set, and which environment once it is", async () => {
    expect(await info()).toEqual({ protocol: 1, push: ios(false, null) });
    await configure();
    expect(await info()).toEqual({ protocol: 1, push: ios(true, "production") });
    resetApnsCache();
    await configure({ environment: "sandbox" });
    expect((await info()).push).toEqual(ios(true, "sandbox"));
  });

  it("is unavailable with any setting missing or malformed, or a key that doesn't import", async () => {
    await configure();
    const good = { ...mutableEnv };
    const cases: Vars[] = [
      { APNS_KEY: "" },
      { APNS_KEY_ID: "" },
      { APNS_TEAM_ID: "" },
      { APNS_TOPIC: "" },
      { APNS_KEY_ID: "SHORT" },
      { APNS_TEAM_ID: "TOO-LONG-TEAM" },
      { APNS_ENVIRONMENT: "staging" },
      { APNS_KEY: "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----" },
    ];
    for (const c of cases) {
      for (const k of APNS_VARS) mutableEnv[k] = good[k];
      Object.assign(mutableEnv, c);
      expect((await info()).push, JSON.stringify(c).slice(0, 60)).toEqual(ios(false, null));
    }
  });

  it("takes the key with \\n escapes and surrounding whitespace, as a secret is often pasted", async () => {
    const key = await configure();
    mutableEnv.APNS_KEY = `  \n${key.pem.replace(/\n/g, "\\n")}\n  `;
    expect((await info()).push).toEqual(ios(true, "production"));
  });
});

describe("POST /v1/phone/push", () => {
  it("sends the fixed, opaque payload with the APNs headers and a signed provider token", async () => {
    const key = await configure();
    const { node, phone } = await nodeWithPhone();
    const calls = mockApns();
    const p = preview();
    const before = Math.floor(Date.now() / 1000);
    const res = await push(node, pushBody(phone, { preview: p, environment: "production" }));
    const after = Math.floor(Date.now() / 1000);
    expect(res).toMatchObject({ status: 200, body: { sent: true } });

    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    expect(call.method).toBe("POST");
    expect(call.url).toBe(`${APNS_HOSTS.production}/3/device/${TOKEN}`);
    expect(call.url).toBe(`https://api.push.apple.com/3/device/${TOKEN}`);
    expect(Object.keys(call.headers).sort()).toEqual(
      ["apns-collapse-id", "apns-expiration", "apns-priority", "apns-push-type", "apns-topic", "authorization", "content-type"].sort(),
    );
    expect(call.headers).toMatchObject({
      "apns-topic": TOPIC,
      "apns-push-type": "alert",
      "apns-priority": "10",
      "apns-collapse-id": "approval",
      "content-type": "application/json",
    });
    const expiration = Number(call.headers["apns-expiration"]);
    expect(expiration).toBeGreaterThanOrEqual(before + 86_400);
    expect(expiration).toBeLessThanOrEqual(after + 86_400);

    // Exactly the contract's payload: the preview verbatim, nothing else from the request.
    expect(JSON.parse(call.body)).toEqual({
      aps: { alert: { title: "An agent needs you", body: "Approval needed." }, sound: "default", category: "APPROVAL", "mutable-content": 1, "thread-id": "approval" },
      zn: { v: 1, kind: "approval", ref: REF, p },
    });
    for (const secret of [TOKEN, phone.deviceId, node.deviceId, node.accountId, "production"]) expect(call.body).not.toContain(secret);

    const { header, claims } = await readJwt(call.headers.authorization!, key.publicKey);
    expect(header).toEqual({ alg: "ES256", kid: KEY_ID });
    expect(claims).toEqual({ iss: TEAM_ID, iat: expect.any(Number) });
    expect(claims.iat as number).toBeGreaterThanOrEqual(before);
    expect(claims.iat as number).toBeLessThanOrEqual(after);

    // The relay keeps the phone, the kind and the time: never the token or the preview.
    const rows = await pushRows(node.accountId);
    expect(rows).toEqual([{ device: phone.deviceId, kind: "approval", at: expect.any(Number) }]);
    const all = await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) =>
      JSON.stringify(
        state.storage.sql
          .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_cf%' AND name NOT LIKE 'sqlite%'")
          .toArray()
          .map((t) => state.storage.sql.exec(`SELECT * FROM "${t.name}"`).toArray()),
      ),
    );
    expect(all).not.toContain(TOKEN);
    expect(all).not.toContain(p.ct);
    const d1 = JSON.stringify((await env.DB.prepare("SELECT * FROM devices").all()).results);
    expect(d1).not.toContain(TOKEN);
  });

  it("sends each kind's fixed texts and leaves out the preview when none is given", async () => {
    await configure();
    const { node, phone } = await nodeWithPhone();
    const calls = mockApns();
    for (const kind of PUSH_KINDS) {
      expect((await push(node, pushBody(phone, { kind }))).body).toEqual({ sent: true });
    }
    expect(calls.map((c) => c.headers["apns-collapse-id"])).toEqual([...PUSH_KINDS]);
    calls.forEach((c, i) => {
      const kind = PUSH_KINDS[i]!;
      const t = PUSH_TEXTS[kind];
      expect(JSON.parse(c.body)).toEqual({
        aps: { alert: { title: t.title, body: t.body }, sound: "default", category: t.category, "mutable-content": 1, "thread-id": kind },
        zn: { v: 1, kind, ref: REF },
      });
    });
    expect(Object.fromEntries(PUSH_KINDS.map((k) => [k, [PUSH_TEXTS[k].title, PUSH_TEXTS[k].body, PUSH_TEXTS[k].category]]))).toEqual({
      approval: ["An agent needs you", "Approval needed.", "APPROVAL"],
      ask: ["An agent needs you", "It asked you something.", "ASK"],
      finished: ["An agent finished", "Open the app to see what it did.", "FINISHED"],
      handoff: ["Continue on your phone", "A conversation was handed to this phone.", "HANDOFF"],
      reconnect: ["Your Mac is back online", "Open the app to reconnect.", "RECONNECT"],
      task: ["Something needs you", "An agent left you a task.", "TASK"],
      done: ["Done", "A task from a meeting is done.", "DONE"],
      drive: ["Your Mac needs you", "Open 00next on your Mac to decide.", "DRIVE"],
    });
  });

  it("goes to the sandbox host when APNS_ENVIRONMENT says so, and answers `environment` on a mismatch", async () => {
    await configure({ environment: "sandbox" });
    const { node, phone } = await nodeWithPhone();
    const calls = mockApns();
    expect((await push(node, pushBody(phone, { environment: "production" }))).body).toEqual({ sent: false, reason: "environment" });
    expect(calls).toHaveLength(0);
    expect(await pushRows(node.accountId)).toEqual([]);
    expect((await push(node, pushBody(phone, { environment: "sandbox" }))).body).toEqual({ sent: true });
    expect(calls.map((c) => c.url)).toEqual([`https://api.sandbox.push.apple.com/3/device/${TOKEN}`]);
    // Without `environment`, it isn't checked.
    expect((await push(node, pushBody(phone, { kind: "ask" }))).body).toEqual({ sent: true });
    expect(calls).toHaveLength(2);
  });

  it("is a clean no-op when push isn't configured, after the caller and the body are checked", async () => {
    const { node, phone } = await nodeWithPhone();
    const calls = mockApns();
    expect(await push(node, pushBody(phone))).toMatchObject({ status: 200, body: { sent: false, reason: "unavailable" } });
    // The shape and the phone are still checked first.
    expect(await push(node, pushBody(phone, { kind: "shout" }))).toMatchObject({ status: 400, body: { error: "invalid", field: "kind" } });
    const other = await nodeWithPhone();
    expect((await push(node, pushBody(other.phone))).status).toBe(403);
    expect(calls).toHaveLength(0);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(await pushRows(node.accountId)).toEqual([]);
  });

  it("refuses a malformed body with the field, and sends nothing", async () => {
    await configure();
    const { node, phone } = await nodeWithPhone();
    const calls = mockApns();
    const p = preview();
    const cases: [Record<string, unknown>, string][] = [
      [{ device: "phone" }, "device"],
      [{ device: undefined }, "device"],
      [{ token: TOKEN.toUpperCase() }, "token"],
      [{ token: TOKEN.slice(1) }, "token"],
      [{ token: "ab".repeat(15) }, "token"],
      [{ token: "ab".repeat(201) }, "token"],
      [{ token: undefined }, "token"],
      [{ environment: "development" }, "environment"],
      [{ kind: "message" }, "kind"],
      [{ kind: undefined }, "kind"],
      [{ ref: REF.slice(1) }, "ref"],
      [{ ref: `${REF.slice(1)}=` }, "ref"],
      [{ ref: undefined }, "ref"],
      [{ text: "hello" }, "text"],
      [{ preview: null }, "preview"],
      [{ preview: [p] }, "preview"],
      [{ preview: { ...p, extra: 1 } }, "preview"],
      [{ preview: { at: p.at, enc: p.enc, ct: p.ct } }, "preview"],
      [{ preview: { ...p, at: 1.5 } }, "preview"],
      [{ preview: { ...p, at: "now" } }, "preview"],
      [{ preview: { ...p, enc: p.enc.slice(1) } }, "preview"],
      [{ preview: { ...p, ct: p.ct.replace(/=+$/, "") + "x" } }, "preview"],
      [{ preview: { ...p, ct: "not base64!" } }, "preview"],
      [{ preview: { ...p, ct: "A".repeat(1404) } }, "preview"],
      [{ preview: { ...p, sig: p.sig.slice(2) } }, "preview"],
    ];
    for (const [extra, field] of cases) {
      const body = pushBody(phone, extra);
      for (const k of Object.keys(body)) if (body[k] === undefined) delete body[k];
      const res = await push(node, body);
      expect(res.status, JSON.stringify(extra).slice(0, 80)).toBe(400);
      expect(res.body).toMatchObject({ error: "invalid", field });
    }
    expect((await push(node, [pushBody(phone)])).body).toMatchObject({ error: "invalid", field: "body" });
    // The largest preview is taken, verbatim.
    const big = { ...p, ct: "A".repeat(1400) };
    expect((await push(node, pushBody(phone, { preview: big }))).body).toEqual({ sent: true });
    expect(calls).toHaveLength(1);
    expect((JSON.parse(calls[0]!.body) as { zn: { p: unknown } }).zn.p).toEqual(big);
  });

  it("answers 403 for a revoked, a pending, another node's and another account's phone, and sends nothing", async () => {
    await configure();
    const node = await newNode();
    const revoked = await pairPhone(node, { name: "old phone" });
    const pending = await pairPhone(node, { confirm: false, name: "pending" });
    const sibling = { ...(await enrolDevice(node, "desktop")), phoneSeal: await newSealPair() };
    const siblings = await pairPhone(sibling, { name: "the desktop's phone" });
    const foreign = await nodeWithPhone();
    const calls = mockApns();

    // A sent push is counted; revoking the phone drops its counters.
    expect((await push(node, pushBody(revoked))).body).toEqual({ sent: true });
    expect((await pushRows(node.accountId)).map((r) => r.device)).toEqual([revoked.deviceId]);
    expect((await signed(node, "DELETE", `/v1/devices/${revoked.deviceId}`)).status).toBe(204);
    expect(await pushRows(node.accountId)).toEqual([]);

    for (const target of [revoked, pending, siblings, foreign.phone, { deviceId: node.deviceId }, { deviceId: `dev_${"0".repeat(26)}` }]) {
      const res = await push(node, pushBody(target, { kind: "ask" }));
      expect(res.status, target.deviceId).toBe(403);
      expect(res.body).toEqual({ error: "forbidden", message: "That phone isn't paired with this device." });
    }
    // The other node's phone is its own to push to.
    expect((await push(sibling, pushBody(siblings))).body).toEqual({ sent: true });
    expect(calls).toHaveLength(2);
  });

  it("answers 403 to a phone and to an API key", async () => {
    await configure();
    const { node, phone } = await nodeWithPhone();
    const calls = mockApns();
    const asPhone = await push(phone, pushBody(phone));
    expect(asPhone.status).toBe(403);
    expect(asPhone.body).toMatchObject({ error: "forbidden" });
    const key = (await (await signed(node, "POST", "/v1/keys", { name: "ci", scopes: ["devices:write"] })).json()) as { token: string };
    const asKey = await fetchRelay("/v1/phone/push", {
      method: "POST",
      headers: { Authorization: `Bearer ${key.token}`, "Content-Type": "application/json" },
      body: JSON.stringify(pushBody(phone)),
    });
    expect(asKey.status).toBe(403);
    expect(calls).toHaveLength(0);
  });

  it("answers `online` and sends nothing while the phone's socket is open", async () => {
    await configure();
    const { node, phone } = await nodeWithPhone();
    const calls = mockApns();
    const sock = await openPhoneSocket(phone);
    await sock.hello(0);
    expect(await push(node, pushBody(phone))).toMatchObject({ status: 200, body: { sent: false, reason: "online" } });
    expect(calls).toHaveLength(0);
    expect(await pushRows(node.accountId)).toEqual([]);
    sock.close();
    await sock.closed;
  });
});

describe("push limits", () => {
  it("allows one push per phone and kind a minute, with Retry-After", async () => {
    await configure();
    const { node, phone } = await nodeWithPhone();
    const calls = mockApns();
    expect((await push(node, pushBody(phone))).body).toEqual({ sent: true });
    const again = await push(node, pushBody(phone));
    expect(again.status).toBe(429);
    expect(again.body).toMatchObject({ error: "rate_limited", retryAfter: expect.any(Number) });
    const wait = again.body.retryAfter as number;
    expect(wait).toBeGreaterThanOrEqual(59);
    expect(wait).toBeLessThanOrEqual(60);
    expect(again.headers.get("Retry-After")).toBe(String(wait));
    // Another kind isn't held back; another phone neither.
    expect((await push(node, pushBody(phone, { kind: "ask" }))).body).toEqual({ sent: true });
    const second = await pairPhone(node, { name: "iPad" });
    expect((await push(node, pushBody(second))).body).toEqual({ sent: true });
    expect(calls).toHaveLength(3);

    // A minute later the kind may go again.
    await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) => {
      state.storage.sql.exec("UPDATE pushes SET at = at - 61000 WHERE device = ?", phone.deviceId);
    });
    expect((await push(node, pushBody(phone))).body).toEqual({ sent: true });
  });

  it("allows 30 pushes per phone in a rolling hour, or PHONE_PUSH_PER_HOUR", async () => {
    await configure();
    const { node, phone } = await nodeWithPhone();
    const calls = mockApns();
    // 30 pushes of other kinds in the last hour, the oldest 59 minutes ago.
    const now = Date.now();
    await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) => {
      for (let i = 0; i < 30; i++) state.storage.sql.exec("INSERT INTO pushes (device, kind, at) VALUES (?, 'ask', ?)", phone.deviceId, now - 59 * 60_000 + i * 60_000);
    });
    const over = await push(node, pushBody(phone, { kind: "finished" }));
    expect(over.status).toBe(429);
    const wait = over.body.retryAfter as number;
    expect(wait).toBeGreaterThanOrEqual(55);
    expect(wait).toBeLessThanOrEqual(60);
    expect(over.headers.get("Retry-After")).toBe(String(wait));
    expect(calls).toHaveLength(0);

    // Once the oldest leaves the window, one more goes.
    await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) => {
      state.storage.sql.exec("UPDATE pushes SET at = at - 120000 WHERE device = ? AND at = (SELECT min(at) FROM pushes WHERE device = ?)", phone.deviceId, phone.deviceId);
    });
    expect((await push(node, pushBody(phone, { kind: "finished" }))).body).toEqual({ sent: true });
    expect((await push(node, pushBody(phone, { kind: "handoff" }))).status).toBe(429);

    // The operator's cap.
    mutableEnv.PHONE_PUSH_PER_HOUR = "2";
    const other = await nodeWithPhone();
    expect((await push(other.node, pushBody(other.phone, { kind: "approval" }))).body).toEqual({ sent: true });
    expect((await push(other.node, pushBody(other.phone, { kind: "ask" }))).body).toEqual({ sent: true });
    const capped = await push(other.node, pushBody(other.phone, { kind: "reconnect" }));
    expect(capped.status).toBe(429);
    expect(capped.body.retryAfter as number).toBeGreaterThan(3500);
  });

  it("counts what is attempted, not what is answered without sending; the alarm prunes old counts", async () => {
    await configure();
    const { node, phone } = await nodeWithPhone();
    mockApns([{ status: 500, reason: "InternalServerError" }]);
    expect((await push(node, pushBody(phone))).status).toBe(502);
    // The failed attempt counts.
    expect((await push(node, pushBody(phone))).status).toBe(429);
    expect(await pushRows(node.accountId)).toHaveLength(1);
    // Answers that send nothing don't.
    expect((await push(node, pushBody(phone, { kind: "ask", environment: "sandbox" }))).body).toEqual({ sent: false, reason: "environment" });
    expect(await pushRows(node.accountId)).toHaveLength(1);

    // Past the hour, the alarm deletes the count.
    await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) => {
      state.storage.sql.exec("UPDATE pushes SET at = at - 3601000");
    });
    expect(await runDurableObjectAlarm(phoneObject(node.accountId))).toBe(true);
    expect(await pushRows(node.accountId)).toEqual([]);
  });
});

describe("APNs answers", () => {
  it("maps 410 and the token reasons to `unregistered`", async () => {
    await configure();
    const { node, phone } = await nodeWithPhone();
    const calls = mockApns([
      { status: 410, reason: "Unregistered" },
      { status: 400, reason: "BadDeviceToken" },
      { status: 400, reason: "DeviceTokenNotForTopic" },
      { status: 400, reason: "Unregistered" },
    ]);
    const kinds: PushKind[] = ["approval", "ask", "finished", "handoff"];
    for (const kind of kinds) expect(await push(node, pushBody(phone, { kind }))).toMatchObject({ status: 200, body: { sent: false, reason: "unregistered" } });
    expect(calls).toHaveLength(4);
  });

  it("maps other failures to 502 push_failed and APNs' 429 to rate_limited, and never logs the token", async () => {
    await configure();
    const { node, phone } = await nodeWithPhone();
    const logs: unknown[][] = [];
    for (const level of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => void logs.push(args));
    }
    mockApns([{ status: 400, reason: "PayloadTooLarge" }, { status: 500 }, "network", { status: 429, reason: "TooManyRequests" }]);
    const kinds: PushKind[] = ["approval", "ask", "finished"];
    for (const kind of kinds) {
      const r = await push(node, pushBody(phone, { kind }));
      expect(r.status).toBe(502);
      expect(r.body).toEqual({ error: "push_failed", message: expect.any(String) });
    }
    const limited = await push(node, pushBody(phone, { kind: "handoff" }));
    expect(limited.status).toBe(429);
    expect(limited.body).toMatchObject({ error: "rate_limited", retryAfter: 60 });
    expect(limited.headers.get("Retry-After")).toBe("60");
    const logged = JSON.stringify(logs);
    expect(logged).not.toContain(TOKEN);
    expect(logged).not.toContain(REF);
    expect(logged).not.toContain(phone.deviceId);
  });

  it("re-mints the provider token once when APNs calls it expired", async () => {
    const key = await configure();
    const { node, phone } = await nodeWithPhone();
    const calls = mockApns([{ status: 403, reason: "ExpiredProviderToken" }]);
    expect((await push(node, pushBody(phone))).body).toEqual({ sent: true });
    expect(calls).toHaveLength(2);
    const first = await readJwt(calls[0]!.headers.authorization!, key.publicKey);
    const second = await readJwt(calls[1]!.headers.authorization!, key.publicKey);
    expect(second.jwt).not.toBe(first.jwt);
    expect(calls[1]!.body).toBe(calls[0]!.body);
    // The fresh token is the one kept.
    expect((await push(node, pushBody(phone, { kind: "ask" }))).body).toEqual({ sent: true });
    expect(calls[2]!.headers.authorization).toBe(calls[1]!.headers.authorization);

    // Refused again after the fresh one: 502, and no third try.
    mockApns([{ status: 403, reason: "InvalidProviderToken" }, { status: 403, reason: "InvalidProviderToken" }]);
    const failed = await push(node, pushBody(phone, { kind: "finished" }));
    expect(failed.status).toBe(502);
    expect(failed.body).toMatchObject({ error: "push_failed" });
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("reuses one provider token across pushes", async () => {
    await configure();
    const { node, phone } = await nodeWithPhone();
    const calls = mockApns();
    for (const kind of ["approval", "ask", "finished"] as const) await push(node, pushBody(phone, { kind }));
    expect(new Set(calls.map((c) => c.headers.authorization)).size).toBe(1);
  });
});

describe("the provider token", () => {
  const testEnv = (pem: string, keyId = KEY_ID, teamId = TEAM_ID) =>
    ({ APNS_KEY: pem, APNS_KEY_ID: keyId, APNS_TEAM_ID: teamId, APNS_TOPIC: TOPIC }) as unknown as Env;

  it("is ES256 with kid, iss and iat, reused for 50 minutes and minted again after", async () => {
    const key = await newApnsKey();
    const c = (await apnsConfig(testEnv(key.pem)))!;
    expect(c).not.toBeNull();
    const t0 = 1_760_000_000_000;
    const tok = await providerToken(c, t0);
    const { header, claims } = await readJwt(`bearer ${tok}`, key.publicKey);
    expect(header).toEqual({ alg: "ES256", kid: KEY_ID });
    expect(claims).toEqual({ iss: TEAM_ID, iat: t0 / 1000 });
    // The segments are unpadded base64url of exactly these JSON texts.
    expect(tok.split(".")[0]).toBe(toBase64Url(utf8(JSON.stringify({ alg: "ES256", kid: KEY_ID }))));
    expect(tok.split(".")[1]).toBe(toBase64Url(utf8(JSON.stringify({ iss: TEAM_ID, iat: t0 / 1000 }))));

    expect(await providerToken(c, t0 + 1000)).toBe(tok);
    expect(await providerToken(c, t0 + TOKEN_REUSE_MS - 1)).toBe(tok);
    const later = await providerToken(c, t0 + TOKEN_REUSE_MS);
    expect(later).not.toBe(tok);
    expect((await readJwt(`bearer ${later}`, key.publicKey)).claims.iat).toBe((t0 + TOKEN_REUSE_MS) / 1000);
    expect(await providerToken(c, t0 + TOKEN_REUSE_MS + 60_000)).toBe(later);
    // `fresh` (APNs called it expired) mints at once.
    expect(await providerToken(c, t0 + TOKEN_REUSE_MS + 60_000, true)).not.toBe(later);
  });

  it("is minted again when the key id, team or key changes", async () => {
    const key = await newApnsKey();
    const t0 = 1_760_000_000_000;
    const a = await providerToken((await apnsConfig(testEnv(key.pem)))!, t0);
    const b = await providerToken((await apnsConfig(testEnv(key.pem, "ZZZ123DEFG")))!, t0);
    expect(b).not.toBe(a);
    expect((await readJwt(`bearer ${b}`, key.publicKey)).header.kid).toBe("ZZZ123DEFG");
    const c = await providerToken((await apnsConfig(testEnv(key.pem, "ZZZ123DEFG", "OTHERTEAM1")))!, t0);
    expect((await readJwt(`bearer ${c}`, key.publicKey)).claims.iss).toBe("OTHERTEAM1");
    const rotated = await newApnsKey();
    const d = await providerToken((await apnsConfig(testEnv(rotated.pem, "ZZZ123DEFG", "OTHERTEAM1")))!, t0);
    await readJwt(`bearer ${d}`, rotated.publicKey);
  });
});
