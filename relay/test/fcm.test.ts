// Android push (PROTOCOL §10.7): `POST /v1/phone/push` with `platform: "android"`, through the real
// Worker and PhoneObject, with Google's token endpoint, FCM and APNs mocked at the global fetch
// (nothing leaves the test). The service-account keys are generated here, per test: no key is
// committed.

import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { resetApnsCache } from "../src/apns.ts";
import { fromBase64, toBase64, toBase64Url, utf8 } from "../src/encoding.ts";
import {
  ACCESS_TOKEN_MARGIN_MS,
  FCM_SCOPE,
  GOOGLE_TOKEN_URL,
  accessToken,
  fcmConfig,
  mintAssertion,
  resetFcmCache,
} from "../src/fcm.ts";
import { PUSH_KINDS, PUSH_TEXTS, type PushKind } from "../src/phone-push.ts";
import { fetchRelay, newNode, pairPhone, signed, type TestDevice, type TestNode, type TestPhone } from "./helpers.ts";

// ── a throwaway service account and a mock of Google ───────────────────────

const PROJECT = "zn-test-project";
const CLIENT_EMAIL = "push@zn-test-project.iam.gserviceaccount.com";
const KEY_ID = "0123456789abcdef0123456789abcdef01234567";

function pemOf(der: ArrayBuffer, label = "PRIVATE KEY"): string {
  const lines = toBase64(new Uint8Array(der)).match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

async function newRsaKey(bits = 2048): Promise<{ pem: string; publicKey: CryptoKey }> {
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  return { pem: pemOf((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer), publicKey: pair.publicKey };
}

/** A service-account JSON as Google issues it (test-only, generated per test). */
function serviceAccount(pem: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    type: "service_account",
    project_id: PROJECT,
    private_key_id: KEY_ID,
    private_key: pem,
    client_email: CLIENT_EMAIL,
    client_id: "123456789012345678901",
    auth_uri: "https://accounts.google.com/o/oauth2/auth",
    token_uri: "https://elsewhere.example/token",
    ...extra,
  });
}

const VARS = ["FCM_SERVICE_ACCOUNT", "APNS_KEY", "APNS_KEY_ID", "APNS_TEAM_ID", "APNS_TOPIC", "APNS_ENVIRONMENT"] as const;
const mutableEnv = env as unknown as Record<string, string | undefined>;

async function configureFcm(): Promise<{ pem: string; publicKey: CryptoKey }> {
  const key = await newRsaKey();
  mutableEnv.FCM_SERVICE_ACCOUNT = serviceAccount(key.pem);
  return key;
}

async function configureApns(): Promise<void> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  Object.assign(mutableEnv, {
    APNS_KEY: pemOf((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer),
    APNS_KEY_ID: "ABC123DEFG",
    APNS_TEAM_ID: "TEAM456XYZ",
    APNS_TOPIC: "dev.example.phone",
  });
}

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

type FcmReply = { status: number; error?: unknown } | "network";

const FCM_URL = `https://fcm.googleapis.com/v1/projects/${PROJECT}/messages:send`;

let fetchSpy: MockInstance<typeof fetch> | null = null;
let tokenCount = 0;

/**
 * Replaces the global fetch. Google's token endpoint answers `tokenReplies` (then a fresh token,
 * `at-1`, `at-2`…, for an hour), FCM answers `fcmReplies` (then 200), APNs answers 200.
 */
function mockGoogle(fcmReplies: FcmReply[] = [], tokenReplies: number[] = []): { token: Call[]; fcm: Call[]; apns: Call[] } {
  const calls = { token: [] as Call[], fcm: [] as Call[], apns: [] as Call[] };
  fetchSpy?.mockRestore();
  fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    const headers: Record<string, string> = {};
    req.headers.forEach((v, k) => (headers[k] = v));
    const call = { url: req.url, method: req.method, headers, body: new TextDecoder().decode(await req.arrayBuffer()) };
    if (req.url === GOOGLE_TOKEN_URL) {
      calls.token.push(call);
      const status = tokenReplies.shift() ?? 200;
      if (status !== 200) return Response.json({ error: "invalid_grant" }, { status });
      return Response.json({ access_token: `at-${++tokenCount}`, expires_in: 3599, token_type: "Bearer" });
    }
    if (req.url.startsWith("https://fcm.googleapis.com/")) {
      calls.fcm.push(call);
      const r = fcmReplies.shift() ?? { status: 200 };
      if (r === "network") throw new TypeError("network down");
      return r.status === 200 ? Response.json({ name: `projects/${PROJECT}/messages/0:1` }) : Response.json(r.error ?? {}, { status: r.status });
    }
    calls.apns.push(call);
    return new Response(null, { status: 200 });
  });
  return calls;
}

/** FCM's error body, as HTTP v1 writes it. */
function fcmError(code: number, status: string, errorCode?: string, tokenField = false): { error: unknown } {
  const details: unknown[] = [];
  if (errorCode) details.push({ "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", errorCode });
  if (tokenField) {
    details.push({ "@type": "type.googleapis.com/google.rpc.BadRequest", fieldViolations: [{ field: "message.token", description: "Invalid registration token" }] });
  }
  return { error: { code, message: "Whatever Google says.", status, details } };
}

afterEach(() => {
  for (const k of VARS) delete mutableEnv[k];
  delete mutableEnv.PHONE_PUSH_PER_HOUR;
  fetchSpy?.mockRestore();
  fetchSpy = null;
  tokenCount = 0;
  resetFcmCache();
  resetApnsCache();
  vi.restoreAllMocks();
});

// ── requests ────────────────────────────────────────────────────────────────

const FCM_TOKEN = `cK3p0abc_DEF-123:APA91b${"Hx9_-q".repeat(24)}`;
const APNS_TOKEN = "a1b2c3d4".repeat(8);
const REF = "AAAAAAAAAAAAAAAAAAAAAA";

function androidBody(phone: { deviceId: string }, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { device: phone.deviceId, platform: "android", token: FCM_TOKEN, kind: "approval", ref: REF, ...extra };
}

async function push(node: TestDevice, body: unknown): Promise<{ status: number; body: Record<string, unknown>; headers: Headers }> {
  const res = await signed(node, "POST", "/v1/phone/push", body);
  return { status: res.status, body: (await res.json()) as Record<string, unknown>, headers: res.headers };
}

async function nodeWithPhone(): Promise<{ node: TestNode; phone: TestPhone }> {
  const node = await newNode();
  return { node, phone: await pairPhone(node) };
}

function preview(): { at: number; enc: string; ct: string; sig: string } {
  return {
    at: 1_760_000_000_000,
    enc: toBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    ct: toBase64(crypto.getRandomValues(new Uint8Array(120))),
    sig: toBase64Url(crypto.getRandomValues(new Uint8Array(64))),
  };
}

const dec = (x: string) => JSON.parse(new TextDecoder().decode(fromBase64(x)!)) as Record<string, unknown>;

/** Decodes an assertion and checks its RS256 signature with `publicKey`. */
async function readAssertion(jwt: string, publicKey: CryptoKey): Promise<{ header: Record<string, unknown>; claims: Record<string, unknown> }> {
  expect(jwt).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  const [h, c, s] = jwt.split(".") as [string, string, string];
  expect(await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, publicKey, fromBase64(s)!, utf8(`${h}.${c}`))).toBe(true);
  return { header: dec(h), claims: dec(c) };
}

const info = async () =>
  ((await (await fetchRelay("/v1/info")).json()) as { phone: { push: { available: boolean; environment: unknown; platforms: unknown } } }).phone.push;

// ── tests ───────────────────────────────────────────────────────────────────

describe("/v1/info push platforms", () => {
  it("says which platforms are available, keeping iOS's fields where older clients read them", async () => {
    await configureFcm();
    expect(await info()).toEqual({
      available: false,
      environment: null,
      platforms: { ios: { available: false, environment: null }, android: { available: true } },
    });
    await configureApns();
    expect(await info()).toEqual({
      available: true,
      environment: "production",
      platforms: { ios: { available: true, environment: "production" }, android: { available: true } },
    });
    delete mutableEnv.FCM_SERVICE_ACCOUNT;
    expect((await info()).platforms).toEqual({ ios: { available: true, environment: "production" }, android: { available: false } });
  });

  it("is unavailable for Android with a malformed service account or a key that isn't a usable RSA key", async () => {
    const key = await newRsaKey();
    const ec = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])) as CryptoKeyPair;
    const ecPem = pemOf((await crypto.subtle.exportKey("pkcs8", ec.privateKey)) as ArrayBuffer);
    const short = await newRsaKey(1024);
    const body = key.pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").trim();
    const cases: string[] = [
      "not json",
      "[]",
      JSON.stringify("service_account"),
      serviceAccount(key.pem, { type: "authorized_user" }),
      serviceAccount(key.pem, { project_id: undefined }),
      serviceAccount(key.pem, { project_id: "Has Spaces" }),
      serviceAccount(key.pem, { project_id: "../other/messages" }),
      serviceAccount(key.pem, { client_email: undefined }),
      serviceAccount(key.pem, { client_email: "not an email" }),
      serviceAccount(key.pem, { private_key: undefined }),
      serviceAccount(key.pem, { private_key: body }),
      serviceAccount(key.pem, { private_key: `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----\n` }),
      serviceAccount(key.pem, { private_key: "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n" }),
      serviceAccount(ecPem),
      serviceAccount(short.pem),
      serviceAccount(key.pem, { padding: "x".repeat(20_000) }),
    ];
    for (const c of cases) {
      mutableEnv.FCM_SERVICE_ACCOUNT = c;
      expect((await info()).platforms, c.slice(0, 80)).toEqual({ ios: { available: false, environment: null }, android: { available: false } });
    }
    // The good one, also with surrounding whitespace as a secret is often pasted.
    mutableEnv.FCM_SERVICE_ACCOUNT = `\n  ${serviceAccount(key.pem)}  \n`;
    expect(((await info()).platforms as { android: unknown }).android).toEqual({ available: true });
  });

  it("answers `unavailable` for Android when only APNs is set, and for iOS when only FCM is", async () => {
    await configureApns();
    const { node, phone } = await nodeWithPhone();
    const calls = mockGoogle();
    expect(await push(node, androidBody(phone))).toMatchObject({ status: 200, body: { sent: false, reason: "unavailable" } });
    delete mutableEnv.APNS_KEY;
    await configureFcm();
    expect(await push(node, { device: phone.deviceId, token: APNS_TOKEN, kind: "ask", ref: REF })).toMatchObject({
      status: 200,
      body: { sent: false, reason: "unavailable" },
    });
    expect(calls.apns.length + calls.fcm.length + calls.token.length).toBe(0);
  });
});

describe("POST /v1/phone/push to Android", () => {
  it("exchanges a signed assertion for an access token, then sends the fixed message to FCM", async () => {
    const key = await configureFcm();
    const { node, phone } = await nodeWithPhone();
    const calls = mockGoogle();
    const p = preview();
    const before = Math.floor(Date.now() / 1000);
    expect(await push(node, androidBody(phone, { preview: p }))).toMatchObject({ status: 200, body: { sent: true } });
    const after = Math.floor(Date.now() / 1000);

    // The token request: Google's fixed endpoint (never the service account's token_uri).
    expect(calls.token).toHaveLength(1);
    const t = calls.token[0]!;
    expect(t.url).toBe("https://oauth2.googleapis.com/token");
    expect(t.method).toBe("POST");
    expect(t.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    const form = new URLSearchParams(t.body);
    expect([...form.keys()].sort()).toEqual(["assertion", "grant_type"]);
    expect(form.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    const { header, claims } = await readAssertion(form.get("assertion")!, key.publicKey);
    expect(header).toEqual({ alg: "RS256", typ: "JWT", kid: KEY_ID });
    expect(claims).toEqual({ iss: CLIENT_EMAIL, scope: FCM_SCOPE, aud: "https://oauth2.googleapis.com/token", iat: expect.any(Number), exp: expect.any(Number) });
    expect(claims.scope).toBe("https://www.googleapis.com/auth/firebase.messaging");
    expect(claims.iat as number).toBeGreaterThanOrEqual(before);
    expect(claims.iat as number).toBeLessThanOrEqual(after);
    expect(claims.exp).toBe((claims.iat as number) + 3600);

    // The push: FCM's fixed host, the project from the service account, the access token.
    expect(calls.fcm).toHaveLength(1);
    const f = calls.fcm[0]!;
    expect(f.url).toBe(FCM_URL);
    expect(f.method).toBe("POST");
    expect(f.headers).toEqual({ authorization: "Bearer at-1", "content-type": "application/json" });
    expect(JSON.parse(f.body)).toEqual({
      message: {
        token: FCM_TOKEN,
        notification: { title: "An agent needs you", body: "Approval needed." },
        data: { zn: JSON.stringify({ v: 1, kind: "approval", ref: REF, p }) },
        android: { priority: "high", ttl: "86400s", collapse_key: "approval", notification: { tag: "approval" } },
      },
    });
    for (const secret of [phone.deviceId, node.deviceId, node.accountId]) expect(f.body).not.toContain(secret);
    expect(calls.apns).toHaveLength(0);
  });

  it("sends each kind's fixed texts, the same as APNs', and leaves out the preview when none is given", async () => {
    await configureFcm();
    const { node, phone } = await nodeWithPhone();
    const calls = mockGoogle();
    for (const kind of PUSH_KINDS) expect((await push(node, androidBody(phone, { kind }))).body).toEqual({ sent: true });
    calls.fcm.forEach((c, i) => {
      const kind = PUSH_KINDS[i]!;
      const m = (JSON.parse(c.body) as { message: Record<string, unknown> }).message;
      expect(m.notification).toEqual({ title: PUSH_TEXTS[kind].title, body: PUSH_TEXTS[kind].body });
      expect(m.data).toEqual({ zn: JSON.stringify({ v: 1, kind, ref: REF }) });
    });
    // One access token for all of them.
    expect(calls.token).toHaveLength(1);
    expect(new Set(calls.fcm.map((c) => c.headers.authorization))).toEqual(new Set(["Bearer at-1"]));
  });

  it("routes by platform: absent or ios to APNs, android to FCM; the limits are the phone's, whatever the platform", async () => {
    await configureApns();
    await configureFcm();
    const { node, phone } = await nodeWithPhone();
    const calls = mockGoogle();
    expect((await push(node, { device: phone.deviceId, token: APNS_TOKEN, kind: "approval", ref: REF })).body).toEqual({ sent: true });
    expect((await push(node, { device: phone.deviceId, platform: "ios", token: APNS_TOKEN, kind: "ask", ref: REF })).body).toEqual({ sent: true });
    expect((await push(node, androidBody(phone, { kind: "finished" }))).body).toEqual({ sent: true });
    expect(calls.apns.map((c) => c.url)).toEqual([`https://api.push.apple.com/3/device/${APNS_TOKEN}`, `https://api.push.apple.com/3/device/${APNS_TOKEN}`]);
    expect(calls.fcm.map((c) => c.url)).toEqual([FCM_URL]);
    // The same kind a minute later, on the other platform, is still held back.
    const again = await push(node, androidBody(phone, { kind: "approval" }));
    expect(again.status).toBe(429);
    expect(again.body).toMatchObject({ error: "rate_limited" });
    expect(calls.fcm).toHaveLength(1);
  });

  it("refuses a malformed Android request with the field, and sends nothing", async () => {
    await configureFcm();
    const { node, phone } = await nodeWithPhone();
    const calls = mockGoogle();
    const cases: [Record<string, unknown>, string][] = [
      [{ platform: "windows" }, "platform"],
      [{ platform: null }, "platform"],
      [{ platform: "Android" }, "platform"],
      [{ environment: "production" }, "environment"],
      [{ token: "short:token" }, "token"],
      [{ token: `${FCM_TOKEN} ` }, "token"],
      [{ token: `${FCM_TOKEN}/x` }, "token"],
      [{ token: "a".repeat(1025) }, "token"],
      [{ token: 12345 }, "token"],
      // An iOS request still takes only an APNs token.
      [{ platform: "ios" }, "token"],
    ];
    for (const [extra, field] of cases) {
      const res = await push(node, androidBody(phone, extra));
      expect(res.status, JSON.stringify(extra).slice(0, 80)).toBe(400);
      expect(res.body).toMatchObject({ error: "invalid", field });
    }
    expect(calls.token.length + calls.fcm.length).toBe(0);
  });
});

describe("FCM answers", () => {
  it("maps 404, UNREGISTERED, SENDER_ID_MISMATCH and INVALID_ARGUMENT on the token to `unregistered`", async () => {
    await configureFcm();
    const { node, phone } = await nodeWithPhone();
    const calls = mockGoogle([
      { status: 404, error: fcmError(404, "NOT_FOUND", "UNREGISTERED") },
      { status: 404 },
      { status: 400, error: fcmError(400, "INVALID_ARGUMENT", "INVALID_ARGUMENT", true) },
      { status: 403, error: fcmError(403, "PERMISSION_DENIED", "SENDER_ID_MISMATCH") },
    ]);
    const kinds: PushKind[] = ["approval", "ask", "finished", "handoff"];
    for (const kind of kinds) expect(await push(node, androidBody(phone, { kind }))).toMatchObject({ status: 200, body: { sent: false, reason: "unregistered" } });
    expect(calls.fcm).toHaveLength(4);
  });

  it("maps other failures to 502 push_failed and FCM's 429 to rate_limited, and never logs the token", async () => {
    await configureFcm();
    const { node, phone } = await nodeWithPhone();
    const logs: unknown[][] = [];
    for (const level of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => void logs.push(args));
    }
    mockGoogle([
      // Not about the token: the message is the relay's, so the token is kept.
      { status: 400, error: fcmError(400, "INVALID_ARGUMENT", "INVALID_ARGUMENT") },
      { status: 500, error: fcmError(500, "INTERNAL", "INTERNAL") },
      "network",
      { status: 429, error: fcmError(429, "RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED") },
    ]);
    for (const kind of ["approval", "ask", "finished"] as const) {
      const r = await push(node, androidBody(phone, { kind }));
      expect(r.status).toBe(502);
      expect(r.body).toEqual({ error: "push_failed", message: "Google's push service didn't accept the push." });
    }
    const limited = await push(node, androidBody(phone, { kind: "handoff" }));
    expect(limited.status).toBe(429);
    expect(limited.body).toMatchObject({ error: "rate_limited", retryAfter: 60 });
    expect(limited.headers.get("Retry-After")).toBe("60");
    const logged = JSON.stringify(logs);
    for (const secret of [FCM_TOKEN, "at-1", REF, phone.deviceId]) expect(logged).not.toContain(secret);
  });

  it("fetches a fresh access token once when FCM answers 401, and keeps it", async () => {
    await configureFcm();
    const { node, phone } = await nodeWithPhone();
    const calls = mockGoogle([{ status: 401, error: fcmError(401, "UNAUTHENTICATED") }]);
    expect((await push(node, androidBody(phone))).body).toEqual({ sent: true });
    expect(calls.token).toHaveLength(2);
    expect(calls.fcm.map((c) => c.headers.authorization)).toEqual(["Bearer at-1", "Bearer at-2"]);
    expect(calls.fcm[1]!.body).toBe(calls.fcm[0]!.body);
    expect((await push(node, androidBody(phone, { kind: "ask" }))).body).toEqual({ sent: true });
    expect(calls.fcm[2]!.headers.authorization).toBe("Bearer at-2");

    // Refused again after the fresh one: 502, and no third try.
    const again = mockGoogle([{ status: 401 }, { status: 401 }]);
    const failed = await push(node, androidBody(phone, { kind: "finished" }));
    expect(failed).toMatchObject({ status: 502, body: { error: "push_failed", message: "Google's push service refused the relay's credentials." } });
    expect(again.fcm).toHaveLength(2);
  });

  it("sends nothing to FCM when Google's token endpoint refuses the service account", async () => {
    await configureFcm();
    const { node, phone } = await nodeWithPhone();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const calls = mockGoogle([], [400]);
    expect(await push(node, androidBody(phone))).toMatchObject({ status: 502, body: { error: "push_failed" } });
    expect(calls.token).toHaveLength(1);
    expect(calls.fcm).toHaveLength(0);
    // Nothing bad is cached: the next push fetches a token again.
    expect((await push(node, androidBody(phone, { kind: "ask" }))).body).toEqual({ sent: true });
    expect(calls.token).toHaveLength(2);
  });
});

describe("the access token", () => {
  const testEnv = (sa: string) => ({ FCM_SERVICE_ACCOUNT: sa }) as unknown as Env;

  it("is reused until five minutes before it expires, then fetched again", async () => {
    const key = await newRsaKey();
    const c = (await fcmConfig(testEnv(serviceAccount(key.pem))))!;
    expect(c).not.toBeNull();
    const calls = mockGoogle();
    const t0 = 1_760_000_000_000;
    expect(await accessToken(c, t0)).toBe("at-1");
    expect(await accessToken(c, t0 + 60_000)).toBe("at-1");
    const refreshAt = t0 + 3599_000 - ACCESS_TOKEN_MARGIN_MS;
    expect(await accessToken(c, refreshAt - 1)).toBe("at-1");
    expect(calls.token).toHaveLength(1);
    expect(await accessToken(c, refreshAt)).toBe("at-2");
    expect(calls.token).toHaveLength(2);
    // The assertion is signed at the time asked for.
    const claims = (await readAssertion(new URLSearchParams(calls.token[1]!.body).get("assertion")!, key.publicKey)).claims;
    expect(claims.iat).toBe(refreshAt / 1000);
    expect(claims.exp).toBe(refreshAt / 1000 + 3600);
    // `fresh` (FCM refused it) fetches at once.
    expect(await accessToken(c, refreshAt + 1000, true)).toBe("at-3");
  });

  it("shares one exchange between parallel pushes, and is fetched again for a rotated key or another account", async () => {
    const key = await newRsaKey();
    const calls = mockGoogle();
    const t0 = 1_760_000_000_000;
    const c = (await fcmConfig(testEnv(serviceAccount(key.pem))))!;
    expect(await Promise.all([accessToken(c, t0), accessToken(c, t0), accessToken(c, t0)])).toEqual(["at-1", "at-1", "at-1"]);
    expect(calls.token).toHaveLength(1);
    const other = (await fcmConfig(testEnv(serviceAccount(key.pem, { client_email: "other@zn-test-project.iam.gserviceaccount.com" }))))!;
    expect(await accessToken(other, t0)).toBe("at-2");
    const rotated = await newRsaKey();
    const r = (await fcmConfig(testEnv(serviceAccount(rotated.pem))))!;
    expect(await accessToken(r, t0)).toBe("at-3");
    await readAssertion(new URLSearchParams(calls.token[2]!.body).get("assertion")!, rotated.publicKey);
  });

  it("leaves out kid when the service account has no key id, and takes the PEM with \\n escapes", async () => {
    const key = await newRsaKey();
    const c = (await fcmConfig(testEnv(serviceAccount(key.pem.replace(/\n/g, "\\n"), { private_key_id: undefined }))))!;
    expect(c).not.toBeNull();
    const t0 = 1_760_000_000_000;
    const { header, claims } = await readAssertion(await mintAssertion(c, t0), key.publicKey);
    expect(header).toEqual({ alg: "RS256", typ: "JWT" });
    expect(claims).toEqual({ iss: CLIENT_EMAIL, scope: FCM_SCOPE, aud: GOOGLE_TOKEN_URL, iat: t0 / 1000, exp: t0 / 1000 + 3600 });
  });
});
