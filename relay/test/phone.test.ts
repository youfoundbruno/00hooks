// Phone links (PROTOCOL §10): pairing, the phone's limits, sealed-only routing between a node and
// its phones, resume, presence, limits and revocation, through the real Worker and PhoneObject.

import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import type { AccountObject } from "../src/account-object.ts";
import { generateDeviceKey } from "../src/canonical.ts";
import { toBase64Url, utf8 } from "../src/encoding.ts";
import { redeemPairing } from "../src/phone.ts";
import type { PhoneObject } from "../src/phone-object.ts";
import {
  BASE,
  accountObject,
  enrolDevice,
  fetchRelay,
  makeEnvelope,
  newNode,
  newPairingSecret,
  newSealPair,
  openPhoneSocket,
  pairPhone,
  phoneObject,
  phoneOpen,
  randomTestIp,
  redeemPhone,
  registerPairing,
  signed,
  type Frame,
  type TestNode,
  type TestPhone,
} from "./helpers.ts";

const nodeKey = (n: TestNode) => ({ deviceId: n.deviceId, sealKey: n.phoneSeal });
const phoneKey = (p: TestPhone) => ({ deviceId: p.deviceId, sealKey: p.seal });

/** Sends an envelope and waits for its answer (`queued` or `refused`); other frames stay queued. */
async function sendEnv(sock: Awaited<ReturnType<typeof openPhoneSocket>>, env: Record<string, unknown>): Promise<Frame> {
  sock.send({ t: "send", env });
  return sock.nextWhere((f) => f.t === "queued" || f.t === "refused");
}

type Env1 = { enc: string; ct: string; id: string };

/** Every value in every table of the account's PhoneObject, as text. */
async function phoneTables(accountId: string): Promise<string> {
  return runInDurableObject(phoneObject(accountId), (_o: PhoneObject, state) => {
    const tables = state.storage.sql
      .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_cf%' AND name NOT LIKE 'sqlite%'")
      .toArray();
    let out = "";
    for (const t of tables) {
      for (const row of state.storage.sql.exec(`SELECT * FROM "${t.name}"`).toArray()) {
        for (const v of Object.values(row)) out += v instanceof ArrayBuffer ? new TextDecoder().decode(v) : String(v);
        out += "\n";
      }
    }
    return out;
  });
}

async function accountTables(accountId: string): Promise<string> {
  return runInDurableObject(accountObject(accountId), (_o: AccountObject, state) => {
    const tables = state.storage.sql
      .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_cf%' AND name NOT LIKE 'sqlite%'")
      .toArray();
    let out = "";
    for (const t of tables) {
      for (const row of state.storage.sql.exec(`SELECT * FROM "${t.name}"`).toArray()) {
        for (const v of Object.values(row)) out += v instanceof ArrayBuffer ? new TextDecoder().decode(v) : String(v);
        out += "\n";
      }
    }
    return out;
  });
}

async function d1Tables(): Promise<string> {
  const { results } = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_cf%' AND name NOT LIKE 'sqlite%'").all<{
    name: string;
  }>();
  let out = "";
  for (const t of results) out += JSON.stringify((await env.DB.prepare(`SELECT * FROM "${t.name}"`).all()).results) + "\n";
  return out;
}

describe("phone pairing", () => {
  it("announces the phone protocol in /v1/info", async () => {
    const info = (await (await fetchRelay("/v1/info")).json()) as { phone: unknown; protocol: number };
    // Push isn't configured in the tests' bindings (phone-push.test.ts sets it).
    expect(info.phone).toEqual({
      protocol: 1,
      push: { available: false, environment: null, platforms: { ios: { available: false, environment: null }, android: { available: false } } },
    });
    expect(info.protocol).toBe(2);
  });

  it("pairs a phone as a pending device and queues its sealed hello to the node", async () => {
    const node = await newNode();
    const pairing = await registerPairing(node);
    const { res, phone } = await redeemPhone(node, pairing, { name: "Ana's iPhone" });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ deviceId: phone!.deviceId, node: node.deviceId });

    const row = await env.DB.prepare("SELECT kind, peer, pending_until, seal_key, name FROM devices WHERE id = ?")
      .bind(phone!.deviceId)
      .first<{ kind: string; peer: string; pending_until: number | null; seal_key: string; name: string }>();
    expect(row).toMatchObject({ kind: "phone", peer: node.deviceId, seal_key: phone!.seal.text, name: "Ana's iPhone" });
    expect(row!.pending_until).toBeGreaterThan(Date.now() + 10 * 60_000);

    // The node, connecting later, finds the pairing hello in its backlog, and opens it.
    const sock = await openPhoneSocket(node);
    const ready = await sock.hello(0);
    expect(ready).toMatchObject({ t: "ready", after: 0, peers: [{ device: phone!.deviceId, online: false }] });
    const sys = await sock.nextOf("sys");
    const pair = sys.sys as Record<string, unknown> & { hello: { enc: string; ct: string } };
    expect(pair).toMatchObject({
      kind: "pair",
      pairingId: pairing.pairingId,
      device: phone!.deviceId,
      name: "Ana's iPhone",
      publicKey: phone!.publicKey,
      sealKey: phone!.seal.text,
    });
    expect(ready.head).toBe(sys.seq);
    const hello = JSON.parse(
      new TextDecoder().decode(await phoneOpen(node.phoneSeal.privateKey, pair.hello.enc, pair.hello.ct, utf8(`00next-pair-v1\n${pairing.pairingId}`))),
    );
    expect(hello).toMatchObject({ type: "pair_hello", signKey: phone!.publicKey, sealKey: phone!.seal.text });
    sock.close();

    // The audit names the node as the one that added it.
    const audit = (await (await signed(node, "GET", "/v1/audit")).json()) as { entries: { kind: string; actor: string; subject: string }[] };
    expect(audit.entries).toContainEqual(expect.objectContaining({ kind: "device.added", actor: node.deviceId, subject: phone!.deviceId }));
    expect(audit.entries).toContainEqual(expect.objectContaining({ kind: "phone.pairing", actor: node.deviceId, subject: pairing.pairingId }));
  });

  it("delivers the hello at once to a node that is connected", async () => {
    const node = await newNode();
    const sock = await openPhoneSocket(node);
    expect(await sock.hello(0)).toMatchObject({ after: 0, head: 0, peers: [] });
    const { phone } = await redeemPhone(node, await registerPairing(node));
    const sys = await sock.nextOf("sys");
    expect(sys.sys).toMatchObject({ kind: "pair", device: phone!.deviceId });
    sock.close();
  });

  it("refuses a wrong proof or an unknown pairing (401), a used one (409) and an expired one (401)", async () => {
    const node = await newNode();
    const pairing = await registerPairing(node);
    const wrong = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const bad = await redeemPhone(node, pairing, { proof: wrong });
    expect(bad.res.status).toBe(401);
    expect(await bad.res.json()).toEqual({ error: "unauthorized", message: "That pairing code isn't valid." });
    const unknown = await redeemPhone(node, await newPairingSecret());
    expect(unknown.res.status).toBe(401);

    expect((await redeemPhone(node, pairing)).res.status).toBe(200);
    const again = await redeemPhone(node, pairing);
    expect(again.res.status).toBe(409);
    expect(await again.res.json()).toEqual({ error: "conflict", message: "That pairing code was already used." });
    // A wrong proof for a used pairing still says only "not valid".
    expect((await redeemPhone(node, pairing, { proof: wrong })).res.status).toBe(401);

    const late = await registerPairing(node);
    await env.DB.prepare("UPDATE phone_pairings SET expires_at = ? WHERE id = ?").bind(Date.now() - 1, late.pairingId).run();
    const expired = await redeemPhone(node, late);
    expect(expired.res.status).toBe(401);
    expect(await expired.res.json()).toEqual({ error: "unauthorized", message: "That pairing code has expired." });
  });

  it("lets exactly one of two parallel redemptions win", async () => {
    const node = await newNode();
    const pairing = await registerPairing(node);
    const results = await Promise.all(Array.from({ length: 4 }, () => redeemPhone(node, pairing)));
    const statuses = results.map((r) => r.res.status).sort();
    expect(statuses).toEqual([200, 409, 409, 409]);
    const { results: phones } = await env.DB.prepare("SELECT id FROM devices WHERE account_id = ? AND kind = 'phone'").bind(node.accountId).all();
    expect(phones).toHaveLength(1);
  });

  it("rate limits pairing attempts per address, and fails closed without the binding", async () => {
    const intoWindow = Date.now() % 60_000;
    if (intoWindow > 50_000) await new Promise((r) => setTimeout(r, 60_000 - intoWindow + 50));
    const ip = randomTestIp();
    const post = () => fetchRelay("/v1/phone/pair", { method: "POST", headers: { "CF-Connecting-IP": ip }, body: "not json" });
    for (let i = 0; i < 10; i++) expect((await post()).status).toBe(400);
    const limited = await post();
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBe("60");
    expect(await limited.json()).toMatchObject({ error: "rate_limited" });

    const req = new Request(`${BASE}/v1/phone/pair`, { method: "POST", headers: { "CF-Connecting-IP": randomTestIp() } });
    const res = await redeemPairing(req, { ...env, PAIR_IP_LIMIT: undefined } as unknown as Env, utf8("{}"));
    expect(res.status).toBe(503);
  }, 20_000);

  it("allows at most five open pairings per account, refuses duplicates and clamps the expiry", async () => {
    const node = await newNode();
    const first = await newPairingSecret();
    const far = Date.now() + 3600_000;
    const created = await signed(node, "POST", "/v1/phone/pairings", { pairingId: first.pairingId, verifier: first.verifier, expiresAt: far });
    expect(created.status).toBe(201);
    const body = (await created.json()) as { pairingId: string; expiresAt: number };
    expect(body.pairingId).toBe(first.pairingId);
    expect(body.expiresAt).toBeLessThanOrEqual(Date.now() + 10 * 60_000);

    const dup = await signed(node, "POST", "/v1/phone/pairings", { pairingId: first.pairingId, verifier: first.verifier, expiresAt: far });
    expect(dup.status).toBe(409);
    for (let i = 0; i < 4; i++) await registerPairing(node);
    const p = await newPairingSecret();
    const sixth = await signed(node, "POST", "/v1/phone/pairings", { pairingId: p.pairingId, verifier: p.verifier, expiresAt: far });
    expect(sixth.status).toBe(429);
    expect(await sixth.json()).toMatchObject({ error: "rate_limited" });

    const past = await signed(node, "POST", "/v1/phone/pairings", { pairingId: p.pairingId, verifier: p.verifier, expiresAt: Date.now() - 1 });
    expect(past.status).toBe(400);
    const short = await signed(node, "POST", "/v1/phone/pairings", { pairingId: "abc", verifier: p.verifier, expiresAt: far });
    expect(short.status).toBe(400);
    expect(await short.json()).toMatchObject({ field: "pairingId" });

    // A used pairing no longer counts as open.
    const other = await newNode();
    const pairings = [];
    for (let i = 0; i < 5; i++) pairings.push(await registerPairing(other));
    expect((await redeemPhone(other, pairings[0]!)).res.status).toBe(200);
    await registerPairing(other);
  });

  it("refuses a pair without a sealing key, or with a malformed hello", async () => {
    const node = await newNode();
    const pairing = await registerPairing(node);
    const { publicKey } = await generateDeviceKey();
    const base = { pairingId: pairing.pairingId, proof: pairing.proof, deviceName: "x", publicKey };
    const post = (body: unknown) =>
      fetchRelay("/v1/phone/pair", { method: "POST", headers: { "CF-Connecting-IP": randomTestIp() }, body: JSON.stringify(body) });
    const seal = await newSealPair();
    const noSeal = await post({ ...base, hello: { enc: seal.text, ct: "AAAAAAAAAAAAAAAAAAAAAA==" } });
    expect(noSeal.status).toBe(400);
    expect(await noSeal.json()).toMatchObject({ field: "sealKey" });
    const zero = await post({ ...base, sealKey: "A".repeat(43), hello: { enc: seal.text, ct: "AAAAAAAAAAAAAAAAAAAAAA==" } });
    expect(zero.status).toBe(400);
    const bigHello = await post({ ...base, sealKey: seal.text, hello: { enc: seal.text, ct: btoa("x".repeat(8 * 1024 + 1)) } });
    expect(bigHello.status).toBe(400);
    expect(await bigHello.json()).toMatchObject({ field: "hello" });
    // Nothing was spent.
    expect((await redeemPhone(node, pairing)).res.status).toBe(200);
  });

  it("limits a phone to the phone routes (403 elsewhere)", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    for (const [method, path, body] of [
      ["GET", "/v1/hooks", undefined],
      ["POST", "/v1/hooks", { name: "x", verify: { preset: "unverified" } }],
      ["POST", "/v1/enrolments", undefined],
      ["GET", "/v1/devices", undefined],
      ["DELETE", `/v1/devices/${node.deviceId}`, undefined],
      ["GET", "/v1/keys", undefined],
      ["GET", "/v1/audit", undefined],
      ["POST", "/v1/ack", { through: 0 }],
      ["POST", "/v1/phone/pairings", { pairingId: "x", verifier: "y", expiresAt: 1 }],
      ["GET", "/v1/phone/devices", undefined],
      ["POST", `/v1/phone/devices/${phone.deviceId}/confirm`, undefined],
    ] as const) {
      const res = await signed(phone, method, path, body);
      expect(res.status, `${method} ${path}`).toBe(403);
      expect(await res.json()).toMatchObject({ error: "forbidden" });
    }
    const stream = await signed(phone, "GET", "/v1/stream", undefined, { headers: { "X-00h-Protocol": "2", Accept: "text/event-stream" } });
    expect(stream.status).toBe(403);
    expect(await stream.json()).toEqual({ error: "forbidden", message: "A phone may use only the phone routes." });
    // A device can't unpair itself as a phone.
    expect((await signed(node, "DELETE", "/v1/phone/self")).status).toBe(403);
    // The phone never became a device of the webhook log.
    expect((await accountObject(node.accountId).stats()).devices.map((d) => d.id)).toEqual([node.deviceId]);
  });

  it("keeps a pending phone from sending until its node confirms; only its node can confirm", async () => {
    const node = await newNode();
    const phone = await pairPhone(node, { confirm: false });
    const other = await enrolDevice(node, "desktop");

    const phoneSock = await openPhoneSocket(phone);
    const ready = await phoneSock.hello(0);
    expect(ready).toMatchObject({ after: 0, head: 0, peers: [{ device: node.deviceId, online: false }] });
    const early = await makeEnvelope(phone, nodeKey(node), "hi");
    expect(await sendEnv(phoneSock, early)).toEqual({ t: "refused", id: early.id, code: "not_paired" });
    // The node can't send to it either until it confirms.
    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);
    expect(await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(phone), "hi"))).toMatchObject({ code: "forbidden" });

    expect((await signed(other, "POST", `/v1/phone/devices/${phone.deviceId}/confirm`)).status).toBe(404);
    expect((await signed(node, "POST", `/v1/phone/devices/${other.deviceId}/confirm`)).status).toBe(404);
    const listed = (await (await signed(node, "GET", "/v1/phone/devices")).json()) as { phones: Record<string, unknown>[] };
    expect(listed.phones).toEqual([
      expect.objectContaining({ id: phone.deviceId, peer: node.deviceId, name: "Ana's iPhone", pending: true, online: true }),
    ]);

    const ok = await signed(node, "POST", `/v1/phone/devices/${phone.deviceId}/confirm`);
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ device: phone.deviceId, active: true });
    // A second confirm finds nothing pending.
    expect((await signed(node, "POST", `/v1/phone/devices/${phone.deviceId}/confirm`)).status).toBe(404);
    expect(await sendEnv(phoneSock, early)).toMatchObject({ t: "queued", id: early.id });

    const devices = (await (await signed(node, "GET", "/v1/devices")).json()) as { devices: Record<string, unknown>[] };
    expect(devices.devices).toContainEqual(expect.objectContaining({ id: phone.deviceId, kind: "phone", peer: node.deviceId }));
    expect(devices.devices).toContainEqual(expect.objectContaining({ id: node.deviceId, kind: "device", peer: null }));
    phoneSock.close();
    nodeSock.close();
  });

  it("treats a pending phone whose pairing ran out as revoked", async () => {
    const node = await newNode();
    const phone = await pairPhone(node, { confirm: false });
    const sock = await openPhoneSocket(phone);
    await sock.hello(0);
    const past = Date.now() - 1;
    await env.DB.prepare("UPDATE devices SET pending_until = ? WHERE id = ?").bind(past, phone.deviceId).run();
    await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) => {
      state.storage.sql.exec("UPDATE phones SET pending_until = ? WHERE id = ?", past, phone.deviceId);
    });
    expect((await signed(phone, "GET", "/v1/phone/socket", undefined, { headers: { Upgrade: "websocket" } })).status).toBe(401);
    expect((await signed(node, "POST", `/v1/phone/devices/${phone.deviceId}/confirm`)).status).toBe(404);
    expect(await runDurableObjectAlarm(phoneObject(node.accountId))).toBe(true);
    expect(await sock.closed).toBe(4401);
    const listed = (await (await signed(node, "GET", "/v1/phone/devices")).json()) as { phones: unknown[] };
    expect(listed.phones).toEqual([]);
  });

  it("answers 426 to a socket request without an upgrade, and 403 to an API key", async () => {
    const node = await newNode();
    const res = await signed(node, "GET", "/v1/phone/socket");
    expect(res.status).toBe(426);
    const key = (await (await signed(node, "POST", "/v1/keys", { name: "ci", scopes: ["devices:write"] })).json()) as { token: string };
    for (const [method, path] of [
      ["GET", "/v1/phone/devices"],
      ["POST", "/v1/phone/pairings"],
    ] as const) {
      const r = await fetchRelay(path, { method, headers: { Authorization: `Bearer ${key.token}` } });
      expect(r.status).toBe(403);
    }
  });
});

describe("sealed-only forwarding", () => {
  it("routes envelopes byte for byte both ways, and never holds what is sealed in them", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const marker = `marker-${crypto.randomUUID()}`;
    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);
    await nodeSock.nextOf("sys"); // the pairing hello
    const phoneSock = await openPhoneSocket(phone);
    await phoneSock.hello(0);

    const up = await makeEnvelope(phone, nodeKey(node), JSON.stringify({ type: "request", rid: "1", method: "send_message", params: { text: marker } }));
    const q1 = await sendEnv(phoneSock, up);
    expect(q1).toMatchObject({ t: "queued", id: up.id });
    const got1 = await nodeSock.nextOf("msg");
    expect(got1.seq).toBe(q1.seq);
    expect(JSON.stringify(got1.env)).toBe(JSON.stringify(up));
    const pt1 = new TextDecoder().decode(
      await phoneOpen(node.phoneSeal.privateKey, (got1.env as Env1).enc, (got1.env as Env1).ct, utf8(`00next-phone-v1\n${phone.deviceId}\n${node.deviceId}\n${up.id}\n${up.at}`)),
    );
    expect(pt1).toContain(marker);

    const down = await makeEnvelope(node, phoneKey(phone), JSON.stringify({ type: "response", rid: "1", ok: true, result: { echo: marker } }), { push: "message" });
    const q2 = await sendEnv(nodeSock, down);
    expect(q2).toMatchObject({ t: "queued", id: down.id });
    const got2 = await phoneSock.nextOf("msg");
    expect(JSON.stringify(got2.env)).toBe(JSON.stringify(down));
    const pt2 = new TextDecoder().decode(
      await phoneOpen(phone.seal.privateKey, (got2.env as Env1).enc, (got2.env as Env1).ct, utf8(`00next-phone-v1\n${node.deviceId}\n${phone.deviceId}\n${down.id}\n${down.at}`)),
    );
    expect(pt2).toContain(marker);

    // Nothing the relay keeps holds the marker, the plaintext, or a private key that opens either.
    const stored = [await phoneTables(node.accountId), await accountTables(node.accountId), await d1Tables()].join("\n");
    expect(stored).not.toContain(marker);
    expect(stored).not.toContain("send_message");
    expect(stored).not.toContain(toBase64Url(node.phoneSeal.privateKey));
    expect(stored).not.toContain(toBase64Url(phone.seal.privateKey));
    // The stored envelopes are there, as ciphertext (until acknowledged).
    expect(await phoneTables(node.accountId)).toContain(up.ct as string);
    phoneSock.close();
    nodeSock.close();
  });
});

describe("routing", () => {
  it("refuses spoofed senders, wrong recipients, a phone's push and malformed envelopes", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const sibling = await pairPhone(node, { name: "iPad" });
    const node2 = { ...(await enrolDevice(node, "desktop")), phoneSeal: await newSealPair() };
    const foreign = await pairPhone(node2);

    const phoneSock = await openPhoneSocket(phone);
    await phoneSock.hello(0);
    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);

    // `from` must be the socket's device.
    const spoof = await makeEnvelope(sibling, nodeKey(node), "x");
    expect(await sendEnv(phoneSock, spoof)).toEqual({ t: "refused", id: spoof.id, code: "forbidden" });
    // A phone sends only to its node: not to another phone, not to another node.
    expect(await sendEnv(phoneSock, await makeEnvelope(phone, phoneKey(sibling), "x"))).toMatchObject({ code: "forbidden" });
    expect(await sendEnv(phoneSock, await makeEnvelope(phone, nodeKey(node2), "x"))).toMatchObject({ code: "forbidden" });
    // A node sends only to its own phones.
    expect(await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(foreign), "x"))).toMatchObject({ code: "forbidden" });
    expect(await sendEnv(nodeSock, await makeEnvelope(node, nodeKey(node2), "x"))).toMatchObject({ code: "forbidden" });
    // `push` is a node's only.
    expect(await sendEnv(phoneSock, await makeEnvelope(phone, nodeKey(node), "x", { push: "approval" }))).toMatchObject({ code: "invalid" });
    expect(await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(phone), "x", { push: "shout" }))).toMatchObject({ code: "invalid" });
    // Shape: version, field formats, and nothing but the envelope.
    const good = await makeEnvelope(phone, nodeKey(node), "x");
    for (const bad of [
      { ...good, v: 2 },
      { ...good, id: "short" },
      { ...good, at: "now" },
      { ...good, ct: "not base64!" },
      { ...good, sig: "x" },
      { ...good, extra: "plaintext" },
    ]) {
      expect(await sendEnv(phoneSock, bad)).toMatchObject({ t: "refused", code: "invalid" });
    }
    expect(await sendEnv(phoneSock, good)).toMatchObject({ t: "queued" });
    phoneSock.close();
    nodeSock.close();
  });

  it("closes a socket whose first frame isn't hello (4400)", async () => {
    const node = await newNode();
    const sock = await openPhoneSocket(node);
    sock.send({ t: "ack", through: 1 });
    expect(await sock.closed).toBe(4400);
    const sock2 = await openPhoneSocket(node);
    sock2.send("not json");
    expect(await sock2.closed).toBe(4400);
  });

  it("answers ping with pong without a hello", async () => {
    const node = await newNode();
    const sock = await openPhoneSocket(node);
    sock.send("ping");
    expect(await sock.next()).toEqual({ t: "text", text: "pong" });
    sock.close();
  });

  it("replaces an older socket for the same device (4409)", async () => {
    const node = await newNode();
    const first = await openPhoneSocket(node);
    await first.hello(0);
    const second = await openPhoneSocket(node);
    expect(await first.closed).toBe(4409);
    expect(await second.hello(0)).toMatchObject({ t: "ready" });
    second.close();
  });
});

describe("resume", () => {
  it("keeps what a node missed, in order, and resumes after what it acknowledged", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const phoneSock = await openPhoneSocket(phone);
    await phoneSock.hello(0);
    const sent = [];
    for (let i = 0; i < 3; i++) {
      const e = await makeEnvelope(phone, nodeKey(node), `m${i}`);
      sent.push({ env: e, q: await sendEnv(phoneSock, e) });
    }
    // A resend with the same id is answered with the seq it has, not stored twice.
    expect(await sendEnv(phoneSock, sent[1]!.env)).toEqual(sent[1]!.q);

    let nodeSock = await openPhoneSocket(node);
    const ready = await nodeSock.hello(0);
    const sysSeq = (await nodeSock.nextOf("sys")).seq as number;
    expect(ready.after).toBe(0);
    expect(ready.head).toBe(sent[2]!.q.seq);
    const got = [await nodeSock.nextOf("msg"), await nodeSock.nextOf("msg"), await nodeSock.nextOf("msg")];
    expect(got.map((g) => (g.env as { id: string }).id)).toEqual(sent.map((s) => s.env.id));
    expect(got.map((g) => g.seq)).toEqual(sent.map((s) => s.q.seq));
    expect((await nodeSock.drain()).filter((f) => f.t === "msg")).toEqual([]);
    nodeSock.send({ t: "ack", through: got[1]!.seq });
    await nodeSock.drain();
    nodeSock.close();
    await nodeSock.closed;

    nodeSock = await openPhoneSocket(node);
    const again = await nodeSock.hello(got[1]!.seq as number);
    expect(again).toMatchObject({ after: got[1]!.seq, head: got[2]!.seq });
    const only = await nodeSock.nextOf("msg");
    expect(only.seq).toBe(got[2]!.seq);
    expect((await nodeSock.drain()).filter((f) => f.t === "msg" || f.t === "sys")).toEqual([]);
    expect(sysSeq).toBeLessThan(got[0]!.seq as number);

    // Acknowledged rows are gone; the rest wait.
    const rows = await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) =>
      state.storage.sql.exec<{ seq: number }>("SELECT seq FROM mailbox WHERE recipient = ? ORDER BY seq", node.deviceId).toArray().map((r) => r.seq),
    );
    expect(rows).toEqual([got[2]!.seq]);
    nodeSock.close();
    phoneSock.close();
  });

  it("drops a phone's oldest rows past its queue limit and reports a gap", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    await runInDurableObject(phoneObject(node.accountId), (o: PhoneObject) => {
      o.limitsOverride = { phoneRows: 3 };
    });
    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);
    const seqs: number[] = [];
    for (let i = 0; i < 5; i++) seqs.push((await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(phone), `m${i}`))).seq as number);

    const phoneSock = await openPhoneSocket(phone);
    const ready = await phoneSock.hello(0);
    expect(ready).toMatchObject({ after: 0, head: seqs[4] });
    expect(await phoneSock.next()).toEqual({ t: "gap", from: seqs[0], to: seqs[1] });
    for (const s of seqs.slice(2)) expect((await phoneSock.nextOf("msg")).seq).toBe(s);
    phoneSock.close();
    nodeSock.close();
  });

  it("drops rows past retention with the alarm, reported as a gap", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const phoneSock = await openPhoneSocket(phone);
    await phoneSock.hello(0);
    const seqs: number[] = [];
    for (let i = 0; i < 3; i++) seqs.push((await sendEnv(phoneSock, await makeEnvelope(phone, nodeKey(node), `m${i}`))).seq as number);
    phoneSock.close();
    const old = Date.now() - 8 * 24 * 3600_000;
    await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) => {
      // The pairing hello and the first two messages are past retention.
      state.storage.sql.exec("UPDATE mailbox SET at = ? WHERE recipient = ? AND seq <= ?", old, node.deviceId, seqs[1]!);
    });
    expect(await runDurableObjectAlarm(phoneObject(node.accountId))).toBe(true);
    const nodeSock = await openPhoneSocket(node);
    const ready = await nodeSock.hello(0);
    expect(ready).toMatchObject({ after: 0, head: seqs[2] });
    expect(await nodeSock.next()).toEqual({ t: "gap", from: 1, to: seqs[1] });
    expect((await nodeSock.next()).seq).toBe(seqs[2]);
    // Acknowledging past the gap forgets it.
    nodeSock.send({ t: "ack", through: seqs[2] });
    await nodeSock.drain();
    nodeSock.close();
    const left = await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) => ({
      rows: state.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM mailbox").one().n,
      gaps: state.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM device_gaps").one().n,
    }));
    expect(left).toEqual({ rows: 0, gaps: 0 });
  });
});

describe("presence", () => {
  it("says who is online in ready, and sends presence when a peer comes and goes", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const nodeSock = await openPhoneSocket(node);
    const r1 = await nodeSock.hello(0);
    expect(r1.peers).toEqual([{ device: phone.deviceId, online: false, since: null }]);

    const phoneSock = await openPhoneSocket(phone);
    const r2 = await phoneSock.hello(0);
    expect(r2.peers).toEqual([{ device: node.deviceId, online: true, since: expect.any(Number) }]);
    const on = await nodeSock.nextOf("presence");
    expect(on).toMatchObject({ device: phone.deviceId, online: true, since: expect.any(Number) });

    phoneSock.close();
    await phoneSock.closed;
    const off = await nodeSock.nextOf("presence");
    expect(off).toMatchObject({ device: phone.deviceId, online: false, since: expect.any(Number) });
    const listed = (await (await signed(node, "GET", "/v1/phone/devices")).json()) as { phones: { online: boolean }[] };
    expect(listed.phones[0]!.online).toBe(false);
    nodeSock.close();
  });
});

describe("limits", () => {
  it("rate limits a phone's frames (30 at once, then 1 a second; the hello spends one)", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const sock = await openPhoneSocket(phone);
    await sock.hello(0);
    const envs = [];
    for (let i = 0; i < 40; i++) envs.push(await makeEnvelope(phone, nodeKey(node), `m${i}`));
    for (const e of envs) sock.send({ t: "send", env: e });
    const answers: Frame[] = [];
    while (answers.length < 40) {
      const f = await sock.next();
      if (f.t === "queued" || f.t === "refused") answers.push(f);
    }
    expect(answers.slice(0, 29).every((a) => a.t === "queued")).toBe(true);
    const limited = answers.filter((a) => a.t === "refused");
    expect(limited.length).toBeGreaterThan(0);
    expect(limited[0]).toMatchObject({ code: "rate_limited", retryAfter: expect.any(Number) });
    sock.close();
  });

  it("refuses a phone's send when its node's queue is full", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    await runInDurableObject(phoneObject(node.accountId), (o: PhoneObject) => {
      // The pairing hello is one row already.
      o.limitsOverride = { nodeRows: 3 };
    });
    const sock = await openPhoneSocket(phone);
    await sock.hello(0);
    expect(await sendEnv(sock, await makeEnvelope(phone, nodeKey(node), "a"))).toMatchObject({ t: "queued" });
    expect(await sendEnv(sock, await makeEnvelope(phone, nodeKey(node), "b"))).toMatchObject({ t: "queued" });
    expect(await sendEnv(sock, await makeEnvelope(phone, nodeKey(node), "c"))).toMatchObject({ t: "refused", code: "queue_full" });
    sock.close();
  });

  it("carries an envelope's push field as sent and pushes nothing for it (PROTOCOL §10.7)", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    try {
      const nodeSock = await openPhoneSocket(node);
      await nodeSock.hello(0);
      // The phone is offline: the old hook would have fired here. Now nothing does.
      const tagged = await makeEnvelope(node, phoneKey(phone), "a", { push: "approval" });
      expect(await sendEnv(nodeSock, tagged)).toMatchObject({ t: "queued" });
      const phoneSock = await openPhoneSocket(phone);
      await phoneSock.hello(0);
      const got = await phoneSock.nextOf("msg");
      expect(JSON.stringify(got.env)).toBe(JSON.stringify(tagged));
      expect(fetchSpy).not.toHaveBeenCalled();
      const pushes = await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) =>
        state.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM pushes").one().n,
      );
      expect(pushes).toBe(0);
      phoneSock.close();
      nodeSock.close();
    } finally {
      fetchSpy.mockRestore();
    }
  });
});

describe("revocation", () => {
  it("revoking a phone closes its socket (4401), refuses it after, and tells its node", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);
    await nodeSock.nextOf("sys");
    const phoneSock = await openPhoneSocket(phone);
    await phoneSock.hello(0);
    await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(phone), "queued for the phone"));

    expect((await signed(node, "DELETE", `/v1/devices/${phone.deviceId}`)).status).toBe(204);
    expect(await phoneSock.closed).toBe(4401);
    expect((await signed(phone, "GET", "/v1/phone/socket", undefined, { headers: { Upgrade: "websocket" } })).status).toBe(401);
    const sys = await nodeSock.nextOf("sys");
    expect(sys.sys).toMatchObject({ kind: "unpaired", device: phone.deviceId });
    // Idempotent: again is 204, and the node isn't told twice.
    expect((await signed(node, "DELETE", `/v1/devices/${phone.deviceId}`)).status).toBe(204);
    expect((await nodeSock.drain()).filter((f) => f.t === "sys")).toEqual([]);
    // The phone's queue is gone.
    const rows = await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) =>
      state.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM mailbox WHERE recipient = ?", phone.deviceId).one().n,
    );
    expect(rows).toBe(0);
    nodeSock.close();
  });

  it("a phone unpairs itself, pending or not, and its node is told", async () => {
    const node = await newNode();
    const phone = await pairPhone(node, { confirm: false });
    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);
    await nodeSock.nextOf("sys");
    const phoneSock = await openPhoneSocket(phone);
    await phoneSock.hello(0);

    expect((await signed(phone, "DELETE", "/v1/phone/self")).status).toBe(204);
    expect(await phoneSock.closed).toBe(4401);
    expect((await nodeSock.nextOf("sys")).sys).toMatchObject({ kind: "unpaired", device: phone.deviceId });
    expect((await signed(phone, "DELETE", "/v1/phone/self")).status).toBe(401);
    const row = await env.DB.prepare("SELECT revoked_at FROM devices WHERE id = ?").bind(phone.deviceId).first<{ revoked_at: number | null }>();
    expect(row!.revoked_at).not.toBeNull();
    nodeSock.close();
  });

  it("revoking a node revokes its phones", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const pending = await pairPhone(node, { confirm: false, name: "iPad" });
    const other = await enrolDevice(node, "desktop");
    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);
    const phoneSock = await openPhoneSocket(phone);
    await phoneSock.hello(0);
    const leftover = await registerPairing(node);

    expect((await signed(other, "DELETE", `/v1/devices/${node.deviceId}`)).status).toBe(204);
    expect(await phoneSock.closed).toBe(4401);
    expect(await nodeSock.closed).toBe(4401);
    for (const p of [phone, pending]) {
      expect((await signed(p, "GET", "/v1/phone/socket", undefined, { headers: { Upgrade: "websocket" } })).status).toBe(401);
    }
    const { results } = await env.DB.prepare("SELECT id FROM devices WHERE account_id = ? AND revoked_at IS NULL").bind(node.accountId).all<{ id: string }>();
    expect(results.map((r) => r.id)).toEqual([other.deviceId]);
    // Its unused pairing can't be redeemed any more.
    expect((await redeemPhone(node, leftover)).res.status).toBe(401);
    // Idempotent.
    expect((await signed(other, "DELETE", `/v1/devices/${node.deviceId}`)).status).toBe(204);
  });
});
