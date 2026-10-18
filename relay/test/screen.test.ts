// The screen at the edge (PROTOCOL §4b): the shared vectors, rules on origin, headers and size,
// fingerprints and keyed field rules synced from a device, words only with consent, the hold
// (not streamed until released, released once, dropped), drops answered 200 with nothing stored,
// forgeries still 401, and nothing kept but hashes.

import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import screenVectors from "../../fixtures/screen.v1.json";
import type { AccountObject } from "../src/account-object.ts";
import { fromBase64, hmac, toHex, utf8 } from "../src/encoding.ts";
import { hostedExtras } from "../src/held.ts";
import {
  decodeSignature,
  domainOf,
  domainSuffixes,
  edgeSafePattern,
  encodeSignature,
  fold,
  itemText,
  keyedHash,
  murmur3,
  parsePayload,
  parseScreen,
  shapeHash,
  signatureOf,
  similarity,
  tokens,
} from "../src/screen.ts";
import {
  accountObject,
  createHook,
  data,
  fetchRelay,
  newAccount,
  openEvent,
  openStream,
  signed,
  type SseReader,
  type StreamedEvent,
  type TestDevice,
} from "./helpers.ts";

const TEMPLATE =
  "Dear customer, congratulations! Your account has been selected for an exclusive reward. To receive your free crypto wallet " +
  "worth 5000 dollars, confirm your details at the link below within twenty four hours. This offer is only available to a small " +
  "number of our most valued customers, and it will expire tonight at midnight. Do not reply to this message; our team cannot " +
  "read replies. Thank you for being with us, and enjoy your reward from the rewards department.";

const junk = (name: string) => ({ message: { text: TEMPLATE.replace("Dear customer", `Dear ${name}`), from: "promo@mail.deals.example" } });

function post(hookId: string, payload: unknown, init: { headers?: Record<string, string>; cf?: Record<string, unknown> } = {}) {
  return fetchRelay(`/h/${hookId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...init.headers },
    body: typeof payload === "string" ? payload : JSON.stringify(payload),
    ...(init.cf ? { cf: init.cf } : {}),
  } as RequestInit);
}

async function setScreen(dev: TestDevice, hookId: string, screen: unknown): Promise<Response> {
  return signed(dev, "PUT", `/v1/hooks/${hookId}/screen`, { screen });
}

async function stats(dev: TestDevice) {
  return accountObject(dev.accountId).stats();
}

async function key(dev: TestDevice): Promise<Uint8Array<ArrayBuffer>> {
  const res = await signed(dev, "GET", "/v1/screen/key");
  expect(res.status).toBe(200);
  return fromBase64(((await res.json()) as { key: string }).key)!;
}

async function nextHook(sse: SseReader): Promise<StreamedEvent> {
  for (;;) {
    const f = await sse.nextEvent();
    if (f?.event === "hook") return data<StreamedEvent>(f);
    if (f === null) throw new Error("stream ended");
  }
}

/** Every value in every table of the account's object, as text. */
async function everything(dev: TestDevice): Promise<string> {
  return runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) => {
    const tables = state.storage.sql
      .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_cf%' AND name NOT LIKE 'sqlite%'")
      .toArray();
    let out = "";
    for (const t of tables) {
      for (const row of state.storage.sql.exec(`SELECT * FROM ${t.name}`).toArray()) {
        for (const v of Object.values(row)) out += v instanceof ArrayBuffer ? new TextDecoder().decode(v) : String(v);
        out += "\n";
      }
    }
    return out;
  });
}

describe("the shared vectors", () => {
  it("words, shapes, signatures, domains, keyed hashes and safe patterns match the harness", async () => {
    for (const m of screenVectors.murmur) expect(murmur3(utf8(m.text)), m.text).toBe(m.hash);
    for (const it of screenVectors.items) {
      const payload = parsePayload(utf8(it.body), it.contentType);
      expect(itemText(payload), it.name).toBe(it.text);
      expect(tokens(it.text), it.name).toEqual(it.tokens);
      expect(await shapeHash(payload), it.name).toBe(it.shape);
      const sig = signatureOf(it.text);
      expect(sig ? encodeSignature(sig) : null, it.name).toBe(it.signature);
    }
    const byName = Object.fromEntries(screenVectors.items.map((i) => [i.name, i.signature]));
    for (const s of screenVectors.similar) {
      expect(similarity(decodeSignature(byName[s.a]!)!, decodeSignature(byName[s.b]!)!)).toBe(s.similarity);
    }
    for (const d of screenVectors.domains) {
      expect(domainOf(d.value)).toBe(d.domain);
      expect(domainSuffixes(d.domain)).toEqual(d.suffixes);
    }
    const k = fromBase64(screenVectors.screenKey)!;
    for (const h of screenVectors.fieldHashes) {
      const n = h.op === "domain_is" ? domainOf(h.value) : fold(h.value);
      expect(n).toBe(h.normalised);
      expect(await keyedHash(k, h.path, n)).toBe(h.hash);
    }
    for (const p of screenVectors.edgePatterns) expect(edgeSafePattern(p.pattern), p.pattern).toBe(p.edge);
  });
});

describe("pushing a screen", () => {
  it("is checked, needs consent for words, and is kept as hashes", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const k = await key(dev);
    const words = { id: "w", verdict: "drop", conditions: [{ on: "field", path: "payload.message.text", op: "contains", words: "free crypto" }] };
    const refused = await setScreen(dev, hook.id, { rules: [words] });
    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({ field: "screen.consent" });
    expect((await setScreen(dev, hook.id, { rules: [{ id: "p", verdict: "drop", conditions: [{ on: "field", path: "payload.t", op: "pattern", pattern: "(a+)+$" }] }], consent: { words: true } })).status).toBe(400);
    expect((await setScreen(dev, hook.id, { rules: [{ id: "x", verdict: "maybe", conditions: [{ on: "size", op: "gt", bytes: 1 }] }] })).status).toBe(400);
    expect((await setScreen(dev, hook.id, { rules: [{ id: "x", verdict: "drop", conditions: [{ on: "ip", in: ["10.0.0.0/33"] }] }] })).status).toBe(400);
    const tooMany = Array.from({ length: 201 }, (_, i) => ({ id: `r${i}`, verdict: "drop", conditions: [{ on: "size", op: "gt", bytes: 1 }] }));
    expect((await setScreen(dev, hook.id, { rules: tooMany })).status).toBe(400);

    const hashed = await keyedHash(k, "payload.message.from", "promo@mail.deals.example");
    const ok = await setScreen(dev, hook.id, {
      rules: [{ id: "promo", verdict: "drop", conditions: [{ on: "field", path: "payload.message.from", op: "is", hashes: [hashed] }] }, words],
      consent: { words: true },
    });
    expect(ok.status).toBe(200);
    const kept = await env.DB.prepare("SELECT screen FROM hooks WHERE id = ?").bind(hook.id).first<{ screen: string }>();
    expect(kept!.screen).toContain(hashed);
    expect(kept!.screen).not.toContain("promo@mail");
    const got = (await (await signed(dev, "GET", `/v1/hooks/${hook.id}/screen`)).json()) as { screen: { consent: { words: boolean } } };
    expect(got.screen.consent.words).toBe(true);
    expect(((await (await signed(dev, "GET", `/v1/hooks/${hook.id}`)).json()) as { screenRules: number }).screenRules).toBe(2);
    // Removing it.
    expect(await (await setScreen(dev, hook.id, null)).json()).toEqual({ screen: null });
    // Another account's hook is not found.
    const other = await newAccount();
    expect((await setScreen(other, hook.id, null)).status).toBe(404);
  });

  it("an API key needs hooks:write to push and events:read to list the hold; the key is a device's", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const make = async (scopes: string[]) =>
      ((await (await signed(dev, "POST", "/v1/keys", { name: "ci", scopes })).json()) as { token: string }).token;
    const writer = await make(["hooks:write"]);
    const reader = await make(["hooks:read"]);
    const as = (token: string, method: string, path: string, body?: unknown) =>
      fetchRelay(path, { method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
    expect((await as(writer, "PUT", `/v1/hooks/${hook.id}/screen`, { screen: null })).status).toBe(200);
    expect((await as(reader, "PUT", `/v1/hooks/${hook.id}/screen`, { screen: null })).status).toBe(403);
    expect((await as(reader, "GET", "/v1/held")).status).toBe(403);
    expect((await as(writer, "GET", "/v1/screen/key")).status).toBe(403);
  });
});

describe("edge rules", () => {
  it("drop by address, network, country, header and size: 200 to the sender, nothing stored", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const rules = [
      { id: "addr", verdict: "drop", conditions: [{ on: "ip", in: ["198.51.100.0/24"] }] },
      { id: "asn", verdict: "drop", conditions: [{ on: "asn", in: [64500] }] },
      { id: "country", verdict: "drop", conditions: [{ on: "country", in: ["xx"] }] },
      { id: "header", verdict: "drop", conditions: [{ on: "header", name: "X-Kind", op: "is", value: "PROMO" }] },
      { id: "size", verdict: "drop", conditions: [{ on: "size", op: "gt", bytes: 2000 }] },
    ];
    expect((await setScreen(dev, hook.id, { rules })).status).toBe(200);
    const cases: [string, Parameters<typeof post>[2], unknown][] = [
      ["addr", { headers: { "CF-Connecting-IP": "198.51.100.7" } }, { a: 1 }],
      ["asn", { cf: { asn: 64500, country: "NL" } }, { a: 1 }],
      ["country", { cf: { asn: 1, country: "XX" } }, { a: 1 }],
      ["header", { headers: { "X-Kind": " promo " } }, { a: 1 }],
      ["size", {}, { big: "x".repeat(3000) }],
    ];
    for (const [name, init, body] of cases) {
      const res = await post(hook.id, body, init);
      expect(res.status, name).toBe(200);
      // Answered like any delivery: the sender can't tell.
      expect(((await res.json()) as { received: string }).received, name).toMatch(/^evt_/);
    }
    expect((await stats(dev)).events).toBe(0);
    expect((await stats(dev)).held).toBe(0);
    // Something else passes and is stored.
    const ok = await post(hook.id, { a: 1 }, { headers: { "CF-Connecting-IP": "203.0.113.1" }, cf: { asn: 1, country: "NL" } });
    expect(ok.status).toBe(200);
    expect((await stats(dev)).events).toBe(1);
    // Counted per hook, never stored.
    const audit = (await (await signed(dev, "GET", "/v1/audit")).json()) as { entries: { kind: string; subject: string; count?: number; actor: unknown }[] };
    expect(audit.entries.find((e) => e.kind === "screen.dropped")).toMatchObject({ subject: hook.id, count: 5, actor: null });
  });

  it("an allow rule above a drop wins, and `not` makes an allow list (a provider's published ranges)", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    await setScreen(dev, hook.id, {
      rules: [
        { id: "office", verdict: "pass", conditions: [{ on: "ip", in: ["203.0.113.5"] }] },
        { id: "not-github", verdict: "drop", conditions: [{ on: "ip", in: ["192.30.252.0/22", "2a0a:a440::/29"], not: true, preset: "github" }] },
      ],
    });
    const from = (ip: string) => post(hook.id, { a: 1 }, { headers: { "CF-Connecting-IP": ip } });
    await from("203.0.113.5");
    await from("192.30.252.9");
    await from("2a0a:a440::1");
    await from("::ffff:192.30.252.10");
    expect((await stats(dev)).events).toBe(4);
    await from("198.51.100.1");
    await from("2001:db8::1");
    expect((await stats(dev)).events).toBe(4);
  });

  it("keyed field rules (is, domain is, one of) match without the relay holding the values", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const k = await key(dev);
    await setScreen(dev, hook.id, {
      rules: [
        { id: "domain", verdict: "drop", conditions: [{ on: "field", path: "payload.message.from", op: "domain_is", hashes: [await keyedHash(k, "payload.message.from", "deals.example")] }] },
        { id: "sku", verdict: "drop", conditions: [{ on: "field", path: "payload.items[].sku", op: "one_of", hashes: [await keyedHash(k, "payload.items[].sku", "bad-1"), await keyedHash(k, "payload.items[].sku", "bad-2")] }] },
        { id: "topic", verdict: "drop", conditions: [{ on: "field", path: "headers.x-topic", op: "is", hashes: [await keyedHash(k, "headers.x-topic", "spam")] }] },
      ],
    });
    await post(hook.id, { message: { from: "x@deals.example" } });
    await post(hook.id, { message: { from: "x@news.deals.example" } });
    await post(hook.id, { items: [{ sku: "ok" }, { sku: "BAD-2" }] });
    await post(hook.id, { a: 1 }, { headers: { "X-Topic": " Spam" } });
    expect((await stats(dev)).events).toBe(0);
    await post(hook.id, { message: { from: "x@nodeals.example" } });
    await post(hook.id, { items: [{ sku: "ok" }] });
    expect((await stats(dev)).events).toBe(2);
    // Another account's key makes other hashes: its rules can't be replayed here.
    const other = await newAccount();
    expect(toHex(await key(other))).not.toBe(toHex(k));
  });

  it("words rules (contains, pattern, similar text) work once consented", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    await setScreen(dev, hook.id, {
      consent: { words: true },
      rules: [
        { id: "phrase", verdict: "drop", conditions: [{ on: "field", path: "payload.note", op: "contains", words: "Free Crypto" }] },
        { id: "link", verdict: "drop", conditions: [{ on: "field", path: "payload.order.note", op: "pattern", pattern: "bit\\.ly/\\w+" }] },
        { id: "like", verdict: "drop", conditions: [{ on: "field", path: "payload.message.text", op: "similar_text", signature: encodeSignature(signatureOf(TEMPLATE)!), threshold: 0.8 }] },
      ],
    });
    await post(hook.id, { note: "get free crypto now" });
    await post(hook.id, { order: { note: "see bit.ly/abc" } });
    await post(hook.id, junk("Ana"));
    expect((await stats(dev)).events).toBe(0);
    await post(hook.id, { note: "crypto free" });
    await post(hook.id, { message: { text: "Your order shipped and arrives on Tuesday." } });
    expect((await stats(dev)).events).toBe(2);
  });

  it("a flood of near-identical junk is dropped at the edge after one Drop + Always", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    // What a device pushes after Drop + "Always drop similar": the first item's fingerprint.
    const first = junk("Ana");
    const fp = { on: "similar", shape: await shapeHash(first), text: encodeSignature(signatureOf(itemText(first))!), threshold: 0.8 };
    expect((await setScreen(dev, hook.id, { rules: [{ id: "lr_0123456789abcdef", verdict: "drop", conditions: [fp] }] })).status).toBe(200);
    for (const name of ["Rui", "Lena", "Sam", "Ben", "Ana Maria", "Jo", "Kim", "Lee", "Max", "Noa"]) {
      expect((await post(hook.id, junk(name))).status).toBe(200);
    }
    const s = await stats(dev);
    expect(s.events).toBe(0);
    expect(s.held).toBe(0);
    // Something of the same shape but other words passes.
    await post(hook.id, { message: { text: "Your order 1234 has shipped and arrives on Tuesday. Thank you for shopping with us.", from: "shop@example.com" } });
    expect((await stats(dev)).events).toBe(1);
  });

  it("a forged signature is still 401, even where a rule would drop everything", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "github", secret: "a-github-secret-0001" });
    await setScreen(dev, hook.id, { rules: [{ id: "all", verdict: "drop", conditions: [{ on: "size", op: "gt", bytes: 0 }] }] });
    const forged = await post(hook.id, { a: 1 }, { headers: { "X-Hub-Signature-256": "sha256=" + "0".repeat(64), "X-GitHub-Event": "push" } });
    expect(forged.status).toBe(401);
    const body = JSON.stringify({ a: 1 });
    const sig = "sha256=" + toHex(await hmac("SHA-256", utf8("a-github-secret-0001"), utf8(body)));
    const genuine = await post(hook.id, body, { headers: { "X-Hub-Signature-256": sig, "X-GitHub-Event": "push", "X-GitHub-Delivery": crypto.randomUUID() } });
    expect(genuine.status).toBe(200);
    expect((await stats(dev)).events).toBe(0);
  });

  it("a strict hook's body is never read: body rules don't hold, origin rules do", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "github", strict: true });
    await setScreen(dev, hook.id, {
      rules: [
        { id: "like", verdict: "drop", conditions: [{ on: "similar", shape: await shapeHash({ a: 1 }) }] },
        { id: "addr", verdict: "drop", conditions: [{ on: "ip", in: ["198.51.100.0/24"] }] },
      ],
    });
    const headers = { "X-Hub-Signature-256": "sha256=" + "a".repeat(64), "X-GitHub-Event": "push" };
    expect((await post(hook.id, { a: 1 }, { headers })).status).toBe(200);
    expect((await stats(dev)).events).toBe(1);
    await post(hook.id, { a: 2 }, { headers: { ...headers, "CF-Connecting-IP": "198.51.100.3" } });
    expect((await stats(dev)).events).toBe(1);
  });
});

describe("the hold", () => {
  it("keeps a quarantined event aside, unstreamed, until it is released once", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    await setScreen(dev, hook.id, {
      rules: [{ id: "doubtful", verdict: "quarantine", conditions: [{ on: "header", name: "x-kind", op: "is", value: "doubtful" }] }],
    });
    const { sse } = await openStream(dev);
    await sse.nextEvent(); // ready
    const heldRes = await post(hook.id, { secret: "HELD-MARKER-7731" }, { headers: { "X-Kind": "doubtful", "CF-Connecting-IP": "203.0.113.44" }, cf: { asn: 64501, country: "PT" } });
    const heldId = ((await heldRes.json()) as { received: string }).received;
    expect(heldId).toMatch(/^evt_/);
    await post(hook.id, { plain: "PASSED-MARKER" });
    // Only the passed one is streamed.
    const firstSeen = await nextHook(sse);
    expect((await openEvent(dev, firstSeen)).text).toContain("PASSED-MARKER");
    expect(firstSeen.held).toBeUndefined();

    const listed = (await (await signed(dev, "GET", "/v1/held")).json()) as { held: Record<string, unknown>[] };
    expect(listed.held).toHaveLength(1);
    expect(listed.held[0]).toMatchObject({ id: heldId, hookId: hook.id, rule: "doubtful", verified: false });
    expect(JSON.stringify(listed)).not.toContain("HELD-MARKER");
    // The relay keeps ciphertext only.
    expect(await everything(dev)).not.toContain("HELD-MARKER");

    const rel = await signed(dev, "POST", `/v1/held/${heldId}/release`);
    expect(rel.status).toBe(200);
    expect(await rel.json()).toMatchObject({ released: heldId, seq: 2 });
    const released = await nextHook(sse);
    expect(released).toMatchObject({ id: heldId, seq: 2, held: true });
    const opened = await openEvent(dev, released);
    expect(opened.text).toContain("HELD-MARKER-7731");
    // The origin the edge saw travels sealed, for the device's own screen.
    expect(opened.origin).toEqual({ ip: "203.0.113.44", asn: 64501, country: "PT" });
    await sse.cancel();
    // Released once.
    expect((await signed(dev, "POST", `/v1/held/${heldId}/release`)).status).toBe(404);
    expect(((await (await signed(dev, "GET", "/v1/held")).json()) as { held: unknown[] }).held).toHaveLength(0);
    // A resumed stream replays it like any event, still marked and still opening.
    const again = await openStream(dev, 1);
    await again.sse.nextEvent();
    const replayed = await nextHook(again.sse);
    expect(replayed.held).toBe(true);
    expect((await openEvent(dev, replayed)).text).toContain("HELD-MARKER-7731");
    await again.sse.cancel();
  });

  it("a held event that's dropped is never streamed, and one past its wait goes by itself", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    await setScreen(dev, hook.id, { rules: [{ id: "all", verdict: "quarantine", conditions: [{ on: "size", op: "gt", bytes: 0 }] }] });
    const a = ((await (await post(hook.id, { n: 1 })).json()) as { received: string }).received;
    await post(hook.id, { n: 2 });
    expect((await stats(dev)).held).toBe(2);
    // The hold is counted apart from the log (PROTOCOL §4b): held events never fill it.
    expect((await stats(dev)).usage.events).toBe(0);
    expect((await stats(dev)).heldUsage.events).toBe(2);
    expect((await signed(dev, "DELETE", `/v1/held/${a}`)).status).toBe(204);
    expect((await signed(dev, "DELETE", `/v1/held/${a}`)).status).toBe(404);
    expect((await stats(dev)).held).toBe(1);
    expect((await stats(dev)).heldUsage.events).toBe(1);
    // Past the wait (7 days by default): the alarm drops it.
    await runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) => {
      state.storage.sql.exec("UPDATE held_events SET received_at = received_at - ?", 8 * 86_400_000);
    });
    await runDurableObjectAlarm(accountObject(dev.accountId));
    const s = await stats(dev);
    expect(s.held).toBe(0);
    expect(s.usage).toEqual({ events: 0, bytes: 0 });
    expect(s.heldUsage).toEqual({ events: 0, bytes: 0 });
    expect(s.head).toBe(0);
  });

  it("a duplicate of a held delivery isn't held twice", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "github", secret: "a-github-secret-0002" });
    await setScreen(dev, hook.id, { rules: [{ id: "all", verdict: "quarantine", conditions: [{ on: "size", op: "gt", bytes: 0 }] }] });
    const body = JSON.stringify({ a: 1 });
    const sig = "sha256=" + toHex(await hmac("SHA-256", utf8("a-github-secret-0002"), utf8(body)));
    const headers = { "X-Hub-Signature-256": sig, "X-GitHub-Event": "push", "X-GitHub-Delivery": "d-1" };
    expect((await post(hook.id, body, { headers })).status).toBe(200);
    expect(await (await post(hook.id, body, { headers })).json()).toEqual({ duplicate: true });
    expect((await stats(dev)).held).toBe(1);
  });
});

describe("what /v1/info announces", () => {
  it("the screen, and hosted extras only as the operator lists them", async () => {
    const info = (await (await fetchRelay("/v1/info")).json()) as Record<string, unknown>;
    expect(info.screen).toEqual({ edge: true, maxRules: 200, heldDays: 7 });
    expect(info.extras).toEqual([]);
    expect(
      hostedExtras(
        JSON.stringify([
          { id: "fingerprint-sync", title: "Fingerprint sync", description: "Across your devices", url: "https://relay.example/sync" },
          { id: "Bad Id", title: "x" },
          { id: "longer-hold", title: "Longer hold", url: "http://insecure.example" },
          "nonsense",
        ]),
      ),
    ).toEqual([
      { id: "fingerprint-sync", title: "Fingerprint sync", description: "Across your devices", url: "https://relay.example/sync" },
      { id: "longer-hold", title: "Longer hold" },
    ]);
    expect(hostedExtras("{not json")).toEqual([]);
  });
});

describe("parseScreen", () => {
  it("normalises what it keeps", () => {
    const s = parseScreen({ rules: [{ id: "a", verdict: "drop", conditions: [{ on: "country", in: ["pt"] }, { on: "header", name: "X-A", op: "contains", value: " Foo " }] }] });
    expect(s!.rules[0]!.conditions).toEqual([
      { on: "country", in: ["PT"] },
      { on: "header", name: "x-a", op: "contains", value: "foo" },
    ]);
    expect(s!.consent.words).toBe(false);
  });
});
