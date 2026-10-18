// The screen's bounds (PROTOCOL §4b): what one delivery can make the edge do is capped whatever the
// screen and the payload. Domains are read up to 253 bytes and 127 labels; patterns run in linear
// time from a checked subset; a path reads at most 64 values; a delivery hashes at most 256 KiB and
// takes a bounded number of pattern steps, past which it is held (`~over-budget`); and a screen is
// compiled once per isolate.

import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { fromBase64 } from "../src/encoding.ts";
import { codePoints, compilePattern, MAX_WEIGHT, patternWeight, type Steps } from "../src/screen-pattern.ts";
import {
  cachedScreens,
  compileScreen,
  decide,
  domainSuffixes,
  importScreenKey,
  keyedHash,
  MAX_CACHED_SCREENS,
  MAX_SCREEN_STEPS,
  OVER_BUDGET_RULE,
  parseScreen,
  screenFor,
  valuesAt,
  type Delivery,
  type EdgeScreen,
} from "../src/screen.ts";
import { accountObject, createHook, fetchRelay, newAccount, signed, type TestDevice } from "./helpers.ts";

function post(hookId: string, payload: unknown, headers: Record<string, string> = {}) {
  return fetchRelay(`/h/${hookId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(payload),
  });
}

const setScreen = (dev: TestDevice, hookId: string, screen: unknown) => signed(dev, "PUT", `/v1/hooks/${hookId}/screen`, { screen });

async function key(dev: TestDevice): Promise<Uint8Array<ArrayBuffer>> {
  const res = await signed(dev, "GET", "/v1/screen/key");
  return fromBase64(((await res.json()) as { key: string }).key)!;
}

const stats = (dev: TestDevice) => accountObject(dev.accountId).stats();

describe("domain_is", () => {
  it("reads a domain of at most 253 bytes and 127 labels; a longer one never matches", async () => {
    expect(domainSuffixes(`${"a.".repeat(126)}a`)).toHaveLength(127);
    expect(domainSuffixes(`${"a.".repeat(127)}a`)).toEqual([]);
    expect(domainSuffixes("x".repeat(253))).toEqual(["x".repeat(253)]);
    expect(domainSuffixes("x".repeat(254))).toEqual([]);
    expect(domainSuffixes("é".repeat(127))).toEqual([]); // 254 bytes

    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const k = await key(dev);
    const hashes = [await keyedHash(k, "payload.from", "example")];
    expect((await setScreen(dev, hook.id, { rules: [{ id: "d", verdict: "drop", conditions: [{ on: "field", path: "payload.from", op: "domain_is", hashes }] }] })).status).toBe(200);
    await post(hook.id, { from: "x@mail.example" });
    expect((await stats(dev)).events).toBe(0);
    await post(hook.id, { from: `x@${"a.".repeat(130)}example` });
    expect((await stats(dev)).events).toBe(1);
    // Many labels and trailing dots cost a delivery next to nothing.
    const started = Date.now();
    expect((await post(hook.id, { from: `x@${"a.".repeat(40_000)}example${".".repeat(40_000)}` })).status).toBe(200);
    expect((await post(hook.id, { from: `${".".repeat(80_000)}x` })).status).toBe(200);
    // Generous, for a loaded machine: before the fix this took minutes.
    expect(Date.now() - started).toBeLessThan(10_000);
    expect((await stats(dev)).events).toBe(3);
  }, 30_000);
});

describe("patterns", () => {
  it("run in linear time: what backtracks for ever elsewhere is quick here", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const n = 28;
    const rules = [
      { id: "opt", verdict: "drop", conditions: [{ on: "field", path: "payload.a", op: "pattern", pattern: `^${"a?".repeat(n)}${"a".repeat(n)}$` }] },
      { id: "poly", verdict: "drop", conditions: [{ on: "field", path: "payload.b", op: "pattern", pattern: "\\w{0,60}\\w{0,60}\\w{0,60}!" }] },
      { id: "cubic", verdict: "drop", conditions: [{ on: "field", path: "payload.c", op: "pattern", pattern: ".*@.*\\.ru" }] },
    ];
    expect((await setScreen(dev, hook.id, { rules, consent: { words: true } })).status).toBe(200);
    const started = Date.now();
    await post(hook.id, { a: "a".repeat(n) });
    await post(hook.id, { b: "a".repeat(5000) });
    await post(hook.id, { c: "@".repeat(5000) });
    // Generous, for a loaded machine: a backtracking engine takes minutes on these.
    expect(Date.now() - started).toBeLessThan(10_000);
    // The first matched and was dropped; the other two didn't match.
    expect((await stats(dev)).events).toBe(2);
  }, 30_000);

  it("take steps in proportion to the program's size times the input, whatever the pattern", () => {
    for (const p of ["(a+)+$", ".*@.*\\.ru", "(x+x+)+y", `^${"a?".repeat(28)}${"a".repeat(28)}$`, "(.{0,20}){0,10}z", "\\w{0,60}\\w{0,60}\\w{0,60}!", "(a*)*b", "(a|aa)+$"]) {
      const re = compilePattern(p);
      for (const input of ["a".repeat(2048), "@".repeat(2048), "x".repeat(2048), "ab".repeat(1024)]) {
        let steps = 0;
        const counter: Steps = { step: (k) => void (steps += k) };
        re.test(codePoints(input, 2048), counter);
        expect(steps, p).toBeLessThanOrEqual(2 * re.size * (input.length + 1));
      }
    }
  });

  it("the subset: weight, repeats and syntax are checked at the push", async () => {
    expect(patternWeight("\\w{250}")).toBe(MAX_WEIGHT);
    expect(() => patternWeight("\\w{251}")).toThrow(/at most 250/);
    expect(() => patternWeight("(\\w)\\1")).toThrow();
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const one = (pattern: string) => ({ on: "field", path: "payload.t", op: "pattern", pattern });
    const refused = await setScreen(dev, hook.id, { consent: { words: true }, rules: [{ id: "p", verdict: "drop", conditions: [one("a{2}{3}")] }] });
    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({ field: "screen.rules[0].conditions[0].pattern" });
    // The different patterns of one screen weigh at most 4,000 together.
    const heavy = (i: number) => `\\w{200}${i}`;
    const rules = (count: number) => Array.from({ length: count }, (_, i) => ({ id: `p${i}`, verdict: "drop", conditions: [one(heavy(i))] }));
    expect((await setScreen(dev, hook.id, { consent: { words: true }, rules: rules(19) })).status).toBe(200);
    const tooHeavy = await setScreen(dev, hook.id, { consent: { words: true }, rules: rules(20) });
    expect(tooHeavy.status).toBe(400);
    expect(await tooHeavy.json()).toMatchObject({ field: "screen.rules" });
    // The same pattern twice counts once.
    const same = Array.from({ length: 40 }, (_, i) => ({ id: `s${i}`, verdict: "drop", conditions: [one(heavy(0))] }));
    expect((await setScreen(dev, hook.id, { consent: { words: true }, rules: same })).status).toBe(200);
  });
});

describe("one delivery's work", () => {
  it("a path reads at most 64 values", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const k = await key(dev);
    const hashes = [await keyedHash(k, "payload.items[].sku", "bad-1")];
    await setScreen(dev, hook.id, { rules: [{ id: "sku", verdict: "drop", conditions: [{ on: "field", path: "payload.items[].sku", op: "one_of", hashes }] }] });
    const items = (at: number) => Array.from({ length: 100 }, (_, i) => ({ sku: i === at ? "bad-1" : `ok-${i}` }));
    await post(hook.id, { items: items(63) });
    expect((await stats(dev)).events).toBe(0);
    await post(hook.id, { items: items(64) });
    expect((await stats(dev)).events).toBe(1);
  });

  it("hashes at most 256 KiB, and holds what would need more (~over-budget)", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const k = await key(dev);
    // Paths that name the same field in different spellings hash it once each.
    const paths = Array.from({ length: 8 }, (_, i) => `payload${".".repeat(i + 1)}t`);
    const rules = await Promise.all(
      paths.map(async (path, i) => ({ id: `r${i}`, verdict: "drop", conditions: [{ on: "field", path, op: "is", hashes: [await keyedHash(k, path, "nothing")] }] })),
    );
    expect((await setScreen(dev, hook.id, { rules })).status).toBe(200);
    await post(hook.id, { t: "x".repeat(20_000) });
    expect((await stats(dev)).events).toBe(1);
    expect((await stats(dev)).held).toBe(0);
    await post(hook.id, { t: "x".repeat(40_000) });
    expect((await stats(dev)).held).toBe(1);
    const listed = (await (await signed(dev, "GET", "/v1/held")).json()) as { held: { rule: string }[] };
    expect(listed.held[0]!.rule).toBe("~over-budget");
  });

  it("takes a bounded number of pattern steps, and holds what would need more", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    const rules = [{ id: "heavy", verdict: "drop", conditions: [{ on: "field", path: "payload.l[]", op: "pattern", pattern: "\\w{0,60}\\w{0,60}\\w{0,60}!" }] }];
    expect((await setScreen(dev, hook.id, { consent: { words: true }, rules })).status).toBe(200);
    await post(hook.id, { l: ["a".repeat(2048)] });
    expect((await stats(dev)).events).toBe(1);
    await post(hook.id, { l: Array.from({ length: 64 }, (_, i) => `${i}${"a".repeat(2048)}`) });
    expect((await stats(dev)).held).toBe(1);
    expect((await stats(dev)).events).toBe(1);
  }, 30_000);

  it("values are read in document order, at most 64, and the walk is counted", () => {
    const payload = { a: [{ b: [1, 2] }, { c: 0 }, { b: [3, { x: 1 }, 4] }] };
    expect(valuesAt(payload, new Headers(), "payload.a[].b[]")).toEqual(["1", "2", "3", "4"]);
    expect(valuesAt(payload, new Headers(), "payload..a[].b[]", 3)).toEqual(["1", "2", "3"]);
    let visits = 0;
    valuesAt({ l: Array.from({ length: 1000 }, () => ({})) }, new Headers(), "payload.l[].x", 64, () => void visits++);
    expect(visits).toBe(1 + 1 + 1000);
  });
});

describe("the compiled screen", () => {
  const stored = (n: number) =>
    JSON.stringify(parseScreen({ rules: [{ id: "big", verdict: "drop", conditions: [{ on: "size", op: "gt", bytes: n }] }] }));

  it("is compiled once per isolate for a hook and its screen, and the cache is bounded", async () => {
    const a = await screenFor("hk_cache_a", stored(10));
    expect(await screenFor("hk_cache_a", stored(10))).toBe(a);
    // A new screen is a new entry; another hook with the same screen is its own.
    expect(await screenFor("hk_cache_a", stored(11))).not.toBe(a);
    expect(await screenFor("hk_cache_b", stored(10))).not.toBe(a);
    expect(await screenFor("hk_cache_a", null)).toBeNull();
    for (let i = 0; i < MAX_CACHED_SCREENS + 50; i++) await screenFor(`hk_fill_${i}`, stored(i));
    expect(cachedScreens()).toBeLessThanOrEqual(MAX_CACHED_SCREENS);
    // The oldest went first.
    expect(await screenFor("hk_cache_a", stored(10))).not.toBe(a);
  });

  const delivery = async (init: Partial<Delivery> = {}): Promise<Delivery> => ({
    ip: null,
    asn: null,
    country: null,
    headers: new Headers(),
    body: new Uint8Array(),
    contentType: "application/json",
    strict: false,
    key: await importScreenKey(new Uint8Array(32)),
    ...init,
  });

  it("a pattern stored before the subset that isn't in it never holds", async () => {
    const legacy = { rules: [{ id: "old", verdict: "drop", conditions: [{ on: "field", path: "payload.t", op: "pattern", pattern: "(\\w)\\1" }] }], consent: { words: true } } as unknown as EdgeScreen;
    const body = new TextEncoder().encode(JSON.stringify({ t: "aa" }));
    expect(await decide(compileScreen(legacy), await delivery({ body }))).toBeNull();
  });

  it("contains counts its comparisons against the budget", async () => {
    const words = `${"a ".repeat(400)}b`;
    const screen = compileScreen(parseScreen({ consent: { words: true }, rules: [{ id: "w", verdict: "drop", conditions: [{ on: "field", path: "payload.l[]", op: "contains", words }] }] })!);
    const body = new TextEncoder().encode(JSON.stringify({ l: Array.from({ length: 64 }, (_, i) => `${i} ${"a ".repeat(5000)}`) }));
    expect(400 * 5000 * 64).toBeGreaterThan(MAX_SCREEN_STEPS);
    expect(await decide(screen, await delivery({ body }))).toEqual({ verdict: "quarantine", rule: OVER_BUDGET_RULE });
  });
});
