// What one webhook costs the account's Durable Object in SQLite rows (relay/docs/COSTS.md): a meter
// that sums the object's own per-query `rowsWritten` and `rowsRead` (each index entry and delete
// counts, as Cloudflare bills them) plus `setAlarm` calls (billed as a row written), and the
// scenarios COSTS.md measures. `costs.test.ts` asserts upper bounds on them.

import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import type { AccountObject } from "../src/account-object.ts";
import { hmac, toHex, utf8 } from "../src/encoding.ts";
import { call, signedWith, withVars } from "./plan-helpers.ts";
import { accountObject, createHook, enrolDevice, fetchRelay, newAccount, signed, type TestDevice } from "./helpers.ts";
import { env } from "cloudflare:workers";

/** Rows one step of a scenario cost. */
export interface Rows {
  /** Rows written, `setAlarm` calls included. */
  written: number;
  read: number;
  /** `setAlarm` calls among `written`. */
  alarms: number;
}

interface Logged {
  sql: string;
  cursor: SqlStorageCursor<Record<string, SqlStorageValue>>;
}

/** What the meter saw since it was installed or last taken. */
const log: Logged[] = [];
let alarms = 0;

/**
 * Installs the meter on an account's object: every query it runs from now on is logged, with its
 * cursor, and every `setAlarm`. Same isolate as the tests, so the log is shared.
 */
export async function installMeter(accountId: string): Promise<void> {
  await runInDurableObject(accountObject(accountId), (o: AccountObject, state) => {
    const real = state.storage.sql;
    const self = o as unknown as { sql: SqlStorage; __metered?: boolean };
    if (self.__metered) return;
    self.__metered = true;
    self.sql = {
      exec: (sql: string, ...args: SqlStorageValue[]) => {
        const cursor = real.exec(sql, ...args);
        log.push({ sql, cursor });
        return cursor;
      },
      get databaseSize() {
        return real.databaseSize;
      },
      Cursor: real.Cursor,
      Statement: real.Statement,
    } as unknown as SqlStorage;
    const setAlarm = state.storage.setAlarm.bind(state.storage);
    Object.defineProperty(state.storage, "setAlarm", {
      configurable: true,
      value: (t: number | Date, opts?: DurableObjectSetAlarmOptions) => {
        alarms++;
        return setAlarm(t, opts);
      },
    });
  });
}

/** Clears the meter. */
export function resetMeter(): void {
  log.length = 0;
  alarms = 0;
}

/** Rows since the last reset (a `setAlarm` is a row written), and the meter cleared. */
export function takeMeter(): Rows & { byQuery: { sql: string; written: number; read: number }[] } {
  const byQuery = log.map((l) => ({ sql: l.sql.replace(/\s+/g, " ").trim(), written: l.cursor.rowsWritten, read: l.cursor.rowsRead }));
  const written = byQuery.reduce((n, q) => n + q.written, 0) + alarms;
  const read = byQuery.reduce((n, q) => n + q.read, 0);
  const taken = alarms;
  resetMeter();
  return { written, read, alarms: taken, byQuery: byQuery.filter((q) => q.written > 0 || q.read > 0) };
}

async function githubSignature(secret: string, body: string): Promise<string> {
  return `sha256=${toHex(await hmac("SHA-256", utf8(secret), utf8(body)))}`;
}

/** A 1 KB GitHub `push` delivery (two dedupe keys: the delivery id and the body hash). */
async function githubDelivery(e: Env | null, hookId: string, secret: string, n: number, delivery = crypto.randomUUID()): Promise<Response> {
  const body = JSON.stringify({ n, pad: "x".repeat(1000) });
  const init = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Hub-Signature-256": await githubSignature(secret, body),
      "X-GitHub-Event": "push",
      "X-GitHub-Delivery": delivery,
    },
    body,
  };
  return e ? call(e, `/h/${hookId}`, init) : fetchRelay(`/h/${hookId}`, init);
}

async function ack(e: Env | null, dev: TestDevice, through: number): Promise<void> {
  const res = e ? await signedWith(e, dev, "POST", "/v1/ack", { through }) : await signed(dev, "POST", "/v1/ack", { through });
  if (res.status !== 200) throw new Error(`ack: ${res.status}`);
}

const DAY = 24 * 3600_000;

/**
 * Moves what the warm-up left (nonces, replay marks) a day ahead, unmetered, so the alarm measured
 * later prunes only what the measured webhook leaves, and still has something to wake for after.
 */
async function setAsideWarmUp(accountId: string): Promise<void> {
  await runInDurableObject(accountObject(accountId), (_o: AccountObject, state) => {
    state.storage.sql.exec("UPDATE nonces SET at = at + ?", DAY);
    state.storage.sql.exec("UPDATE seen SET at = at + ?", DAY);
  });
}

/** Ages what the measured webhook left (nonces, replay marks) past any expiry, unmetered. */
async function ageForAlarm(accountId: string): Promise<void> {
  await runInDurableObject(accountObject(accountId), (_o: AccountObject, state) => {
    const old = 400 * DAY;
    const cut = Date.now() + DAY / 2;
    state.storage.sql.exec("UPDATE nonces SET at = at - ? WHERE at < ?", old, cut);
    state.storage.sql.exec("UPDATE seen SET at = at - ? WHERE at < ?", old, cut);
  });
}

/** One scenario's cost per step. */
export interface Scenario {
  append: Rows;
  /** Every device's ack, in all. */
  acks: Rows;
  /**
   * The hourly alarm that later prunes what the webhook left (nonces, replay marks). Its own re-arm
   * (`alarms`, one `setAlarm`) is shared by every webhook of the hour, so `total` leaves it out.
   */
  alarm: Rows;
  /** Rows per webhook: append, acks, and the alarm's pruning without its re-arm. */
  total: Rows;
}

function sum(...r: Rows[]): Rows {
  return {
    written: r.reduce((n, x) => n + x.written, 0),
    read: r.reduce((n, x) => n + x.read, 0),
    alarms: r.reduce((n, x) => n + x.alarms, 0),
  };
}

/**
 * One GitHub delivery to `devices` devices (all with sealing keys), after a warm-up event, each
 * device then acknowledging it on its own, and the alarm that prunes after it. `plan`: the account's
 * plan's limits (PLANS), with the edge's rate limits out of the way.
 */
export async function webhookScenario(opts: { devices?: number; plan?: Record<string, number> } = {}): Promise<Scenario & { seq: number }> {
  const e = opts.plan ? withVars({ PLANS: JSON.stringify({ p: opts.plan }) }) : null;
  const first = await newAccount();
  const devs = [first];
  for (let i = 1; i < (opts.devices ?? 1); i++) devs.push(await enrolDevice(first, `device ${i}`));
  if (opts.plan) await env.DB.prepare("UPDATE accounts SET plan = 'p' WHERE id = ?").bind(first.accountId).run();
  const { hook, secret } = await createHook(first, { preset: "github" });
  await installMeter(first.accountId);
  // Warm-up: the first event creates the rows later ones update.
  const warm = await githubDelivery(e, hook.id, secret!, 0);
  if (warm.status !== 200) throw new Error(`warm-up: ${warm.status}`);
  const warmSeq = (await accountObject(first.accountId).stats()).head;
  for (const d of devs) await ack(e, d, warmSeq);
  await setAsideWarmUp(first.accountId);
  resetMeter();

  const res = await githubDelivery(e, hook.id, secret!, 1);
  if (res.status !== 200) throw new Error(`delivery: ${res.status}`);
  const append = takeMeter();
  const seq = (await accountObject(first.accountId).stats()).head;
  resetMeter();
  for (const d of devs) await ack(e, d, seq);
  const acks = takeMeter();
  await ageForAlarm(first.accountId);
  resetMeter();
  if (!(await runDurableObjectAlarm(accountObject(first.accountId)))) throw new Error("no alarm was set");
  const alarm = takeMeter();
  const pruning = { written: alarm.written - alarm.alarms, read: alarm.read, alarms: 0 };
  return { append, acks, alarm, total: sum(append, acks, pruning), seq };
}

/** A GitHub delivery redelivered (same delivery id): what the duplicate costs. */
export async function duplicateScenario(): Promise<Rows> {
  const dev = await newAccount();
  const { hook, secret } = await createHook(dev, { preset: "github" });
  await installMeter(dev.accountId);
  const id = crypto.randomUUID();
  await githubDelivery(null, hook.id, secret!, 1, id);
  resetMeter();
  const res = await githubDelivery(null, hook.id, secret!, 1, id);
  if (res.status !== 200) throw new Error(`duplicate: ${res.status}`);
  return takeMeter();
}

/** A GitHub delivery the screen holds (PROTOCOL §4b), after a warm-up one: what the hold costs. */
export async function heldScenario(): Promise<Rows> {
  const dev = await newAccount();
  const { hook, secret } = await createHook(dev, { preset: "github" });
  const screen = { rules: [{ id: "hold", verdict: "quarantine", conditions: [{ on: "size", op: "gt", bytes: 0 }] }], consent: { words: false } };
  const put = await signed(dev, "PUT", `/v1/hooks/${hook.id}/screen`, { screen });
  if (put.status !== 200) throw new Error(`screen: ${put.status}`);
  await installMeter(dev.accountId);
  await githubDelivery(null, hook.id, secret!, 0);
  resetMeter();
  const res = await githubDelivery(null, hook.id, secret!, 1);
  if (res.status !== 200) throw new Error(`held: ${res.status}`);
  return takeMeter();
}
