// Phone links, hardened (PROTOCOL §10.3, §10.4): frame sizes checked before parsing and a token
// bucket per device for every frame, one gap record per device that never expires, per-recipient
// queue counters, resend dedupe per recipient, the schema migration, and revoked nodes remembered.

import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { toBase64Url } from "../src/encoding.ts";
import type { PhoneObject } from "../src/phone-object.ts";
import {
  makeEnvelope,
  newNode,
  openPhoneSocket,
  pairPhone,
  phoneObject,
  signed,
  type Frame,
  type TestNode,
  type TestPhone,
} from "./helpers.ts";

const nodeKey = (n: TestNode) => ({ deviceId: n.deviceId, sealKey: n.phoneSeal });
const phoneKey = (p: TestPhone) => ({ deviceId: p.deviceId, sealKey: p.seal });

async function sendEnv(sock: Awaited<ReturnType<typeof openPhoneSocket>>, e: Record<string, unknown>): Promise<Frame> {
  sock.send({ t: "send", env: e });
  return sock.nextWhere((f) => f.t === "queued" || f.t === "refused");
}

describe("frames", () => {
  it("closes a socket on an oversized frame (4400) before reading it as JSON", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const sock = await openPhoneSocket(phone);
    await sock.hello(0);
    // Not JSON, and too large: the size is what closes it, so it was never parsed.
    sock.send("x".repeat(70 * 1024));
    expect(await sock.closed).toBe(4400);
    expect(sock.closeReason).toBe("frame too large");
  });

  it("closes a socket that sends an oversized envelope (4400), from a phone or a node", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const sock = await openPhoneSocket(phone);
    await sock.hello(0);
    sock.send({ t: "send", env: await makeEnvelope(phone, nodeKey(node), "x".repeat(70 * 1024)) });
    expect(await sock.closed).toBe(4400);
    expect(sock.closeReason).toBe("frame too large");

    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);
    // 70 KiB is fine from a node; 520 KiB isn't.
    expect(await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(phone), "x".repeat(70 * 1024)))).toMatchObject({ t: "queued" });
    nodeSock.send({ t: "send", env: await makeEnvelope(node, phoneKey(phone), "x".repeat(520 * 1024)) });
    expect(await nodeSock.closed).toBe(4400);
  });

  it("charges acks to the token bucket", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const sock = await openPhoneSocket(phone);
    // Made first, so no time passes (and no tokens refill) between the acks and the send.
    const env = await makeEnvelope(phone, nodeKey(node), "after the acks");
    await sock.hello(0);
    for (let i = 0; i < 40; i++) sock.send({ t: "ack", through: 0 });
    const answer = await sendEnv(sock, env);
    expect(answer).toMatchObject({ t: "refused", code: "rate_limited", retryAfter: expect.any(Number) });
    sock.close();
  });

  it("keeps a device's token bucket across reconnects", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    let sock = await openPhoneSocket(phone);
    await sock.hello(0);
    const envs = [];
    for (let i = 0; i < 35; i++) envs.push(await makeEnvelope(phone, nodeKey(node), `m${i}`));
    for (const e of envs) sock.send({ t: "send", env: e });
    let answers = 0;
    while (answers < 35) if (["queued", "refused"].includes((await sock.next()).t)) answers++;
    sock.close();
    await sock.closed;

    // A fresh socket isn't a fresh bucket: a few seconds' refill at most, so most of these are refused.
    const more = [];
    for (let i = 0; i < 6; i++) more.push(await makeEnvelope(phone, nodeKey(node), `n${i}`));
    sock = await openPhoneSocket(phone);
    sock.send({ t: "hello", after: 0 });
    for (const e of more) sock.send({ t: "send", env: e });
    const got: Frame[] = [];
    while (got.length < more.length && sock.closeCode === null) {
      const f = await sock.next().catch(() => null);
      if (!f) break;
      if (f.t === "queued" || f.t === "refused") got.push(f);
    }
    // Either the hello found the bucket empty (4429), or some sends were refused.
    const limited = sock.closeCode === 4429 || got.some((f) => f.t === "refused" && f.code === "rate_limited");
    expect(limited).toBe(true);
    sock.close();
  });

  it("closes a hello that finds the bucket empty with 4429", async () => {
    const node = await newNode();
    await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) => {
      state.storage.sql.exec(
        "INSERT INTO buckets (device, tokens, at) VALUES (?, 0, ?) ON CONFLICT(device) DO UPDATE SET tokens = 0, at = excluded.at",
        node.deviceId,
        Date.now() + 60_000,
      );
    });
    const sock = await openPhoneSocket(node);
    sock.send({ t: "hello", after: 0 });
    expect(await sock.closed).toBe(4429);
  });
});

describe("gaps", () => {
  it("keeps one gap record per device, however many times its queue overflows", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const other = await pairPhone(node, { name: "iPad" });
    await runInDurableObject(phoneObject(node.accountId), (o: PhoneObject) => {
      o.limitsOverride = { phoneRows: 1 };
    });
    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);
    const seqs: number[] = [];
    for (let i = 0; i < 5; i++) {
      seqs.push((await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(phone), `m${i}`))).seq as number);
      // A row for the other phone between each, so the lost seqs never touch.
      await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(other), `o${i}`));
    }

    const phoneSock = await openPhoneSocket(phone);
    await phoneSock.hello(0);
    expect(await phoneSock.next()).toEqual({ t: "gap", from: seqs[0], to: seqs[3] });
    expect((await phoneSock.next()).seq).toBe(seqs[4]);
    expect((await phoneSock.drain()).filter((f) => f.t === "gap")).toEqual([]);
    const records = await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) =>
      state.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM device_gaps WHERE recipient = ?", phone.deviceId).one().n,
    );
    expect(records).toBe(1);
    phoneSock.close();
    nodeSock.close();
  });

  it("never expires a gap record: it goes only when the device acknowledges past it", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const phoneSock = await openPhoneSocket(phone);
    await phoneSock.hello(0);
    const seq = (await sendEnv(phoneSock, await makeEnvelope(phone, nodeKey(node), "m"))).seq as number;
    phoneSock.close();
    const old = Date.now() - 30 * 24 * 3600_000;
    await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) => {
      state.storage.sql.exec("UPDATE mailbox SET at = ? WHERE recipient = ?", old, node.deviceId);
    });
    // The first alarm drops the rows and records the loss.
    await runDurableObjectAlarm(phoneObject(node.accountId));
    await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) => {
      // However old the record is (a schema that dated gap records would expire this one now).
      for (const t of ["gaps", "device_gaps"]) {
        try {
          state.storage.sql.exec(`UPDATE ${t} SET at = ?`, old);
        } catch {
          // No such table or column: nothing dates it.
        }
      }
    });
    await runDurableObjectAlarm(phoneObject(node.accountId));
    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);
    expect(await nodeSock.next()).toEqual({ t: "gap", from: 1, to: seq });
    nodeSock.send({ t: "ack", through: seq });
    await nodeSock.drain();
    nodeSock.close();
    const left = await runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) =>
      state.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM device_gaps").one().n,
    );
    expect(left).toBe(0);
  });
});

describe("queue counters", () => {
  it("keeps each recipient's rows and bytes in step with the mailbox", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const other = await pairPhone(node, { name: "iPad" });
    await runInDurableObject(phoneObject(node.accountId), (o: PhoneObject) => {
      o.limitsOverride = { phoneRows: 2 };
    });
    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);
    const phoneSock = await openPhoneSocket(phone);
    await phoneSock.hello(0);
    for (let i = 0; i < 4; i++) await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(phone), `m${i}`));
    for (let i = 0; i < 3; i++) await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(other), `o${i}`));
    for (let i = 0; i < 3; i++) await sendEnv(phoneSock, await makeEnvelope(phone, nodeKey(node), `u${i}`));
    const check = () =>
      runInDurableObject(phoneObject(node.accountId), (_o: PhoneObject, state) => {
        const sql = state.storage.sql;
        const actual = sql
          .exec<{ recipient: string; n: number; b: number }>("SELECT recipient, count(*) AS n, sum(size) AS b FROM mailbox GROUP BY recipient ORDER BY recipient")
          .toArray();
        const kept = sql
          .exec<{ recipient: string; n: number; b: number }>(
            "SELECT recipient, queued_rows AS n, queued_bytes AS b FROM queue_stats WHERE queued_rows > 0 ORDER BY recipient",
          )
          .toArray();
        return { actual, kept };
      });
    let c = await check();
    expect(c.kept).toEqual(c.actual);
    expect(c.actual.length).toBe(3);

    // An ack, then a revocation (which deletes rows to and from the phone).
    const last = await phoneSock.nextOf("msg");
    phoneSock.send({ t: "ack", through: last.seq });
    await phoneSock.drain();
    c = await check();
    expect(c.kept).toEqual(c.actual);
    expect((await signed(node, "DELETE", `/v1/devices/${phone.deviceId}`)).status).toBe(204);
    c = await check();
    expect(c.kept).toEqual(c.actual);
    nodeSock.close();
  });
});

describe("schema migration", () => {
  it("brings an object written by the first phone relay up to date, once", async () => {
    const node = await newNode();
    const phone = await pairPhone(node);
    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);
    for (let i = 0; i < 3; i++) await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(phone), `m${i}`));
    nodeSock.close();
    const after = await runInDurableObject(phoneObject(node.accountId), (o: PhoneObject, state) => {
      const sql = state.storage.sql;
      // The first schema: dated gap records, several per device; no counters; the old resend index.
      sql.exec("DELETE FROM meta WHERE key = 'schema'");
      sql.exec("DELETE FROM queue_stats");
      sql.exec("CREATE TABLE gaps (recipient TEXT NOT NULL, from_seq INTEGER NOT NULL, to_seq INTEGER NOT NULL, at INTEGER NOT NULL)");
      sql.exec("INSERT INTO gaps VALUES (?, 2, 3, 1), (?, 7, 8, 2)", phone.deviceId, phone.deviceId);
      sql.exec("CREATE INDEX mailbox_sender_id ON mailbox(sender, msg_id)");
      (o as unknown as { migrate(): void }).migrate();
      return {
        stats: sql.exec("SELECT recipient, queued_rows, queued_bytes FROM queue_stats ORDER BY recipient").toArray(),
        actual: sql
          .exec("SELECT recipient, count(*) AS queued_rows, sum(size) AS queued_bytes FROM mailbox GROUP BY recipient ORDER BY recipient")
          .toArray(),
        gaps: sql.exec("SELECT recipient, from_seq, to_seq FROM device_gaps").toArray(),
        old: sql.exec("SELECT name FROM sqlite_master WHERE name IN ('gaps', 'mailbox_sender_id')").toArray(),
        schema: sql.exec<{ value: number }>("SELECT value FROM meta WHERE key = 'schema'").one().value,
      };
    });
    expect(after.stats).toEqual(after.actual);
    expect(after.gaps).toEqual([{ recipient: phone.deviceId, from_seq: 2, to_seq: 8 }]);
    expect(after.old).toEqual([]);
    expect(after.schema).toBe(2);
  });
});

describe("resend dedupe", () => {
  it("keys a resend on the sender, the recipient and the id", async () => {
    const node = await newNode();
    const a = await pairPhone(node);
    const b = await pairPhone(node, { name: "iPad" });
    const nodeSock = await openPhoneSocket(node);
    await nodeSock.hello(0);
    const id = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
    const toA = await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(a), "for a", { id }));
    const toB = await sendEnv(nodeSock, await makeEnvelope(node, phoneKey(b), "for b", { id }));
    expect(toA).toMatchObject({ t: "queued", id });
    expect(toB).toMatchObject({ t: "queued", id });
    expect(toB.seq).not.toBe(toA.seq);
    const bSock = await openPhoneSocket(b);
    await bSock.hello(0);
    const got = await bSock.nextOf("msg");
    expect(got.seq).toBe(toB.seq);
    expect((got.env as { to: string }).to).toBe(b.deviceId);
    bSock.close();
    nodeSock.close();
  });
});

describe("revoked nodes", () => {
  it("remembers a revoked node, so a socket opened after its revocation is refused", async () => {
    const node = await newNode();
    await pairPhone(node);
    const other = await newNode();
    await runInDurableObject(phoneObject(node.accountId), async (o: PhoneObject) => {
      await o.revokeNode(node.deviceId, []);
    });
    // The upgrade the Worker authenticated just before the revocation reaches the object after it.
    const status = await runInDurableObject(phoneObject(node.accountId), async (o: PhoneObject) => {
      const res = await o.fetch(new Request(`https://phone/socket?device=${node.deviceId}&role=node`, { headers: { Upgrade: "websocket" } }));
      return res.status;
    });
    expect(status).toBe(401);
    // Another account's node is unaffected.
    const sock = await openPhoneSocket(other);
    expect(await sock.hello(0)).toMatchObject({ t: "ready" });
    sock.close();
  });
});
