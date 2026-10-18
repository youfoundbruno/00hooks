// Phone pairing, hardened (PROTOCOL §10.1): the proof is checked before anything else, a pairing
// burns after too many wrong proofs, a relay-wide limit backs the per-address one, a taken key is
// only said after the proof, and a redemption never leaves half a phone behind.

import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { generateDeviceKey } from "../src/canonical.ts";
import { toBase64Url, utf8 } from "../src/encoding.ts";
import { MAX_PROOF_FAILURES, redeemPairing } from "../src/phone.ts";
import type { PhoneObject } from "../src/phone-object.ts";
import {
  BASE,
  fetchRelay,
  newNode,
  newSealPair,
  pairPhone,
  phoneSeal,
  randomTestIp,
  redeemPhone,
  registerPairing,
  type TestNode,
  type TestPairing,
} from "./helpers.ts";

/** The body of a `POST /v1/phone/pair`, with the fields a test wants to set. */
async function pairBody(node: TestNode, pairing: TestPairing, over: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  const { publicKey } = await generateDeviceKey();
  const seal = await newSealPair();
  const hello = await phoneSeal(node.phoneSeal.publicKey, utf8("{}"), utf8(`00next-pair-v1\n${pairing.pairingId}`));
  return { pairingId: pairing.pairingId, proof: pairing.proof, deviceName: "Phone", publicKey, sealKey: seal.text, hello, ...over };
}

const postPair = (body: unknown) =>
  fetchRelay("/v1/phone/pair", { method: "POST", headers: { "CF-Connecting-IP": randomTestIp() }, body: JSON.stringify(body) });

const wrongProof = () => toBase64Url(crypto.getRandomValues(new Uint8Array(32)));

describe("pairing atomicity", () => {
  it("rolls the phone back out of D1 and frees the pairing when the phone object fails", async () => {
    const node = await newNode();
    const pairing = await registerPairing(node);
    const body = await pairBody(node, pairing);
    const real = env.PHONE as unknown as DurableObjectNamespace<PhoneObject>;
    const revoked: string[] = [];
    const failing = {
      idFromName: (n: string) => real.idFromName(n),
      get: () => ({
        pair: async () => {
          throw new Error("phone object unavailable");
        },
        revokePhone: async (phone: string) => {
          revoked.push(phone);
          return true;
        },
      }),
    };
    const req = new Request(`${BASE}/v1/phone/pair`, { method: "POST", headers: { "CF-Connecting-IP": randomTestIp() } });
    await expect(redeemPairing(req, { ...env, PHONE: failing } as unknown as Env, utf8(JSON.stringify(body)))).rejects.toThrow();
    const left = await env.DB.prepare("SELECT count(*) AS n FROM devices WHERE public_key = ?").bind(body.publicKey).first<{ n: number }>();
    expect(left!.n).toBe(0);
    expect(revoked).toHaveLength(1);
    // The same phone, retrying, pairs.
    const retry = await postPair(body);
    expect(retry.status).toBe(200);
  });

  it("frees the key of a phone whose pending time ran out, so the phone can pair again", async () => {
    const node = await newNode();
    const first = await registerPairing(node);
    const body = await pairBody(node, first);
    expect((await postPair(body)).status).toBe(200);
    const stale = await env.DB.prepare("SELECT id FROM devices WHERE public_key = ?").bind(body.publicKey).first<{ id: string }>();
    await env.DB.prepare("UPDATE devices SET pending_until = ? WHERE id = ?").bind(Date.now() - 1, stale!.id).run();

    const second = await registerPairing(node);
    const res = await postPair({ ...body, pairingId: second.pairingId, proof: second.proof });
    expect(res.status).toBe(200);
    const { deviceId } = (await res.json()) as { deviceId: string };
    expect(deviceId).not.toBe(stale!.id);
    const rows = await env.DB.prepare("SELECT id FROM devices WHERE public_key = ?").bind(body.publicKey).all<{ id: string }>();
    expect(rows.results.map((r) => r.id)).toEqual([deviceId]);
  });

  it("frees expired pending phones' keys when the account registers a pairing", async () => {
    const node = await newNode();
    const phone = await pairPhone(node, { confirm: false });
    await env.DB.prepare("UPDATE devices SET pending_until = ? WHERE id = ?").bind(Date.now() - 1, phone.deviceId).run();
    await registerPairing(node);
    const row = await env.DB.prepare("SELECT id FROM devices WHERE id = ?").bind(phone.deviceId).first();
    expect(row).toBeNull();
  });
});

describe("pairing brute force", () => {
  it(`burns a pairing after ${MAX_PROOF_FAILURES} wrong proofs`, async () => {
    const node = await newNode();
    const pairing = await registerPairing(node);
    for (let i = 0; i < MAX_PROOF_FAILURES; i++) {
      const res = await postPair(await pairBody(node, pairing, { proof: wrongProof() }));
      expect(res.status).toBe(401);
    }
    const right = await postPair(await pairBody(node, pairing));
    expect(right.status).toBe(401);
    expect(await right.json()).toMatchObject({ error: "unauthorized" });
    const phones = await env.DB.prepare("SELECT count(*) AS n FROM devices WHERE account_id = ? AND kind = 'phone'").bind(node.accountId).first<{ n: number }>();
    expect(phones!.n).toBe(0);
    // A burned pairing doesn't count as open.
    for (let i = 0; i < 5; i++) await registerPairing(node);
  });

  it("checks the proof before saying a public key is taken (no 409 oracle)", async () => {
    const node = await newNode();
    const pairing = await registerPairing(node);
    const taken = await postPair(await pairBody(node, pairing, { publicKey: node.publicKey, proof: wrongProof() }));
    expect(taken.status).toBe(401);
    // With the right proof, the key is refused, and the pairing isn't spent.
    const right = await postPair(await pairBody(node, pairing, { publicKey: node.publicKey }));
    expect(right.status).toBe(409);
    expect(await right.json()).toMatchObject({ error: "conflict", message: "That public key already belongs to a device." });
    expect((await redeemPhone(node, pairing)).res.status).toBe(200);
  });

  it("checks the proof before the expensive fields", async () => {
    const node = await newNode();
    const pairing = await registerPairing(node);
    const res = await postPair(await pairBody(node, pairing, { proof: wrongProof(), sealKey: "A".repeat(43) }));
    expect(res.status).toBe(401);
  });

  it("limits pairing attempts globally, and fails closed without the binding", async () => {
    const node = await newNode();
    const body = utf8(JSON.stringify(await pairBody(node, await registerPairing(node))));
    const req = () => new Request(`${BASE}/v1/phone/pair`, { method: "POST", headers: { "CF-Connecting-IP": randomTestIp() } });
    const no = { limit: async () => ({ success: false }) } as unknown as RateLimit;
    const limited = await redeemPairing(req(), { ...env, PAIR_GLOBAL_LIMIT: no } as Env, body);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBe("60");
    for (const missing of ["PAIR_IP_LIMIT", "PAIR_GLOBAL_LIMIT"] as const) {
      const res = await redeemPairing(req(), { ...env, [missing]: undefined } as unknown as Env, body);
      expect(res.status).toBe(503);
    }
  });
});
