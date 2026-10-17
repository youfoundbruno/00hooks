// Shared vectors: the provider presets (fixtures/presets.v1.json, also run by the CLI's strict-mode
// verifier), RFC 9180's HPKE vector for our suite, and events sealed by this code under Node for the
// CLI (fixtures/seal-interop.v1.json), opened here too.

import { describe, expect, it } from "vitest";
import presetVectors from "../../fixtures/presets.v1.json";
import rfc from "../../fixtures/hpke-rfc9180-a2.json";
import interop from "../../fixtures/seal-interop.v1.json";
import { fromBase64, fromHex, toHex, utf8 } from "../src/encoding.ts";
import { SUITE, decodeContent, envelopeSigString, openWith, sealAad, sealKid } from "../src/envelope.ts";
import { PRESETS, SPECS, parseVerify, verifyDelivery, type Preset } from "../src/presets.ts";

interface PresetVector {
  name: string;
  verify: Record<string, unknown>;
  secrets: string[];
  now: number;
  url?: string;
  headers: Record<string, string>;
  body: string;
  expect: { ok: boolean; eventType?: string | null };
}

describe("provider preset vectors", () => {
  const vectors = presetVectors.vectors as unknown as PresetVector[];

  it("cover every preset that verifies anything", () => {
    const covered = new Set(vectors.map((v) => v.verify.preset));
    for (const p of PRESETS) if (p !== "unverified") expect(covered, p).toContain(p);
  });

  for (const v of vectors) {
    it(v.name, async () => {
      // The stored config is what parseVerify makes of the vector's verify object (secrets aside).
      const provided = SPECS[v.verify.preset as Preset].secret === "provided";
      // (A placeholder secret for parsing: some published vectors use secrets shorter than the
      // relay accepts at creation, such as Twilio's "12345".)
      const { config } = parseVerify({ ...v.verify, ...(provided ? { secret: "placeholder" } : {}) });
      const verdict = await verifyDelivery(config, v.secrets, { body: utf8(v.body), headers: new Headers(v.headers), now: v.now, url: v.url });
      expect(verdict.ok).toBe(v.expect.ok);
      expect(verdict.verified).toBe(v.expect.ok);
      if (v.expect.ok && "eventType" in v.expect) expect(verdict.eventType).toBe(v.expect.eventType);
    });
  }
});

describe("RFC 9180 A.2.1 (our suite, base mode)", () => {
  it("derives the keys and produces the published enc and ciphertexts", async () => {
    const r = await SUITE.kem.deriveKeyPair(fromHex(rfc.ikmR)!);
    expect(toHex(await SUITE.kem.serializePublicKey(r.publicKey))).toBe(rfc.pkRm);
    expect(toHex(await SUITE.kem.serializePrivateKey(r.privateKey))).toBe(rfc.skRm);
    const e = await SUITE.kem.deriveKeyPair(fromHex(rfc.ikmE)!);
    const sender = await SUITE.createSenderContext({ recipientPublicKey: r.publicKey, info: fromHex(rfc.info)!, ekm: e });
    expect(toHex(sender.enc)).toBe(rfc.enc);
    for (const x of rfc.encryptions) {
      expect(toHex(await sender.seal(fromHex(x.pt)!, fromHex(x.aad)!)), `seq ${x.seq}`).toBe(x.ct);
    }
    const recipient = await SUITE.createRecipientContext({ recipientKey: r.privateKey, enc: fromHex(rfc.enc)!, info: fromHex(rfc.info)! });
    for (const x of rfc.encryptions) expect(toHex(await recipient.open(fromHex(x.ct)!, fromHex(x.aad)!))).toBe(x.pt);
  });
});

describe("seal interop fixture", () => {
  it("opens and verifies every event the relay's code sealed under Node", async () => {
    const priv = fromBase64(interop.devicePrivateKey)!;
    expect(await sealKid(fromBase64(interop.devicePublicKey)!)).toBe(interop.kid);
    const relayKey = await crypto.subtle.importKey("raw", fromBase64(interop.relayKey)!, { name: "Ed25519" }, false, ["verify"]);
    for (const { message: m, expect: want } of interop.events) {
      const ct = fromBase64(m.sealed.ct)!;
      const toSign = await envelopeSigString({ ...m, deviceId: interop.deviceId }, { kid: m.sealed.kid, enc: m.sealed.enc, ct });
      expect(await crypto.subtle.verify("Ed25519", relayKey, fromBase64(m.sig)!, utf8(toSign))).toBe(true);
      const content = decodeContent(await openWith(priv, fromBase64(m.sealed.enc)!, ct, sealAad(m.hookId, m.seq, m.id)));
      expect(content.headers).toEqual(want.headers);
      expect(content.contentType).toBe(want.contentType);
      expect(content.url ?? null).toBe(want.url);
      expect(fromBase64(want.body)).toEqual(new Uint8Array(content.body));
      // Moved to another seq, it doesn't open: the hook, seq and id are the associated data.
      await expect(openWith(priv, fromBase64(m.sealed.enc)!, ct, sealAad(m.hookId, m.seq + 1, m.id))).rejects.toThrow();
    }
  });
});
