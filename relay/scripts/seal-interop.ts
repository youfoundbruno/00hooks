// Seals events with the relay's own sealing code (src/envelope.ts), under Node, for the Rust client to
// open: the cross-implementation proof of PROTOCOL §5. Run with Node 22.18+ (type stripping).
//
//   node relay/scripts/seal-interop.ts --fixture
//       rewrites fixtures/seal-interop.v1.json: a fixed device and relay key, events with fresh HPKE
//       randomness (the Rust tests open them; the relay's tests open them too).
//   node relay/scripts/seal-interop.ts --live <sealKey base64url> <deviceId>
//       prints the same events, sealed to a key the caller just made, as JSON on stdout (the Rust
//       round-trip test runs this).

import { fromBase64, toBase64, toBase64Url } from "../src/encoding.ts";
import { encodeContent, eventMessage, importRelayKey, sealEnvelope, sealKid, SUITE, type SealedContent } from "../src/envelope.ts";

/** RELAY_SIGNING_KEY for the fixture: the seed 00 01 … 1f (PROTOCOL §1's example key). */
const RELAY_SEED = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
/** The fixture device's sealing key, derived from this IKM (RFC 9180 DeriveKeyPair). */
const DEVICE_IKM = new TextEncoder().encode("00hooks interop fixture device key, not a secret");
const DEVICE_ID = "dev_0123456789abcdefghjkmnpq";

// Node's globals, declared here: this script's type check has no @types/node (like idle-cost.ts).
declare const process: { argv: string[]; exit(code: number): never };
const FS = "node:fs";
const { writeFileSync } = (await import(FS)) as { writeFileSync(path: URL, data: string): void };

interface Sample {
  meta: { seq: number; id: string; hookId: string; receivedAt: number; verified: boolean; strict: boolean; preset: string; eventType: string | null };
  content: SealedContent;
}

function samples(): Sample[] {
  const bin = new Uint8Array(256);
  for (let i = 0; i < 256; i++) bin[i] = i;
  return [
    {
      meta: { seq: 1, id: "evt_000000000000000000000000a1", hookId: "hk_000000000000000000000000h1", receivedAt: 1792233600000, verified: true, strict: false, preset: "github", eventType: "push" },
      content: {
        headers: { "content-type": "application/json", "x-github-event": "push", "x-github-delivery": "d-1" },
        contentType: "application/json",
        body: new TextEncoder().encode('{"ref":"refs/heads/main","n":1}'),
      },
    },
    {
      meta: { seq: 2, id: "evt_000000000000000000000000a2", hookId: "hk_000000000000000000000000h2", receivedAt: 1792233601000, verified: false, strict: false, preset: "unverified", eventType: null },
      content: { headers: {}, contentType: null, body: new Uint8Array(0) },
    },
    {
      meta: { seq: 3, id: "evt_000000000000000000000000a3", hookId: "hk_000000000000000000000000h1", receivedAt: 1792233602000, verified: true, strict: false, preset: "hmac", eventType: "ünïcode\nlabel ✓" },
      content: { headers: { "content-type": "application/octet-stream" }, contentType: "application/octet-stream", body: bin },
    },
    {
      meta: { seq: 4, id: "evt_000000000000000000000000a4", hookId: "hk_000000000000000000000000h3", receivedAt: 1792233603000, verified: false, strict: true, preset: "stripe", eventType: null },
      content: {
        headers: { "content-type": "application/json", "stripe-signature": "t=1792233603,v1=00" },
        contentType: "application/json",
        url: "https://relay.example.com/h/hk_000000000000000000000000h3",
        body: new TextEncoder().encode('{"id":"evt_1","type":"invoice.paid"}'),
      },
    },
  ];
}

async function seal(sealKey: Uint8Array, deviceId: string) {
  const relay = (await importRelayKey(RELAY_SEED))!;
  const kid = await sealKid(sealKey);
  const out = [];
  for (const s of samples()) {
    const env = await sealEnvelope(relay, { deviceId, kid, publicKey: sealKey }, s.meta, encodeContent(s.content));
    out.push({
      message: JSON.parse(eventMessage(s.meta, env)) as unknown,
      expect: {
        headers: s.content.headers,
        contentType: s.content.contentType,
        url: s.content.url ?? null,
        body: toBase64(s.content.body),
      },
    });
  }
  return { relayKey: relay.publicKey, deviceId, kid, events: out };
}

const [mode, a, b] = process.argv.slice(2);
if (mode === "--live") {
  const key = a ? fromBase64(a) : null;
  if (!key || key.byteLength !== 32 || !b) {
    console.error("usage: seal-interop.ts --live <sealKey base64url> <deviceId>");
    process.exit(2);
  } else {
    console.log(JSON.stringify(await seal(key, b)));
  }
} else if (mode === "--fixture") {
  const pair = await SUITE.kem.deriveKeyPair(DEVICE_IKM);
  const publicKey = new Uint8Array(await SUITE.kem.serializePublicKey(pair.publicKey));
  const privateKey = new Uint8Array(await SUITE.kem.serializePrivateKey(pair.privateKey));
  const sealed = await seal(publicKey, DEVICE_ID);
  const file = new URL("../../fixtures/seal-interop.v1.json", import.meta.url);
  const doc = {
    about:
      "Events sealed by the relay's own code (relay/src/envelope.ts) under Node, for the CLI to open: PROTOCOL §5. The device key is a fixture, not a secret. Regenerate with: node relay/scripts/seal-interop.ts --fixture",
    devicePrivateKey: toBase64Url(privateKey),
    devicePublicKey: toBase64Url(publicKey),
    ...sealed,
  };
  writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`);
  console.log(`wrote ${sealed.events.length} sealed events to ${file.pathname}`);
} else {
  console.error("usage: seal-interop.ts --fixture | --live <sealKey base64url> <deviceId>");
  process.exit(2);
}
