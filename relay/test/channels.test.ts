// Webhook channels (PROTOCOL §3, §4, §4a): the Meta preset and its GET handshake answered at the
// edge, TwiML answers for Twilio, and the offline notice with its conditions and its once-a-day cap.

import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { AccountObject } from "../src/account-object.ts";
import { hmac, toHex, utf8 } from "../src/encoding.ts";
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

const APP_SECRET = "meta-app-secret-0001";
const TWILIO_TOKEN = "twilio-auth-token-0001";
const NOTICE = "Thanks, we got your message & will reply soon.";

const WHATSAPP = JSON.stringify({
  object: "whatsapp_business_account",
  entry: [
    {
      id: "102290129340398",
      changes: [
        {
          field: "messages",
          value: {
            messaging_product: "whatsapp",
            metadata: { display_phone_number: "15550783881", phone_number_id: "106540352242922" },
            contacts: [{ profile: { name: "Sheena Nelson" }, wa_id: "16505551234" }],
            messages: [{ from: "16505551234", id: "wamid.1", timestamp: "1749416383", type: "text", text: { body: "Hello" } }],
          },
        },
      ],
    },
  ],
});

async function metaSig(body: string, secret = APP_SECRET): Promise<string> {
  return `sha256=${toHex(await hmac("SHA-256", utf8(secret), utf8(body)))}`;
}

async function nextHook(sse: SseReader): Promise<StreamedEvent> {
  for (;;) {
    const f = await sse.nextEvent();
    if (f?.event === "hook") return data<StreamedEvent>(f);
    if (f === null) throw new Error("stream ended");
  }
}

/** A Twilio message webhook, signed as Twilio signs it (the URL, then the sorted parameters). */
async function twilioPost(url: string, params: Record<string, string>, token = TWILIO_TOKEN): Promise<Response> {
  const names = Object.keys(params).sort();
  const signedString = url + names.map((n) => n + params[n]).join("");
  const raw = await hmac("SHA-1", utf8(token), utf8(signedString));
  const sig = btoa(String.fromCharCode(...raw));
  return fetchRelay(new URL(url).pathname, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Twilio-Signature": sig },
    body: new URLSearchParams(params).toString(),
  });
}

const sms = (from: string, body = "hi there", sid = `SM${crypto.randomUUID().replaceAll("-", "")}`) => ({
  To: "+15005550006",
  From: from,
  Body: body,
  MessageSid: sid,
  SmsStatus: "received",
});

/** Moves the object's clocks back: the last stream seen, and the notices already sent. */
async function rewind(dev: TestDevice, what: { stream?: number; notices?: number }): Promise<void> {
  await runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) => {
    if (what.stream !== undefined) {
      state.storage.sql.exec("UPDATE meta SET value = value - ? WHERE key = 'stream_seen'", what.stream);
      // A socket the runtime still holds counts only while it shows life: move that back too.
      for (const ws of state.getWebSockets()) {
        const att = ws.deserializeAttachment() as { openedAt?: number } | null;
        if (att?.openedAt) ws.serializeAttachment({ ...att, openedAt: att.openedAt - what.stream });
      }
    }
    if (what.notices !== undefined) state.storage.sql.exec("UPDATE notices SET at = at - ?", what.notices);
  });
}

describe("the meta preset", () => {
  it("needs the app secret, makes a verify token shown once, and keeps only its keyed hash", async () => {
    const dev = await newAccount();
    expect((await signed(dev, "POST", "/v1/hooks", { name: "wa", verify: { preset: "meta" } })).status).toBe(400);
    const bad = await signed(dev, "POST", "/v1/hooks", { name: "x", verify: { preset: "github", verifyToken: "abcdefghij" } });
    expect(await bad.json()).toMatchObject({ field: "verify.verifyToken" });
    const created = await createHook(dev, { preset: "meta", secret: APP_SECRET });
    const token = (created as unknown as { verifyToken: string }).verifyToken;
    expect(token).toMatch(/^[A-Za-z0-9_-]{32}$/);
    expect(created).not.toHaveProperty("secret");
    expect(created.hook.verify).toEqual({ preset: "meta" });
    const listed = await (await signed(dev, "GET", `/v1/hooks/${created.hook.id}`)).text();
    expect(listed).not.toContain(token);
    expect(listed).not.toContain(APP_SECRET);
    // A token the caller chose is never echoed.
    const own = await createHook(dev, { preset: "meta", secret: APP_SECRET, verifyToken: "my-own-verify-token" });
    expect(own).not.toHaveProperty("verifyToken");
    // The provider issues the app secret: it can't be rotated here.
    expect((await signed(dev, "POST", `/v1/hooks/${created.hook.id}/rotate`)).status).toBe(409);
  });

  it("answers Meta's GET handshake at the edge only with the hook's verify token, and stores nothing", async () => {
    const dev = await newAccount();
    const created = await createHook(dev, { preset: "meta", secret: APP_SECRET, verifyToken: "verify-token-0001" });
    const path = `/h/${created.hook.id}`;
    const get = (q: string) => fetchRelay(`${path}?${q}`);
    const ok = await get("hub.mode=subscribe&hub.verify_token=verify-token-0001&hub.challenge=1158201444");
    expect(ok.status).toBe(200);
    expect(ok.headers.get("Content-Type")).toContain("text/plain");
    expect(await ok.text()).toBe("1158201444");
    // A wrong token, the wrong mode, or a challenge that could be anything but a plain echo.
    expect((await get("hub.mode=subscribe&hub.verify_token=verify-token-0002&hub.challenge=1")).status).toBe(401);
    expect((await get("hub.mode=unsubscribe&hub.verify_token=verify-token-0001&hub.challenge=1")).status).toBe(401);
    expect((await get("hub.mode=subscribe&hub.verify_token=verify-token-0001&hub.challenge=%3Cscript%3E")).status).toBe(401);
    expect((await get("hub.mode=subscribe&hub.challenge=1")).status).toBe(401);
    // Failures are counted, never stored; nothing at all is stored.
    const audit = (await (await signed(dev, "GET", "/v1/audit")).json()) as { entries: { kind: string; count?: number }[] };
    expect(audit.entries.find((e) => e.kind === "verify.failed")?.count).toBe(4);
    expect((await accountObject(dev.accountId).stats()).events).toBe(0);
    // Other presets have no GET handshake at all.
    const gh = await createHook(dev, { preset: "github" });
    expect((await fetchRelay(`/h/${gh.hook.id}?hub.mode=subscribe&hub.verify_token=x&hub.challenge=1`)).status).toBe(404);
  });

  it("verifies X-Hub-Signature-256 over the raw body, types by the signed object, and dedupes on the body", async () => {
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "meta", secret: APP_SECRET });
    const post = async (body: string, sig: string) =>
      fetchRelay(`/h/${hook.id}`, { method: "POST", headers: { "Content-Type": "application/json", "X-Hub-Signature-256": sig }, body });
    expect((await post(WHATSAPP, await metaSig(WHATSAPP, "another-app-secret"))).status).toBe(401);
    const first = await post(WHATSAPP, await metaSig(WHATSAPP));
    expect(first.status).toBe(200);
    expect(await first.json()).toHaveProperty("received");
    // Meta retries with the same body.
    expect(await (await post(WHATSAPP, await metaSig(WHATSAPP))).json()).toEqual({ duplicate: true });
    const { sse } = await openStream(dev);
    const ev = await nextHook(sse);
    expect(ev).toMatchObject({ verified: true, preset: "meta", eventType: "whatsapp_business_account" });
    const opened = await openEvent(dev, ev);
    expect(opened.text).toBe(WHATSAPP);
    expect(opened.headers).not.toHaveProperty("x-hub-signature-256");
    expect(opened.notice).toBeUndefined();
    await sse.cancel();
  });
});

describe("offline notices", () => {
  it("are only for presets whose provider takes a reply in the response, and are checked", async () => {
    const dev = await newAccount();
    const notice = { text: NOTICE, afterMinutes: 10 };
    const meta = await signed(dev, "POST", "/v1/hooks", { name: "wa", verify: { preset: "meta", secret: APP_SECRET }, offlineNotice: notice });
    expect(meta.status).toBe(400);
    expect(await meta.json()).toMatchObject({ field: "offlineNotice" });
    for (const bad of [{ text: "", afterMinutes: 10 }, { text: "x".repeat(321), afterMinutes: 10 }, { text: "ok", afterMinutes: 0 }, { text: "a\u0007b", afterMinutes: 5 }]) {
      const res = await signed(dev, "POST", "/v1/hooks", { name: "sms", verify: { preset: "twilio", secret: TWILIO_TOKEN }, offlineNotice: bad });
      expect(res.status, JSON.stringify(bad)).toBe(400);
    }
    const { hook } = await createHook(dev, { preset: "twilio", secret: TWILIO_TOKEN });
    expect(hook.offlineNotice).toBeNull();
    const set = await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { offlineNotice: notice });
    expect(await set.json()).toMatchObject({ offlineNotice: notice });
    const cleared = await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { offlineNotice: null });
    expect(await cleared.json()).toMatchObject({ offlineNotice: null });
  });

  it("answer Twilio with TwiML: the notice while no device has been connected for long enough, once a day per sender", async () => {
    const dev = await newAccount();
    const { hook, url } = await createHook(dev, { preset: "twilio", secret: TWILIO_TOKEN });
    await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { offlineNotice: { text: NOTICE, afterMinutes: 30 } });
    const twiml = async (res: Response) => {
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toContain("text/xml");
      return res.text();
    };
    const withNotice = '<?xml version="1.0" encoding="UTF-8"?><Response><Message>Thanks, we got your message &amp; will reply soon.</Message></Response>';
    const empty = '<?xml version="1.0" encoding="UTF-8"?><Response></Response>';

    // No device has ever streamed: the first message from a sender gets the notice, the next doesn't.
    expect(await twiml(await twilioPost(url, sms("+15005550001")))).toBe(withNotice);
    expect(await twiml(await twilioPost(url, sms("+15005550001", "again")))).toBe(empty);
    expect(await twiml(await twilioPost(url, sms("+15005550002")))).toBe(withNotice);
    // A status callback isn't a message: no notice, still TwiML.
    expect(await twiml(await twilioPost(url, { ...sms("+15005550003"), MessageStatus: "delivered" }))).toBe(empty);
    // Forged: refused before anything else.
    expect((await twilioPost(url, sms("+15005550004"), "wrong-token")).status).toBe(401);

    // A device connects: nobody gets a notice while it is.
    const { sse } = await openStream(dev);
    expect(await twiml(await twilioPost(url, sms("+15005550005")))).toBe(empty);
    // Each event the device reads says whether its sender got the notice.
    const read: boolean[] = [];
    for (let i = 0; i < 5; i++) read.push((await openEvent(dev, await nextHook(sse))).notice === true);
    expect(read).toEqual([true, false, true, false, false]);
    await sse.cancel();
    // Just gone: not yet (30 minutes must pass without a device).
    expect(await twiml(await twilioPost(url, sms("+15005550006")))).toBe(empty);
    await rewind(dev, { stream: 31 * 60_000 });
    expect(await twiml(await twilioPost(url, sms("+15005550006", "later")))).toBe(withNotice);
    // Once a day per sender: +…01 had one; a day later it may have another.
    expect(await twiml(await twilioPost(url, sms("+15005550001", "still there?")))).toBe(empty);
    await rewind(dev, { notices: 24 * 3600_000 + 1000 });
    expect(await twiml(await twilioPost(url, sms("+15005550001", "next day")))).toBe(withNotice);

    // Senders are kept only as keyed hashes: no number, no text, in the notices table.
    const rows = await runInDurableObject(accountObject(dev.accountId), (_o: AccountObject, state) =>
      state.storage.sql.exec<{ hook_id: string; mark: string }>("SELECT hook_id, mark FROM notices").toArray(),
    );
    expect(rows.length).toBe(3);
    for (const r of rows) {
      expect(r.mark).toMatch(/^[0-9a-f]{64}$/);
      expect(r.mark).not.toContain("15005550");
    }
  });

  it("are never sent for a hook without one, nor for a duplicate", async () => {
    const dev = await newAccount();
    const { url } = await createHook(dev, { preset: "twilio", secret: TWILIO_TOKEN });
    const res = await twilioPost(url, sms("+15005550001", "hi", "SMfixed"));
    expect(await res.text()).toBe('<?xml version="1.0" encoding="UTF-8"?><Response></Response>');
    const dev2 = await newAccount();
    const h2 = await createHook(dev2, { preset: "twilio", secret: TWILIO_TOKEN });
    await signed(dev2, "PATCH", `/v1/hooks/${h2.hook.id}`, { offlineNotice: { text: NOTICE, afterMinutes: 1 } });
    const params = sms("+15005550009", "hi", "SMsame");
    expect(await (await twilioPost(h2.url, params)).text()).toContain("<Message>");
    // Twilio's retry of the same message is a duplicate: answered with empty TwiML.
    expect(await (await twilioPost(h2.url, params)).text()).toBe('<?xml version="1.0" encoding="UTF-8"?><Response></Response>');
  });

  it("answer a Slack slash command ephemerally, and leave Slack events alone", async () => {
    const dev = await newAccount();
    const secret = "slack-signing-secret-01";
    const { hook } = await createHook(dev, { preset: "slack", secret });
    await signed(dev, "PATCH", `/v1/hooks/${hook.id}`, { offlineNotice: { text: NOTICE, afterMinutes: 5 } });
    const post = async (body: string, contentType: string) => {
      const ts = String(Math.floor(Date.now() / 1000));
      const sig = `v0=${toHex(await hmac("SHA-256", utf8(secret), utf8(`v0:${ts}:${body}`)))}`;
      return fetchRelay(`/h/${hook.id}`, {
        method: "POST",
        headers: { "Content-Type": contentType, "X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig },
        body,
      });
    };
    const command = "command=%2Fask&text=hours&team_id=T1&user_id=U1&channel_id=C1";
    const res = await post(command, "application/x-www-form-urlencoded");
    expect(await res.json()).toMatchObject({ response_type: "ephemeral", text: NOTICE });
    const event = await post('{"type":"event_callback","event_id":"Ev1","event":{"type":"message"}}', "application/json");
    expect(await event.json()).toHaveProperty("received");
  });
});
