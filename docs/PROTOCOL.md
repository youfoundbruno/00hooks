# 00hooks protocol (v2)

The contract between the relay (`relay/`) and its clients (the `00hooks` CLI and the `hooks-client`
crate). Both sides test against this document; a change here is a version bump. Everything below is
implemented except where marked *(later)*.

All JSON is UTF-8 with camelCase keys. Times are Unix milliseconds. Ids are lowercase base32
(Crockford, no padding) with a prefix: `acc_`, `dev_`, `hk_`, `evt_`, `enr_`, `key_`.

## 0. Versions

Version 2 seals every event to the devices' keys (§5). That isn't additive: an event loses its
`body` and `headers`, and a version 1 client could read nothing. So the stream is versioned and
negotiated, and everything else stays compatible:

- `GET /v1/info` says `protocol` (the version the relay prefers) and `protocols` (every version it
  serves; this relay serves `[2]`). A client picks the highest version both speak; a client that
  finds none tells the person to update (the version 1 CLI compares `protocol` with its own `1` and
  says exactly that).
- `GET /v1/stream` must carry `X-00h-Protocol: 2`. Without it, or with a version the relay doesn't
  serve, the relay answers `400` `invalid` with `field: "X-00h-Protocol"` and `protocols`, never a
  stream of events the client can't open.
- The management API keeps its `/v1/` paths and only gains fields and routes, so a version 1 client
  can still list and manage hooks.

Version 2 changes from 1: devices publish a sealing key (§2); events are sealed and relay-signed
(§5); `ready` gains `protocol` and `sealKid`, and `gap` gains the reason `no_key` (§6); new presets
and strict mode (§3); API keys, the audit log and the events list (§9); the error `forbidden` (§8).

Additive within version 2 (webhook channels): the `meta` preset and its GET handshake (§3, §4);
TwiML answers for Twilio deliveries (§4); a hook's `offlineNotice` (§3, §4a); and `notice` in the
sealed content (§5). A client that ignores them keeps working.

## 1. Signed requests

Every `/v1/*` request except account creation and enrolment is signed by a **device**. A device has an
Ed25519 key pair; the private key never leaves the machine (OS keychain, or a 0600 file fallback).

Headers:

```
X-00h-Device:    dev_…               the device id
X-00h-Time:      1792233600000       now, ms
X-00h-Nonce:     22 random base64url chars (128 bits)
X-00h-Signature: base64url(ed25519_sign(canonical))
```

The canonical string is these lines joined with `\n`:

```
00hooks-v1
<X-00h-Device>
<host: exactly the Host header, lowercase, IPv6 in brackets, :port only when not the default>
<METHOD>
<path and query, exactly as sent>
<X-00h-Time>
<X-00h-Nonce>
<hex sha256 of the raw body; of the empty string when there is none>
```

The device id is signed so a signature can't be presented as another device's. The relay builds the
host and path lines from the request URL it received (`new URL(request.url)`), which matches what the
client sent because Workers don't rewrite the path or query. `POST /v1/enrolments` and
`POST /v1/hooks/<id>/rotate` have no body, so their last line is the empty string's hash.

The relay refuses (`401`, body `{"error":"…"}`, never saying which check failed in detail):
- a time more than 300 s from its clock;
- a nonce already seen for that device in the last 600 s (nonces are stored in the account's Durable
  Object, so the check is strongly consistent; GET requests spend nonces too, because a replayed
  stream request would be a live copy of the account's events);
- an unknown or revoked device, or a bad signature.

A client whose clock is off sees `401` with `{"error":"clock_skew","serverTime":…}` and may retry
once with the server time offset; `00hooks doctor` reports the skew.

All base64url values in this section (`publicKey`, the nonce, the signature) are **unpadded**
(RFC 4648 §5 without `=`): a public key is 43 characters, a signature 86.

### Example

Both sides test against this vector (`cli/hooks-client/src/signing.rs`, and the relay's tests).
Ed25519 is deterministic, so the signature is fixed.

| | |
|---|---|
| private key seed (hex) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| public key | `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg` |
| `X-00h-Device` | `dev_0123456789abcdefghjkmnpq` |
| request | `POST https://relay.example.com/v1/hooks?limit=10` |
| `X-00h-Time` | `1792233600000` |
| `X-00h-Nonce` | `AAECAwQFBgcICQoLDA0ODw` (the bytes `00`…`0f`) |
| body (exact bytes) | `{"name":"ci","verify":{"preset":"github"}}` |
| body sha256 | `871ec9aaacf62bacee0fb97ada9c29fed342cd0d7a3a07731570385a03c17a4c` |

The canonical string (eight lines, `\n` between them, no trailing newline):

```
00hooks-v1
dev_0123456789abcdefghjkmnpq
relay.example.com
POST
/v1/hooks?limit=10
1792233600000
AAECAwQFBgcICQoLDA0ODw
871ec9aaacf62bacee0fb97ada9c29fed342cd0d7a3a07731570385a03c17a4c
```

`X-00h-Signature`:
`_nBVrNWhRGN_JWnxbDBmQjNFDXz5APg0zqD6eCXe7EeJptiP0-Xb1czIn-r0p9faavla1rF7dhbtotQ3OTR1DA`

With no body, the last line is the hash of the empty string,
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## 2. Accounts and devices

A device has two keys: the Ed25519 **signing key** of §1 and an X25519 **sealing key** that events
are sealed to (§5). Both private halves stay on the machine. The sealing key's id (its **kid**) is the
first 16 bytes of `SHA-256("00hooks-seal-kid-v1\n" ‖ raw public key)`, unpadded base64url (22
characters); both sides compute it.

- `POST /v1/accounts` `{ "deviceName": "…", "publicKey": "<base64url ed25519 public key>",
  "sealKey": "<base64url x25519 public key>" }` → `201` `{ "accountId", "deviceId" }`. `sealKey` is
  optional for compatibility (the reference client always sends it); a device without one receives
  every event as a `no_key` gap (§6). A sealing key is 32 bytes, unpadded base64url (43 characters)
  in its one spelling, and is refused (`400` `invalid`, `field: "sealKey"`) when it's malformed or a
  low-order point (the relay seals to it once on the spot; a point whose shared secret would be all
  zeros fails). When the relay has a `SIGNUP_TOKEN` secret, the request must carry
  `Authorization: Bearer <SIGNUP_TOKEN>`; without the secret, signups are open (development only;
  `/v1/info` says so).
- `POST /v1/enrolments` (signed) → `{ "code": "ABCD-EFGH-JKMN", "expiresAt" }`: a one-time code,
  valid 10 minutes, for adding another device to the same account. A code is 12 Crockford base32
  characters (60 random bits) in three groups of four; redeeming reads it case-insensitively, ignores
  dashes and spaces, and takes `I`/`L` as `1` and `O` as `0`.
- `POST /v1/enrolments/redeem` `{ "code", "deviceName", "publicKey", "sealKey"? }` →
  `{ "accountId", "deviceId" }`.
  Limits, all answering `429` `rate_limited` with `Retry-After`, keyed on the client address (an IPv4
  address, or an IPv6 address's /64):
  - at most 10 redemptions a minute per address and 300 a minute in all (the Rate Limiting binding,
    checked before anything else);
  - every attempt is counted, atomically, **before** the code is looked at, and a right code is
    refunded; the attempt after five wrong codes in 10 minutes blocks the address for 10 minutes,
    so parallel guesses each count.
- `GET /v1/devices` (signed, or an API key with `devices:write`) → `{ "devices": [{ "id", "name",
  "createdAt", "lastSeenAt", "current", "sealKid" }] }` (`sealKid` is null for a device without a
  sealing key; `current` is false for an API key).
- `PUT /v1/devices/<id>/seal-key` (signed, by that device only) `{ "sealKey" }` → `{ "kid" }`: sets or
  replaces the device's sealing key; events appended from then on are sealed to it, and events
  already in the log keep the key they were sealed to (each envelope names its kid). This is how a
  device created before version 2 gets one. Another device (or an API key) gets `403` `forbidden`:
  whoever sets a device's sealing key chooses who can read what is sealed to it.
- `DELETE /v1/devices/<id>` (signed, or an API key with `devices:write`) → `204`: revokes it; its open stream closes at once with `4401`.
  Idempotent: revoking a device of this account that is already revoked answers `204` again and
  closes any stream it still has (so a retry after a failure part-way finishes the job); a device of
  another account, or none, is `404`.
- `POST /v1/enrolments` and `/redeem` answer `200`; a wrong, used or expired code answers `401`
  `unauthorized`. A newly enrolled device **starts at the head** of the log: it doesn't receive the
  older backlog and doesn't hold it back from deletion.
- `GET /v1/info` (unsigned) → `{ "version", "protocol": 2, "protocols": [2], "signupOpen": bool,
  "relayKey", "serverTime" }`. `relayKey` is the relay's Ed25519 public key (unpadded base64url, 43
  characters) that signs every envelope (§5); a client **pins it at login** and refuses envelopes it
  doesn't verify. It is null only on a relay with no `RELAY_SIGNING_KEY`, which takes no deliveries
  (§4) and which the reference client refuses to log in to.

## 3. Hooks

- `POST /v1/hooks` (signed, or `hooks:write`) `{ "name", "verify": <Verify>, "offlineNotice"? }` →
  `201` `{ "hook": <Hook>, "url", "secret"?, "verifyToken"? }`. `secret` appears **only here** and
  only when the relay generated it; so does `verifyToken` (a `meta` hook's, when the caller gave
  none). `offlineNotice` is §4a's, for the presets that can carry one.
- `GET /v1/hooks` (`hooks:read`) → `{ "hooks": [<Hook>] }`; `GET /v1/hooks/<id>` → `<Hook>`.
- `PATCH /v1/hooks/<id>` (`hooks:write`) `{ "name"?, "enabled"?, "maxBodyBytes"?, "offlineNotice"? }`
  → `<Hook>`. `"offlineNotice": null` clears it.
- `POST /v1/hooks/<id>/rotate` (`hooks:write`) → `{ "secret" }`; the previous secret keeps working for
  24 h. Only for presets whose secret the relay generates; a provider-issued secret (Stripe, Slack,
  Linear, Shopify, Twilio) is rotated at the provider, and a strict hook's secret is on the devices:
  both answer `409` `conflict`.
- `DELETE /v1/hooks/<id>` (`hooks:write`) → `204`. Events already in the log stay until acknowledged.

`Hook`: `{ "id", "name", "url", "enabled", "verify": { "preset", …non-secret fields }, "maxBodyBytes",
"createdAt", "lastEventAt", "offlineNotice": { "text", "afterMinutes" } | null }`.

### Presets

The presets are a declarative table in the relay (`relay/src/presets.ts`, `SPECS`), mirrored by the
client for strict mode (`cli/hooks-client/src/presets.rs`): which header carries the signature and how
it is written, which bytes are signed, the key's form, the timestamp rule, the replay marks and where
the event type comes from. Both are held to the same vectors (`fixtures/presets.v1.json`: the
providers' published examples where they publish one, and vectors computed from the documented
scheme with Node's own crypto where they don't).

| `preset` | `Verify` fields | secret | check |
|---|---|---|---|
| `github` | `secret`? | generated when absent | `X-Hub-Signature-256: sha256=<hex HMAC-SHA256(body)>`; answers GitHub's `ping` like any event |
| `standard-webhooks` | `secret`? (`whsec_` + base64) | generated when absent | `webhook-signature: v1,<base64 HMAC-SHA256(id.timestamp.body)>` (any of several, space-separated), `webhook-timestamp` within 300 s |
| `standard-webhooks-ed25519` | `publicKey` (`whpk_` + base64, 32 bytes) | none: the relay holds only the sender's **public** key, returned in `Hook.verify` | `webhook-signature: v1a,<base64 Ed25519(id.timestamp.body)>`, timestamp within 300 s. A relay breach can't forge these |
| `stripe` | `secret` (required: Stripe issues it) | provider's | `Stripe-Signature: t=<s>,v1=<hex>[,v1=…]`: HMAC-SHA256 of `t.body` with the secret's UTF-8 bytes; any `v1` may match (Stripe sends two while you roll the secret); `t` within 300 s |
| `slack` | `secret` (required) | provider's | `X-Slack-Signature: v0=<hex HMAC-SHA256("v0:" ts ":" body)>`, `X-Slack-Request-Timestamp` within 300 s; answers `url_verification` (below) |
| `linear` | `secret` (required) | provider's | `Linear-Signature: <hex HMAC-SHA256(body)>`; the body's `webhookTimestamp` (ms, signed) within **60 s** |
| `shopify` | `secret` (required) | provider's | `X-Shopify-Hmac-Sha256: <base64 HMAC-SHA256(body)>` |
| `meta` | `secret` (required: the app secret), `verifyToken`? (8 to 200 printable characters) | provider's; the verify token is generated when absent | `X-Hub-Signature-256: sha256=<hex HMAC-SHA256(body)>` under the app secret (WhatsApp Cloud API, Messenger, Instagram); answers the GET handshake (§4) |
| `twilio` | `secret` (required: the auth token) | provider's | `X-Twilio-Signature: <base64 HMAC-SHA1>` over the **public URL the relay was reached at**, then, for a form body, every parameter name and value (names sorted by code point, each name's distinct values sorted); for a JSON body, the URL alone, whose `bodySHA256` query parameter must equal the body's hex SHA-256. Tried with the URL as reached, without its port, and with the scheme's default port, as Twilio's own libraries do |
| `hmac` | `header` (required), `algorithm` (`sha256` default, or `sha1`), `encoding` (`hex` default, or `base64`), `prefix`?, `secret`? | generated when absent | HMAC of the raw body |
| `token` | `header` (default `Authorization`), `secret`? | generated when absent | constant-time compare with `Bearer <secret>` (or the raw value for other headers); medium strength; **no dedupe** |
| `unverified` | — | — | accepts anything; events carry `verified: false`; **no dedupe** |

Every preset except `unverified` also takes `"strict": true` (below). A `secret` is 8 to 512
characters; the relay refuses to create a hook of a provider-issued preset without one (`400`,
`field: "verify.secret"`), since it can't make one the provider would use.

What each preset's signature covers, what the relay uses besides, and its replay marks (a delivery is
a duplicate when **any** mark was seen in the last 7 days):

| `preset` | signed | used but **not** signed (the sender's claim) | replay marks | `eventType` |
|---|---|---|---|---|
| `github` | the body | `X-GitHub-Delivery`, `X-GitHub-Event` | the delivery id, the body's hash | `X-GitHub-Event` (claimed) |
| `standard-webhooks` | `webhook-id`, `webhook-timestamp`, the body | — | `webhook-id` | the body's `type` (signed) |
| `standard-webhooks-ed25519` | `webhook-id`, `webhook-timestamp`, the body | — | `webhook-id` | the body's `type` (signed) |
| `stripe` | `t`, the body (with the event's `id` and `type`) | — | the body's `id`, the body's hash | the body's `type` (signed) |
| `slack` | the timestamp, the body | `X-Slack-Retry-Num` (kept, not used) | the body's `event_id` (Events API), the body's hash | the body's `event.type`, else `type` (signed) |
| `linear` | the body (with `webhookTimestamp` and `type`) | `Linear-Delivery` | the delivery id, the body's hash | the body's `type` (signed) |
| `shopify` | the body | `X-Shopify-Webhook-Id`, `X-Shopify-Topic` | the webhook id, the body's hash | `X-Shopify-Topic` (claimed) |
| `twilio` | the URL and the form parameters (or the URL, with the JSON body's hash in it) | `I-Twilio-Idempotency-Token` | the token, the body's hash | none |
| `meta` | the body | — | the body's hash (Meta sends no delivery id, and retries the same body) | the body's `object` (signed): `whatsapp_business_account`, `page`, `instagram` |
| `hmac` | the body | — | the body's hash | none |
| `token` | nothing (the token proves the sender knows the secret; the body has no integrity) | — | none | none |
| `unverified` | nothing | — | none | none |

Where the id a provider sends is **not** signed (GitHub, Linear, Shopify, Twilio), someone who
captured one delivery could resend it under a new id; the body-hash mark answers that as a duplicate.
The cost: two genuinely different deliveries with byte-identical bodies within 7 days are stored
once. GitHub, Shopify and Twilio sign no timestamp and retry for hours, so for them these marks are
the only replay defence. Marks are stored as keyed hashes (HMAC-SHA256 under `HASH_PEPPER` of the hook
id and the mark), never the ids themselves: an event id read from a body is content too.

**Slack's endpoint check.** A `slack` delivery whose body is `{"type":"url_verification",
"challenge":…}` is answered `200` `text/plain` with the challenge (at most 200 characters of
`[A-Za-z0-9._~-]`, or it is treated as an ordinary event) **after** the signature verifies, and it is
not stored: it carries no event. GitHub's `ping` (sent when a webhook is created) is verified, deduped
and stored as a normal event with `eventType: "ping"`, so a new hook can be tested end to end.

**Meta's endpoint check.** Before Meta sends anything to a callback URL it asks
`GET /h/<hookId>?hub.mode=subscribe&hub.verify_token=…&hub.challenge=…`. A `meta` hook keeps its
verify token only as `HMAC-SHA256(HASH_PEPPER, "verify-token:" hookId ":" token)`; the relay answers
`200` `text/plain` with the challenge (at most 200 characters of `[A-Za-z0-9._~-]`) only when the
token it carries hashes to that, compared in constant time. Anything else (another mode, a missing
or unsafe challenge, a wrong token) is `401` `signature`, counted like a failed verification; nothing
is stored. Hooks of other presets answer `GET` with `404`. The verify token is not a signing secret
(it proves nothing about later deliveries), so a strict `meta` hook keeps it at the relay too.

`maxBodyBytes` is at most 1,835,008 (bodies live in 2 MB SQLite rows; larger ones move to R2 in a
later phase). Secrets are stored encrypted with the relay's `SECRETS_KEY` (AES-256-GCM, the hook id
as associated data), never returned after creation.

### Strict mode: verify on your devices

`"strict": true` keeps the provider's secret **off the relay**: it is never sent there (`secret` and
`publicKey` are refused with `400`), and only the devices hold it (the reference client keeps it in
the keychain beside the device keys). The relay then checks only what needs no secret, seals the raw
body together with the signature headers and the URL, and each device verifies the provider's
signature itself:

- **At the edge**: size and rate as always; the preset's signature header must be present and well
  formed; a timestamp the provider puts in a **header** (Stripe's `t`, Slack's, Standard Webhooks')
  must be within its window. The body is never parsed. Replay marks are the **body hash only**:
  an unverified sender must not be able to burn an id a genuine delivery will need later, and a
  forger can't predict a future genuine body. Events are stored `verified: false`, `strict: true`,
  with `eventType` only from a header (GitHub, Shopify) and otherwise null.
- **Sealed for the device**: the kept headers plus the signature header and every header the signed
  content or timestamp uses (`webhook-id`, `x-slack-request-timestamp`…), and `url`, the public URL
  the relay was reached at (Twilio signs it).
- **On the device**: the same table and vectors as the relay; timestamps are checked against the
  event's `receivedAt` (signed by the relay, §5), not the device's clock, so an event read days later
  still verifies; a body timestamp (Linear's) is checked there too. A verified event is handed over
  with `verified: true` and the type read from the signed body; one that doesn't verify, or for
  which the device has no secret, is quarantined (recorded raw, §7), never handed over.

Trade-offs, for choosing it:

| | relay verifies (default) | strict |
|---|---|---|
| who holds the provider's secret | the relay (encrypted under `SECRETS_KEY`) and the provider | your devices and the provider |
| a relay breach can | forge events (with the secret) | not forge events |
| junk at the edge | refused `401` before it's stored | stored until a device refuses it (well-formed header, fresh header timestamp, new body); it costs quota and is visible as quarantined events |
| replay marks | provider ids and body hashes | body hashes at the edge; timestamps checked on the device |
| `eventType` for routing | from the signed body | header-borne types only (the relay never reads the body) |
| relay-generated secrets, rotation | the relay generates and rotates (24 h overlap) | the device generates; rotation happens on the device |
| every device | receives verified events | needs the hook's secret to verify (copy it with the CLI) |

The payload is in the relay's memory for an instant in both modes: it has to be, to seal it. Strict
mode removes the secret, and the parsing, not the transit.

## 4. Receiving

`POST /h/<hookId>` (also PUT and PATCH; `GET` is only ever §3's Meta endpoint check). In order:

0. A relay whose rate limit bindings or `RELAY_SIGNING_KEY` are missing refuses everything here with
   `503` `unavailable` (it fails closed rather than take a flood at full cost, or take events it
   couldn't seal).
1. Rate limit per client address (an IPv4 address, or an IPv6 /64; 600 requests per 10 s by
   default), **before** the hook is looked up → `429` `rate_limited` with `Retry-After`. Guessing hook
   ids costs the guesser this budget, not the relay a database read each.
2. Unknown or disabled hook → `404`. Body declared larger than the hook's `maxBodyBytes` (default
   1 MiB) in `Content-Length` → `413`.
3. Rate limit per hook (60 requests per 10 s by default) → `429` with `Retry-After`. Only then is the
   body read, and a body that turns out larger than the limit while streaming → `413`.
4. Verify with the preset (for a strict hook, the edge checks of §3) → `401` `{"error":"signature"}`
   on failure (counted per hour in the audit, §9, never stored).
5. A handshake the preset answers (Slack's `url_verification`) → answered, not stored.
6. Dedupe → a duplicate (any of the delivery's marks seen before) answers `200` `{"duplicate":true}`
   and is not stored again.
7. Quota: an account's log holds at most `ACCOUNT_MAX_EVENTS` events (default 10,000) and
   `ACCOUNT_MAX_BYTES` of sealed envelopes (default 256 MiB; an event costs its sealed size once per
   device) waiting for acknowledgement; past either → `429` `quota` with `Retry-After: 60`.
   Acknowledging (or retention) frees it.
8. Seal the content to every active device that has a sealing key, sign each envelope (§5), and
   append the event, its envelopes and its dedupe marks in one Durable Object transaction → `200`
   `{"received": "<evt_…>"}`. The account's object takes no other request while it seals (the seq is
   part of what is sealed), and the plaintext is never written to storage or logs.

**Answers a provider reads.** A `twilio` delivery is answered with TwiML instead of JSON, `200`
`text/xml`: `<?xml version="1.0" encoding="UTF-8"?><Response></Response>`, or, when §4a's notice is
due, `<Response><Message>…</Message></Response>` with the notice's text XML-escaped. A duplicate gets
the empty one. A Slack slash command that gets a notice is answered
`{"response_type":"ephemeral","text":…,"received":…}`; every other delivery keeps the JSON above.

## 4a. Offline notices

While your devices are off, the relay can answer a sender at once with a fixed notice the hook
carries ("Thanks, we got your message and will reply soon."). It is not an answer to what they
wrote: the relay never reads a message to choose a reply, and nothing is answered by a model.

- **Only where the provider takes a reply in the webhook's response**: `twilio` (SMS and WhatsApp
  through Twilio, as TwiML) and `slack` (slash commands only; events can't be answered that way).
  Providers that need an API call to answer (Meta's WhatsApp Cloud API, Messenger, Instagram) can't
  have one: setting it is `400` `invalid` with `field: "offlineNotice"`.
- `offlineNotice`: `{ "text": 1–320 characters, no control characters but line breaks,
  "afterMinutes": 1–10080 }`.
- **When it is sent**, decided by the account's object in the same transaction as the append:
  1. the delivery verified at the relay (never for a strict hook, whose sender the relay can't vouch
     for) and is a message from a sender it can name: Twilio's `From` on an incoming message (it has
     a `MessageSid` and no `MessageStatus`), Slack's `team_id` and `user_id` on a slash command;
  2. no device stream is connected, and none has been for `afterMinutes`. A stream counts as
     connected while its socket is open and has shown life in the last 90 s (it opened, or answered
     the Worker's 30 s ping); the object notes when the last one went;
  3. this sender hasn't had a notice from this hook in the last 24 hours.
- **What is kept**: the sender only as `HMAC-SHA256(HASH_PEPPER, "notice:" hookId ":" sender)` with
  the time, for 24 hours, then pruned by the alarm. No address, no text.
- The event is stored and delivered as always, and its sealed content says `"notice": true` (§5),
  so the device can show that the sender was answered.

## 5. Events

An event, as one device receives it in `event: hook` (each device gets its own envelope):

```json
{
  "seq": 42,
  "id": "evt_…",
  "hookId": "hk_…",
  "receivedAt": 1792233600000,
  "verified": true,
  "strict": false,
  "preset": "github",
  "eventType": "pull_request",
  "sealed": { "kid": "<22 chars>", "enc": "<43 chars>", "ct": "<standard base64, padded>" },
  "sig": "<86 chars>"
}
```

- `seq` is per account, strictly increasing, never reused.
- `seq`, `id`, `hookId`, `receivedAt`, `verified`, `strict`, `preset` and `eventType` are the relay's
  **routing metadata**: in the clear, visible to the relay's operator, and signed by the relay.
- `eventType` comes from the preset (§3's table) or is `null`, at most 200 characters. **For
  `github` and `shopify` it is the sender's claim, not authenticated**: those providers sign only the
  body, so treat it as a label and read the type from the body where it matters.
- `verified` is the relay's verdict. For a strict hook it is `false` (the relay didn't check), and the
  client sets it after verifying (§3).

**What is sealed** (the plaintext): the UTF-8 JSON `{"headers": {…}, "contentType": … | null,
"url"?: "…", "notice"?: true}`, one newline byte (`0x0a`), then the raw body bytes. JSON has no raw
newline, so the first one is the boundary. `notice` is present when the relay answered this delivery
with the hook's offline notice (§4a); a client reads it only from the sealed content.

- `headers` keeps only an allowlist per preset (the provider's event and delivery headers,
  `content-type`, `user-agent`, and the runner's loop-prevention headers `00hooks-origin` and
  `00hooks-hop`), lowercased, each value at most 1,024 characters. None of them is
  covered by a signature. Never `cookie`, `authorization`, or any signature or token header: once
  verified they're no use to a reader, and a stored signature beside its body is a ready-made replay.
  A strict hook's envelope is the exception: it carries the signature headers its device needs
  (§3), sealed.
- `contentType` is the sender's `Content-Type`, at most 200 characters; `url` (strict hooks only) is
  the public URL the relay was reached at.

**How it is sealed**: HPKE (RFC 9180) base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
ChaCha20-Poly1305 (suite `0x0020, 0x0001, 0x0003`), single-shot, to the device's sealing key:

- `info` = the UTF-8 bytes of `00hooks seal v1`;
- `aad` = the UTF-8 bytes of `00hooks-seal-v1\n<hookId>\n<seq>\n<id>`, so a stored ciphertext can't
  be moved to another event, hook or position;
- `kid` names the device key (§2), so keys can be replaced; `enc` is the encapsulated key (unpadded
  base64url); `ct` the ciphertext with its tag (standard padded base64).

**The relay's signature**: `sig` is the unpadded base64url Ed25519 signature, under the key published
as `relayKey` (§2), of these lines joined with `\n` (no trailing newline):

```
00hooks-envelope-v1
<the receiving device's id>
<seq>
<id>
<hookId>
<receivedAt>
<verified: 1 or 0>
<strict: 1 or 0>
<preset>
<eventType: "-" when null, otherwise base64url (unpadded) of its UTF-8>
<sealed.kid>
<sealed.enc>
<hex SHA-256 of the ciphertext bytes>
```

HPKE alone says nothing about who sealed (anyone with a device's public key can seal to it); the
signature says it was this relay, for this device, with this metadata. A client:

1. verifies `sig` with the `relayKey` it pinned at login (§2);
2. opens `sealed` with the private key named by `kid`, with the `info` and `aad` above;
3. for a strict event, verifies the provider's signature (§3);

and hands over the event with `headers`, `contentType` and `body` (standard base64) restored, as in
version 1, so what runs automations never sees an envelope. An event that fails any step is
quarantined (§7), never handed over. A version 2 client also refuses an event that arrives
**unsealed**.

`fixtures/seal-interop.v1.json` holds events sealed by the relay's own code under Node, with the
fixed device key that opens them; `fixtures/hpke-rfc9180-a2.json` is RFC 9180's vector for this suite.
Both the relay's tests and the CLI's run them.

## 6. Streaming

`GET /v1/stream` (signed by a device; never an API key), `Accept: text/event-stream`,
`X-00h-Protocol: 2` (§0), optional `Last-Event-ID: <seq>`.

Response headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache, no-transform`,
`X-Accel-Buffering: no`.

The stream sends, in order:

```
retry: 5000

event: ready
data: {"accountId":"…","deviceId":"…","after":40,"head":42,"protocol":2,"sealKid":"…"}

id: 41
event: hook
data: {…event…}

id: 42
event: hook
data: {…event…}

: hb
```

- **Where it starts**: after `max(Last-Event-ID, this device's acknowledged seq)`. `ready.after` says
  which; `ready.head` is the newest seq in the log. `ready.sealKid` is the kid of the sealing key the
  relay holds for this device (null when it has none): a client that doesn't hold that key, or sees
  null, should say so, since new events will be sealed to a key it can't use (or not at all).
- **Gaps**: when events after that point were already dropped by retention, a `gap` event comes before
  the next `hook`: `id: 30` `event: gap` `data: {"from": 12, "to": 30, "reason": "retention"}`
  (inclusive range of lost seqs; the `id` is `to`, so a resume starts after the gap). `reason` is
  `retention`; `no_key` for a single event with no envelope for this device (it had no sealing key
  when the event arrived: the relay keeps no plaintext to seal it later); or `too_large` for a single
  event whose message would pass the WebSocket message limit between the relay's Worker and its
  Durable Object (32 MiB). That can't happen within this version's limits (the largest event, a
  1,835,008-byte body sealed and base64-encoded with its headers, is under 2.5 MB); the rule exists
  so one undeliverable event can never wedge a stream.
- `Last-Event-ID` beyond the head is clamped to the head; one that isn't a number answers `400`
  `invalid`.
- **Heartbeat**: a comment line `: hb` every 15 s.
- **Backpressure**: when more than 256 KiB is waiting to be written, the relay stops queueing and, once
  the client drains, sends `event: resync` `data: {"after": <last seq written>}` and **ends the stream**
  (no `closed` event); the client reconnects at once with that `Last-Event-ID`. A client that reads nothing for 60 s is closed with `4408`.
- **Closing**: before closing, the relay sends `event: closed` `data: {"code": <code>, "reason": "…"}`:

| code | meaning | client should |
|---|---|---|
| `4401` | the device was revoked or the signature no longer holds | stop; ask the person to log in again |
| `4408` | too slow to read | reconnect at once |
| `4409` | a newer stream for this device replaced this one | stop (another process is listening) |
| `1012` | the relay is restarting (deploy) | reconnect with jitter |

- **Reconnecting**: on any drop without a terminal code, wait a random time between half and all of
  `min(30 s, retry × 2^attempt)`, never under 1 s, then reconnect; `attempt` resets after `ready`.
  70 s without a byte (heartbeats included) counts as a drop. Re-sign every attempt (fresh time and
  nonce).
- **One stream per device**: a second stream for the same device replaces the first (`4409`).
- **Probe**: `GET /v1/stream?probe=1` (signed, `X-00h-Protocol: 2`) answers `retry`, `ready` and
  `closed {"code":1000,"reason":"probe"}`, then ends, without replacing the device's live stream and
  without sending events (for `00hooks doctor`).
- *(later)* per-hook delivery, so a device receives only the hooks routed to it: today every active
  device with a sealing key gets an envelope for every event, and filters locally.

How the relay serves it (informative): the Worker holds the SSE response and connects to the
account's Durable Object over a WebSocket that the object accepts with the hibernation API, so the
object costs nothing while idle. The Worker pings every 30 s (answered by the object's auto-response
without waking it) and closes the stream with `1012` when no pong arrives for 75 s. Clients see only
SSE.

## 7. Acknowledging

`POST /v1/ack` (signed) `{ "through": 42 }` → `{ "acked": 42 }`. Acknowledge only after the event is
recorded locally (not after acting on it). Acks are per device and monotonic: a lower value is
ignored. A device's own envelopes are deleted as soon as it acknowledges them; an event acknowledged by
every device is deleted; unacknowledged events are kept 7 days (`RETENTION_DAYS`), then dropped,
which shows up as a `gap`.

Clients dedupe by `id` before acting, so at-least-once delivery never runs an automation twice.
The reference client records an event (opened) before acknowledging it, and then hands it to its
consumer. By default it marks the event handed-over as it does (at most once to the consumer); a
consumer that records durably itself can ask to **confirm** instead (`SubscribeOptions::confirm`,
then `Subscription::confirm(id)` after its own record): an unconfirmed event is handed over again
after a restart, with the same `id`, so nothing is lost between the two records.

Because acks are cumulative, a client keeps an ack that failed and retries it with backoff (any later
ack covers it too) while it goes on recording and handing over newer events in order; otherwise the
relay keeps those events, and they hold every other device's deletions back, until retention. A
`hook` message a client can't read, open or verify (a bad relay signature, an unknown kid, a strict
event whose provider signature fails, an unsealed event) still counts as received: the client
records it raw (the reference client appends it to `quarantine.jsonl` in its state directory, with
the reason, and says so) before acknowledging past it, so nothing is skipped silently.

## 8. Errors

Every error body is `{ "error": "<code>", "message": "<one plain sentence>" }`. Codes: `unauthorized`,
`clock_skew`, `not_found`, `too_large`, `rate_limited`, `quota` (a `429`: the account's log is full),
`signature`, `invalid` (with `field`), `conflict`, `forbidden` (a `403`: an API key without the
scope, or a route only a device may use), `unavailable` (a `503`: the relay is missing a safety
binding or its signing key and refuses rather than run without it), `internal` (a `500`; the relay logs the
cause, never the payload). Messages never contain secrets, signatures or payload content.

## 9. API keys, the audit log and the events list

**API keys** are for management and CI. A device creates them; they can never open the stream.

- `POST /v1/keys` (signed by a device) `{ "name", "scopes": [<scope>…], "expiresInDays"? }` → `201`
  `{ "key": <ApiKey>, "token" }`. `expiresInDays` is 1 to 365 (default 90). The `token` appears **only
  here**: `hk_` + the key id's 26 characters + `_` + 32 random bytes in unpadded base64url (43
  characters). The relay keeps only a salt and `HMAC-SHA256(HASH_PEPPER, "apikey:" salt ":" secret)`.
- `GET /v1/keys` (device) → `{ "keys": [<ApiKey>] }` (revoked keys aren't listed; expired ones are,
  with their `expiresAt`).
- `DELETE /v1/keys/<id>` (device) → `204`, idempotent; another account's key is `404`.

`ApiKey`: `{ "id": "key_…", "name", "scopes", "createdAt", "createdBy": "dev_…", "expiresAt",
"lastUsedAt" }`.

A key is presented as `Authorization: Bearer hk_…` (with no `X-00h-Device` header). An unknown, wrong,
revoked or expired key is `401` `unauthorized`, the same answer for each. A key without the route's
scope, or on a route only a device may use, is `403` `forbidden`.

| scope | allows |
|---|---|
| `hooks:read` | `GET /v1/hooks`, `GET /v1/hooks/<id>` |
| `hooks:write` | `POST /v1/hooks`, `PATCH`/`DELETE /v1/hooks/<id>`, `POST /v1/hooks/<id>/rotate` |
| `events:read` | `GET /v1/events` |
| `devices:write` | `GET /v1/devices`, `DELETE /v1/devices/<id>` |
| `audit:read` | `GET /v1/audit` |
| *(device only)* | `/v1/stream`, `/v1/ack`, `/v1/enrolments`, `PUT /v1/devices/<id>/seal-key`, `/v1/keys` |

The device-only routes are what would turn a stolen key into a reader of the account's events (a
stream, a new device, a sealing key) or into more keys.

**The audit log**: `GET /v1/audit?since=<ms>&limit=<1–500, default 100>` (device, or `audit:read`) →
`{ "entries": [{ "at", "kind", "actor", "subject", "name", "count"? }] }`, newest first, kept 90 days.
Names and ids only: never a secret, a token, a header value or a payload.

| `kind` | `subject` | `actor` | `name` |
|---|---|---|---|
| `hook.created`, `hook.rotated`, `hook.deleted` | the hook | the device or key | the hook's name |
| `device.added` | the new device | itself (new account), or the device that issued the enrolment code | its name |
| `device.revoked` | the device | the device or key | its name |
| `device.seal_key` | the device | itself | the new kid |
| `key.created`, `key.revoked` | the key | the device | the key's name |
| `key.used` | the key | the key | the key's name; `count` uses in the hour starting at `at` |
| `verify.failed` | the hook | null | the hook's name, while it exists; `count` failures in the hour starting at `at` |

**The events list**: `GET /v1/events?limit=<1–500, default 50>` (device, or `events:read`) →
`{ "events": [{ "seq", "id", "hookId", "receivedAt", "verified", "strict", "preset", "eventType",
"size", "deliveredTo": [dev…], "pendingFor": [dev…] }] }`: the events still in the log, newest first,
metadata only. `size` is the bytes held for it (its envelopes).
