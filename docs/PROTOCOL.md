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

Additive within version 2 (the screen, §4b): a hook's edge screen (`/v1/hooks/<id>/screen`), the
account's screen key (`/v1/screen/key`), the hold (`/v1/held`), `screen` and `extras` in
`/v1/info`, `screenRules` in `Hook`, `origin` in the sealed content (§5), and released events, which
carry `held: true` and a last signed line `held` (§5). A client that predates them keeps working
for every event except a released one, which it can't verify and so quarantines (§7), never
handing it over unverified.

Additive within version 2 (phone links, §10): a kind of device, `phone`, that pairs with one node
device and may use only the phone routes (`/v1/phone/*`); its own versioned socket protocol
(`/v1/info`'s `phone.protocol`, 1); `kind` and `peer` in `GET /v1/devices`; and the audit kinds
`phone.pairing` and `phone.confirmed`. The relay routes the sealed envelopes between a node and its
phones and never sees their content. A client that ignores them keeps working; a phone is refused
everywhere else with `403` `forbidden`.

Additive within version 2 (hardening): the stream's `hook-change` event (§6), which has no `id` and
which a client that predates it ignores; the `hooks:secrets` scope (§9); `scope` in a `quota` error
(§4); and `DELETE /v1/held` (§4b). Some answers are stricter, and a
client that handles the codes of §8 handles them: a hook name already used on the account is `409`
(§3); an API key with `hooks:write` alone gets `403` where the answer would carry a secret (§3);
management requests are rate-limited per address (`429`, §1); an account at its device cap gets
`409` (§2); and a relay with neither a signup token nor `OPEN_SIGNUP=1` refuses signups with `403` (its
`/v1/info` says `signupOpen: false`).

Additive within version 2 (finishing the plan): renaming a device (`PATCH /v1/devices/<id>`, §2);
a hook's `deliverTo` and `response` (§3, §6); the signed test event (`POST /v1/test/<hookId>`,
§3), whose routing `eventType` is `00hooks.test`; and the audit kinds `device.renamed` and
`hook.delivery` (§9). A client that ignores them keeps working: an event its hook delivers to
another device never reaches it, and a test event is an ordinary verified event.

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

Every `/v1/*` request except `GET /v1/info`, signed or not, is first limited per client address (an
IPv4 address, or an IPv6 /64; 300 requests per 10 s by default) → `429` `rate_limited` with
`Retry-After`, before its body is read or anything is looked up.

The relay refuses (`401`, body `{"error":"…"}`, never saying which check failed in detail):
- a time more than 300 s from its clock;
- a nonce already seen for that device in the last 660 s, more than twice the clock window, so a
  request timed at the window's far edge can't be replayed at its other edge (nonces are stored in the account's Durable
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
  `Authorization: Bearer <SIGNUP_TOKEN>` (`401` otherwise). Without the secret, signups are
  **refused** (`403` `forbidden`) unless the operator sets `OPEN_SIGNUP=1` explicitly (development,
  or a relay meant to be open); `/v1/info` says which. Account creation is limited per client address
  (5 a minute by default, `429` `rate_limited`), checked first. A public key that already belongs to a
  device is `409` `conflict`, also when two signups race for it; the account and its first device
  are created together or not at all.
- An account holds at most `ACCOUNT_MAX_DEVICES` node devices (10 by default; phones, §10, aren't
  counted, and revoked devices free their place). At the cap, `POST /v1/enrolments` and the
  redemption answer `409` `conflict`.
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
  "createdAt", "lastSeenAt", "current", "sealKid", "kind", "peer" }] }` (`sealKid` is null for a
  device without a sealing key; `current` is false for an API key; `kind` is `device` or `phone` and
  `peer` a phone's node, null for a device, §10).
- `PUT /v1/devices/<id>/seal-key` (signed, by that device only) `{ "sealKey" }` → `{ "kid" }`: sets or
  replaces the device's sealing key; events appended from then on are sealed to it, and events
  already in the log keep the key they were sealed to (each envelope names its kid). This is how a
  device created before version 2 gets one. Another device (or an API key) gets `403` `forbidden`:
  whoever sets a device's sealing key chooses who can read what is sealed to it.
- `PATCH /v1/devices/<id>` (signed by a device, or an API key with `devices:write`) `{ "name" }` →
  `{ "device": <as GET /v1/devices lists it> }`: renames one of the account's devices (a phone
  too). The name is 1 to 100 characters once trimmed, without control characters (`400` `invalid`,
  `field: "name"`). A revoked device, a phone whose pairing ran out unconfirmed, or another
  account's device is `404`. Audit: `device.renamed`, named by the new name.
- `DELETE /v1/devices/<id>` (signed, or an API key with `devices:write`) → `204`: revokes it; its open stream closes at once with `4401`.
  Revoking a device also revokes every phone paired with it, and revoking a phone tells its node
  (§10.5).
  Idempotent: revoking a device of this account that is already revoked answers `204` again and
  closes any stream it still has (so a retry after a failure part-way finishes the job); a device of
  another account, or none, is `404`.
- `POST /v1/enrolments` and `/redeem` answer `200`; a wrong, used or expired code answers `401`
  `unauthorized`. A newly enrolled device **starts at the head** of the log: it doesn't receive the
  older backlog and doesn't hold it back from deletion.
- `GET /v1/info` (unsigned) → `{ "version", "protocol": 2, "protocols": [2], "signupOpen": bool,
  "relayKey", "serverTime", "screen": { "edge": true, "maxRules": 200, "heldDays" }, "extras": [],
  "phone": { "protocol": 1, "push": { "available": bool, "environment": "sandbox" | "production" |
  null, "platforms": { "ios": { "available": bool, "environment": … }, "android": { "available": bool } } } } }`.
  `signupOpen` is true only when a signup needs no token
  (`OPEN_SIGNUP=1` and no `SIGNUP_TOKEN`). `phone` says the relay carries phone links (§10) and the
  version of their socket protocol; `phone.push.platforms` says, per platform, whether it can wake a
  phone (§10.7): `ios` through APNs, with the APNs environment it sends to (null when it can't), and
  `android` through FCM. `phone.push.available` and `environment` are the same as `ios`'s, for
  clients written before Android.
  `screen` says what the edge screen takes (§4b). `extras` lists the optional hosted extras this
  relay offers (fingerprint sync across devices, reputation lists shared as hashes, a longer hold,
  evaluator credits…), each `{ "id", "title", "description"?, "url"? }`, as the operator sets them
  in `HOSTED_EXTRAS`; it is data, never prices or code, a client shows only what is there, and a
  self-hosted relay announces none. `relayKey` is the relay's Ed25519 public key (unpadded base64url, 43
  characters) that signs every envelope (§5); a client **pins it at login** and refuses envelopes it
  doesn't verify. It is null only on a relay with no `RELAY_SIGNING_KEY`, which takes no deliveries
  (§4) and which the reference client refuses to log in to.

## 3. Hooks

- `POST /v1/hooks` (signed, or `hooks:write`) `{ "name", "verify": <Verify>, "offlineNotice"? }` →
  `201` `{ "hook": <Hook>, "url", "secret"?, "verifyToken"? }`. `secret` appears **only here** and
  only when the relay generated it; so does `verifyToken` (a `meta` hook's, when the caller gave
  none). A hook whose answer would carry either needs a device or an API key with `hooks:secrets`;
  `hooks:write` alone gets `403` `forbidden` and nothing is made (it may still create hooks with a
  supplied secret, or none). `offlineNotice` is §4a's, for the presets that can carry one.
- **Names are unique per account** (1 to 100 characters, compared exactly): creating or renaming a
  hook to a name another of the account's hooks has is `409` `conflict`. Clients that let a person
  refer to a hook by name resolve the name to the hook's id once and keep the id: a hook renamed
  later, or a new hook given a freed name, is a different hook.
- `GET /v1/hooks` (`hooks:read`) → `{ "hooks": [<Hook>] }`; `GET /v1/hooks/<id>` → `<Hook>`.
- `PATCH /v1/hooks/<id>` (`hooks:write`) `{ "name"?, "enabled"?, "maxBodyBytes"?, "offlineNotice"?,
  "deliverTo"?, "response"? }` → `<Hook>`. `null` clears `offlineNotice`, `deliverTo` and `response`.
  - `deliverTo`: a device id. The hook's events are sealed to that device alone, so an automation
    that two machines both run happens once (*the Mac in the office*); every other device's stream
    passes them by without a word (§6). It must be an active device of kind `device` of the account
    with a sealing key (`400` `invalid`, `field: "deliverTo"`). When that device is revoked (or
    loses its key) the hook's deliveries go to every device again rather than to nobody, and the
    events only it could read are deleted with it. Changing it is an audit line `hook.delivery`
    (named by the device id, or `*` for every device).
  - `response`: `{ "status"?: 200–299 but 204 and 205 (200 by default), "contentType"?:
    "text/plain" (default) | "application/json" | "application/xml" | "text/xml", "body"?: at most
    4,096 bytes of UTF-8 (valid JSON for JSON) }`: what the relay answers the provider for a delivery
    it accepts, instead of `{"received": …}`: stored, a duplicate, or dropped by the screen (which
    must look the same). Refusals (`401`, `404`, `413`, `429`) keep their usual answers. It carries
    `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'; sandbox`, and
    never HTML: the relay's origin serves no page someone wrote. A `twilio` hook, answered with TwiML,
    can't have one (`400`, `field: "response"`); a due Slack notice (§4a) takes precedence.
- `POST /v1/hooks/<id>/rotate` (a device, or `hooks:secrets`) → `{ "secret" }`; the previous secret
  keeps working for 24 h. Only for presets whose secret the relay generates; a provider-issued secret (Stripe, Slack,
  Linear, Shopify, Twilio, Meta, Paddle, Zoom, PagerDuty) is rotated at the provider, and a strict hook's secret is on the devices:
  both answer `409` `conflict`.
- `DELETE /v1/hooks/<id>` (`hooks:write`) → `204`. Events already in the log stay until acknowledged.

Every device's stream is told of each hook created, rotated, renamed or deleted (`hook-change`,
§6), so a person notices a change they didn't make (an API key rotating a secret, say).

`Hook`: `{ "id", "name", "url", "enabled", "verify": { "preset", …non-secret fields }, "maxBodyBytes",
"createdAt", "lastEventAt", "offlineNotice": { "text", "afterMinutes" } | null, "screenRules",
"deliverTo": "dev_…" | null, "response": { "status", "contentType", "body" } | null }`
(`screenRules`: how many edge rules the hook's screen has, §4b).

### The test event

`POST /v1/test/<hookId>` (a device, or an API key with `hooks:secrets`: signing with a hook's secret
needs what being shown it does) sends the hook a sample delivery, signed with the hook's own
secret the way its preset's provider signs (the preset table drives it: signed parts, a timestamp
of now, fresh delivery ids so it is never a duplicate), through the hook's own path: rate limits,
verification, the screen, dedupe, sealing and the log apply exactly as to a delivery. The sample is
JSON (`{"type": "00hooks.test", …, "00hooks": {"test": true, "sentAt", "note"}}`; a form for `twilio`),
and the event's routing `eventType` is `00hooks.test`, set by the relay whatever the preset reads,
and signed with the rest of the metadata (§5). → `200` `{ "status": <what the delivery was
answered>, "answer": <its JSON answer, or null>, "eventType": "00hooks.test" }`. A strict hook (its
secret is on the devices) and a `standard-webhooks-ed25519` hook (the relay holds only the public
key) can't be signed for: `409` `conflict`; send a test from the provider. The reference runner
records a test event and runs only the automations whose kinds name `00hooks.test`.

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
| `standard-webhooks-ed25519` | `publicKey` (`whpk_` + base64, 32 bytes) | none: the relay holds only the sender's **public** key, returned in `Hook.verify` | `webhook-signature: v1a,<base64 Ed25519(id.timestamp.body)>`, timestamp within 300 s. A leak of the relay's stored secrets can't forge these; a relay whose code is compromised can still mark anything verified, unless the hook is strict |
| `stripe` | `secret` (required: Stripe issues it) | provider's | `Stripe-Signature: t=<s>,v1=<hex>[,v1=…]`: HMAC-SHA256 of `t.body` with the secret's UTF-8 bytes; any `v1` may match (Stripe sends two while you roll the secret); `t` within 300 s |
| `slack` | `secret` (required) | provider's | `X-Slack-Signature: v0=<hex HMAC-SHA256("v0:" ts ":" body)>`, `X-Slack-Request-Timestamp` within 300 s; answers `url_verification` (below) |
| `linear` | `secret` (required) | provider's | `Linear-Signature: <hex HMAC-SHA256(body)>`; the body's `webhookTimestamp` (ms, signed) within **60 s** |
| `shopify` | `secret` (required) | provider's | `X-Shopify-Hmac-Sha256: <base64 HMAC-SHA256(body)>` |
| `meta` | `secret` (required: the app secret), `verifyToken`? (8 to 200 printable characters) | provider's; the verify token is generated when absent | `X-Hub-Signature-256: sha256=<hex HMAC-SHA256(body)>` under the app secret (WhatsApp Cloud API, Messenger, Instagram); answers the GET handshake (§4) |
| `twilio` | `secret` (required: the auth token) | provider's | `X-Twilio-Signature: <base64 HMAC-SHA1>` over the **public URL the relay was reached at**, then, for a form body, every parameter name and value (names sorted by code point, each name's distinct values sorted); for a JSON body, the URL alone, whose `bodySHA256` query parameter must equal the body's hex SHA-256. Tried with the URL as reached, without its port, and with the scheme's default port, as Twilio's own libraries do |
| `calendly` | `secret`? (Calendly's webhook signing key) | generated when absent | `Calendly-Webhook-Signature: t=<s>,v1=<hex>`: HMAC-SHA256 of `t.body`; `t` within **180 s** (Calendly's documented tolerance) |
| `typeform` | `secret`? | generated when absent | `Typeform-Signature: sha256=<base64 HMAC-SHA256(body)>` |
| `paddle` | `secret` (required: the destination's `pdl_ntfset_…` key) | provider's | Paddle Billing. `Paddle-Signature: ts=<s>;h1=<hex>[;h1=…]` (`;`-separated): HMAC-SHA256 of `ts:body`; any `h1` may match; `ts` within **5 s**, as Paddle's own SDKs check |
| `twitch` | `secret`? (10 to 100 ASCII characters, Twitch's rule) | generated when absent | Twitch EventSub. `Twitch-Eventsub-Message-Signature: sha256=<hex HMAC-SHA256(message id ‖ timestamp ‖ body)>`, the `Twitch-Eventsub-Message-Timestamp` (RFC 3339) within **600 s**; answers `webhook_callback_verification` (below) |
| `zoom` | `secret` (required: the app's secret token) | provider's | `x-zm-signature: v0=<hex HMAC-SHA256("v0:" ts ":" body)>`, `ts` from `x-zm-request-timestamp`. Zoom documents no window, and doesn't say whether its retries (up to 85 minutes later) are signed afresh, so the timestamp is signed but not checked; answers `endpoint.url_validation` (below). Can't be strict |
| `pagerduty` | `secret` (required) | provider's | PagerDuty v3. `X-PagerDuty-Signature: v1=<hex HMAC-SHA256(body)>[,v1=…]`; any `v1` may match |
| `hmac` | `header` (required), `algorithm` (`sha256` default, or `sha1`), `encoding` (`hex` default, or `base64`), `prefix`?, `secret`? | generated when absent | HMAC of the raw body |
| `token` | `header` (default `Authorization`), `secret`? | generated when absent | constant-time compare with `Bearer <secret>` (or the raw value for other headers); medium strength; **no dedupe** |
| `unverified` | — | — | accepts anything; events carry `verified: false`; **no dedupe** |

Every preset except `unverified`, `token` and `zoom` (its endpoint check needs the secret, below)
also takes `"strict": true` (below). A strict `token`
hook would prove nothing on the device (the token reaches the relay in the clear and signs no
content), so the relay refuses it (`400`, `field: "verify.strict"`), as it refuses a strict
`unverified` one, and a device refuses to verify one. A `secret` is 8 to 512
characters; the relay refuses to create a hook of a provider-issued preset without one (`400`,
`field: "verify.secret"`), since it can't make one the provider would use.

What each preset's signature covers, what the relay uses besides, and its replay marks (a delivery is
a duplicate when **any** mark was seen in the last 7 days; for the presets that sign no timestamp,
`github`, `shopify`, `twilio`, `meta`, `typeform`, `zoom`, `pagerduty` and `hmac`, the body-hash
mark is kept `REPLAY_MARK_DAYS`, 180 days by default):

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
| `calendly` | `t`, the body (with its `event`) | — | the body's hash (no event id in the body) | the body's `event` (signed): `invitee.created`… |
| `typeform` | the body (with `event_id` and `event_type`) | — | the body's `event_id`, the body's hash | the body's `event_type` (signed) |
| `paddle` | `ts`, the body (with `event_id` and `event_type`) | — | the body's `event_id`, the body's hash | the body's `event_type` (signed) |
| `twitch` | the message id, the timestamp, the body | `Twitch-Eventsub-Message-Type`, `-Retry`, `-Subscription-Type` and `-Version` (kept, not used) | the message id (a resend keeps it) | the body's `subscription.type` (signed) |
| `zoom` | the timestamp, the body (with its `event`) | — | the body's hash | the body's `event` (signed) |
| `pagerduty` | the body (with `event.id` and `event.event_type`) | `X-Webhook-Id`, `X-Webhook-Subscription` (kept, not used) | the body's `event.id`, the body's hash | the body's `event.event_type` (signed) |
| `hmac` | the body | — | the body's hash | none |
| `token` | nothing (the token proves the sender knows the secret; the body has no integrity) | — | none | none |
| `unverified` | nothing | — | none | none |

Where the id a provider sends is **not** signed (GitHub, Linear, Shopify, Twilio), someone who
captured one delivery could resend it under a new id; the body-hash mark answers that as a duplicate.
The cost: two genuinely different deliveries with byte-identical bodies within 7 days are stored
once. GitHub, Shopify, Twilio, Meta, Typeform, PagerDuty and the generic `hmac` preset sign no
timestamp (Zoom signs one the relay doesn't check), so for them these marks are the only replay
defence: a captured genuine delivery (GitHub shows recent ones, body
and signature, to a repository's admins) verifies forever. That is why their body-hash mark is kept
for `REPLAY_MARK_DAYS` rather than a week. Past it, a replay is accepted as a new event with a new
`evt_` id, so a client that acts on events should also dedupe by the content's hash, kept at least
as long as it keeps anything; the reference runner is meant to. Marks are stored as keyed hashes (HMAC-SHA256 under `HASH_PEPPER` of the hook
id and the mark), never the ids themselves: an event id read from a body is content too.

**Slack's endpoint check.** A `slack` delivery whose body is `{"type":"url_verification",
"challenge":…}` is answered `200` `text/plain` with the challenge (at most 200 characters of
`[A-Za-z0-9._~-]`, or it is treated as an ordinary event) **after** the signature verifies, and it is
not stored: it carries no event. GitHub's `ping` (sent when a webhook is created) is verified, deduped
and stored as a normal event with `eventType: "ping"`, so a new hook can be tested end to end.

**Twitch's endpoint check.** A `twitch` delivery with `Twitch-Eventsub-Message-Type:
webhook_callback_verification` whose body carries a `challenge` (at most 200 characters of
`[A-Za-z0-9._~-]`, or it is treated as an ordinary event) is answered `200` `text/plain` with the
challenge **after** the signature and timestamp verify, and it is not stored. A `revocation`
(Twitch telling you why it ended a subscription) is verified and stored like any event; its type
header is kept with it.

**Zoom's endpoint check.** A `zoom` delivery whose body is `{"event":"endpoint.url_validation",
"payload":{"plainToken":…}}` is answered `200` `application/json` with `{"plainToken",
"encryptedToken"}`, the token's hex HMAC-SHA256 under the secret that verified the delivery, **after**
the signature verifies; it is not stored. The token is read only from a body Zoom signed, so nobody
else can make the relay compute it, and it must be at most 200 characters of `[A-Za-z0-9_-]`: with
no `:` in it, the answer can never be a signature over a `v0:…` delivery. The answer needs the
secret, so a strict `zoom` hook is refused (`400`, `field: "verify.strict"`): Zoom re-checks the
endpoint every 72 hours and would switch the webhook off.

**Meta's endpoint check.** Before Meta sends anything to a callback URL it asks
`GET /h/<hookId>?hub.mode=subscribe&hub.verify_token=…&hub.challenge=…`. A `meta` hook keeps its
verify token only as `HMAC-SHA256(HASH_PEPPER, "verify-token:" hookId ":" token)`; the relay answers
`200` `text/plain` with the challenge (at most 200 characters of `[A-Za-z0-9._~-]`) only when the
token it carries hashes to that, compared in constant time. Anything else (another mode, a missing
or unsafe challenge, a wrong token) is `401` `signature`, counted like a failed verification; nothing
is stored. Hooks of other presets answer `GET` with `404`. The verify token is not a signing secret
(it proves nothing about later deliveries), so a strict `meta` hook keeps it at the relay too.

`maxBodyBytes` is at most 1,835,008 (bodies live in 2 MB SQLite rows; PLAN §3.2 says why larger
bodies don't go to R2). It is 1 MiB by default, and 256 KiB for a strict or `unverified` hook (anyone who
knows its URL can send it junk the relay can't tell from deliveries); `PATCH` raises it. Secrets are stored encrypted with the relay's `SECRETS_KEY` (AES-256-GCM, the hook id
as associated data), never returned after creation.

### Strict mode: verify on your devices

`"strict": true` keeps the provider's secret **off the relay**: it is never sent there (`secret` and
`publicKey` are refused with `400`), and only the devices hold it (the reference client keeps it in
the keychain beside the device keys). The relay then checks only what needs no secret, seals the raw
body together with the signature headers and the URL, and each device verifies the provider's
signature itself:

- **At the edge**: size and rate as always; the preset's signature header must be present and well
  formed; a timestamp the provider puts in a **header** (Stripe's `t`, Slack's, Standard Webhooks',
  Calendly's `t`, Paddle's `ts`, Twitch's) must be within its window. The body is never parsed. Replay marks are the **body hash only**:
  an unverified sender must not be able to burn an id a genuine delivery will need later, and a
  forger can't predict a future genuine body. Events are stored `verified: false`, `strict: true`,
  with `eventType` only from a header (GitHub, Shopify) and otherwise null.
- **Sealed for the device**: the kept headers plus the signature header and every header the signed
  content or timestamp uses (`webhook-id`, `x-slack-request-timestamp`…), and `url`, the public URL
  the relay was reached at (Twilio signs it).
- **On the device**: the same table and vectors as the relay. What the device verifies with is its
  own, never the relay's word:
  - it verifies **every** event of a hook it keeps a strict secret for, whatever the relay's
    `strict` flag says (the reference client keeps an index of those hooks beside its state), so a
    relay can't switch strict mode off;
  - with the `verify` object it built when the secret was kept (the person's preset and fields, and
    for Ed25519 the person's public key), never one fetched from the relay; the event's signed
    `preset` must equal it, and `unverified` and `token` verify nothing in strict mode;
  - timestamps are checked against the event's `receivedAt` (signed by the relay, §5), so an event
    read days later still verifies, and `receivedAt` itself must be plausible by the device's clock:
    at most 10 minutes ahead and at most 8 days old (retention, and a margin);
  - the device keeps its own **replay marks**: per hook, the hash of each verified body, with the
    event id it came as, for 8 days. The same body under another event id is refused as a replay
    (the same id again, a redelivery, is not), whoever sends it;
  - once verified, the signature headers are dropped from the event, so what is stored or forwarded
    is never a ready-made replay.

  A verified event is handed over with `verified: true`, `strict: true` and the type read from the
  signed body. One that doesn't verify is quarantined (its ids, size and hash only, §7), never
  handed over. One for which the device has no secret yet is **held**: not acknowledged, so the
  relay sends it again, and after a number of tries kept whole in the quarantine and opened again
  once the secret is there (§7).

Trade-offs, for choosing it:

| | relay verifies (default) | strict |
|---|---|---|
| who holds the provider's secret | the relay (encrypted under `SECRETS_KEY`) and the provider | your devices and the provider |
| a relay breach can | forge events (with the secret) | not forge, downgrade, relabel or replay events for a hook whose secret a device keeps (above). It can still read routing metadata, see each payload in memory as it seals it, withhold, delay or drop events (they show as gaps), and hold back events for a device that hasn't been given the secret yet |
| junk at the edge | refused `401` before it's stored | stored until a device refuses it (well-formed header, fresh header timestamp, new body); it costs quota and is visible as quarantined events. It can fill only the hook's own share of the account's quota (a sixteenth by default, §4 step 7), so it can't make the account's other hooks answer `429` |
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
   on failure, never stored. Failures are counted in the Worker and written to the account's Durable
   Object at most once a minute per hook per Worker instance, so a flood of forged signatures to a
   public URL doesn't wake the account's object per request; the audit's hourly `verify.failed`
   counts (§9) are therefore approximate (an instance evicted before its next write loses its count).
5. A handshake the preset answers (Slack's `url_verification`) → answered, not stored.
5a. The hook's screen (§4b), when it has one: **drop** → `200` `{"received": "<evt_…>"}` with an id
   that names nothing (the sender can't tell it from a delivery), nothing stored, counted per hour
   (`screen.dropped`); **quarantine** → the event is held (step 8 stores it aside); **pass** or no
   rule → on. Always after step 4, so a forged signature keeps its `401`.
6. Dedupe → a duplicate (any of the delivery's marks seen before) answers `200` `{"duplicate":true}`
   and is not stored again.
7. Quota: an account's log holds at most `ACCOUNT_MAX_EVENTS` events (default 10,000) and
   `ACCOUNT_MAX_BYTES` of sealed envelopes (default 256 MiB; an event costs its sealed size once per
   device) waiting for acknowledgement, and **each hook only a share of it**: half for a hook the
   relay verifies (`HOOK_MAX_EVENTS`, `HOOK_MAX_BYTES`), a sixteenth for a strict or `unverified`
   hook (`UNCHECKED_HOOK_MAX_EVENTS`, `UNCHECKED_HOOK_MAX_BYTES`), so a flood on one hook can't refuse
   the others. Past any → `429` `{"error":"quota","scope":"account"|"hook"|"held"}` with
   `Retry-After: 60` (`held`: the hook's hold is full, §4b). Acknowledging (or retention) frees it.
8. Seal the content to every active device that has a sealing key, sign each envelope (§5), and
   append the event, its envelopes and its dedupe marks in one Durable Object transaction → `200`
   `{"received": "<evt_…>"}`. The seq (part of what is sealed) and the quota are reserved first, the
   sealing runs without blocking the account's object (nonces and acks are served meanwhile), and
   the commits are written in seq order. The plaintext is never written to storage or logs. A device
   whose key can't be sealed to gets that event as a `no_key` gap (§6), never a failed delivery.

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

## 4b. The screen at the edge

An optional firewall (PLAN §6a) for each hook: rules a device pushes, checked after the signature
and before anything is stored or streamed. The first rule that holds decides its verdict: `pass`
(on as usual; an allow rule above a block wins), `quarantine` (held at the relay, not streamed until
a device releases it) or `drop` (§4 step 5a). No rule holding is a pass. Nothing it reads is kept:
a decision leaves the rule's id and an hourly count.

**What it reads.** The client's address (`CF-Connecting-IP`), its network (`request.cf.asn`) and
country (`request.cf.country`), the headers, the body's size, the time it arrived (the relay's
clock, which is the event's `receivedAt`) and, unless the hook is strict, the body itself, read as the harness reads it: JSON, else a form's fields (a repeated name becomes a
list), else UTF-8 text. A strict hook's body is never parsed, so conditions on its body never hold
there (its devices still screen it).

**`PUT /v1/hooks/<id>/screen`** (device, or `hooks:write`) `{ "screen": EdgeScreen | null }` →
`{ "screen": EdgeScreen | null }`, the screen as kept (`null` or no rules removes it). The body may
be up to 512 KiB. **`GET /v1/hooks/<id>/screen`** (`hooks:read`) → the same. Every change is an
audit line (`hook.screen`).

```
EdgeScreen = { "rules": [EdgeRule], "consent": { "words": bool } }       at most 200 rules
EdgeRule   = { "id": [A-Za-z0-9_-]{1,64}, "verdict": "pass" | "quarantine" | "drop",
               "any"?: true,                    conditions joined by or (default: and)
               "conditions": [Condition] }      1 to 20
Condition  =
  { "on": "ip", "in": [address or CIDR…], "not"?: true, "preset"?: "github" }
  { "on": "asn", "in": [number…], "not"?: true }
  { "on": "country", "in": ["PT"…], "not"?: true }
  { "on": "header", "name", "op": "present" | "absent" }
  { "on": "header", "name", "op": "is", "hashes": [22 chars…] }
  { "on": "header", "name", "op": "contains", "value" }                     needs consent.words
  { "on": "size", "op": "gt" | "lt", "bytes" }
  { "on": "field", "path", "op": "is" | "domain_is" | "one_of", "hashes": [22 chars…], "not"?: true }
  { "on": "field", "path", "op": "contains", "words", "not"?: true }         needs consent.words
  { "on": "field", "path", "op": "pattern", "pattern", "not"?: true }        needs consent.words
  { "on": "field", "path", "op": "similar_text", "signature", "threshold"? } needs consent.words
  { "on": "similar", "shape"?: 64 hex, "text"?: signature, "threshold"? }
  { "on": "time", "from": "HH:MM", "to": "HH:MM", "days"?: [0..6…], "tz"?: IANA zone, "not"?: true }
```

Lists hold 1 to 1,000 entries. `not` turns a list into an allow list: `{"on": "ip", "in": <GitHub's
published hook ranges>, "not": true, "preset": "github"}` with `drop` drops what doesn't come from
GitHub. The relay fetches no list itself: the client sends the ranges, and `preset` only names
them. An address that isn't known (no `CF-Connecting-IP`) never matches, `not` or not; so does a
missing network, country or field.

- **Fields** are named by their catalogue path (PLAN §5.0): `payload.sender.email`,
  `payload.items[].sku` (any item), `headers.<name>`. Only scalars count: strings as they are,
  numbers and booleans as their JSON text. A path reads at most the first 64 values, in document
  order (the harness, screening on the device, reads up to 1,000).
- **Keyed hashes.** `is` and `one_of` compare a value trimmed and lower-cased; `domain_is` compares
  the domain of an address (after the last `@`) or a URL (its host, without user, port or a trailing
  dot), and matches the domain or any parent of it; a domain of more than 253 bytes (UTF-8) or 127
  labels never matches, at the relay and in the harness alike. Each value travels only as
  `HMAC-SHA256(screenKey, "00hooks-screen-field-v1\n" + path + "\n" + normalised)`, its first 16
  bytes in unpadded base64url; the relay hashes the incoming field (each parent domain, for
  `domain_is`) and compares. `GET /v1/screen/key` (device only) → `{ "key" }`: the account's screen
  key, 32 bytes, unpadded base64url (`HMAC-SHA256(HASH_PEPPER, "screen-key:" + accountId)`), so
  another account's hashes never match here. A keyed hash keeps the value from storage and logs,
  not from the relay's operator, who holds the key and could test guesses.
- **Headers.** A header's `is` is a field rule on `headers.<name>` by another spelling: it carries
  the keyed hashes of the trimmed, lower-cased value over the path `headers.<name>` (the name
  lower-cased), never the value. A screen that sends `value` with a header's `is` is refused
  (`400`, `field: "…conditions[j].value"`); a screen kept from before this rule, with a plain value,
  still runs until it is pushed again. A header's `contains` reads the words, so it needs
  `consent.words`.
- **Words.** `contains` (the words appear in order and adjacent, case-insensitive; on a field or a
  header), `pattern` and `similar_text` make the relay read the words, so a screen with any of them
  is refused (`400`, `field: "screen.consent"`) unless `consent.words` is `true`; the screen kept
  says whether it reads words.
- **Patterns** are matched in time linear in what they read, whatever the pattern: the relay runs
  its own Thompson-NFA matcher (no backtracking) on the first 2,048 characters (code points) of a
  value, unanchored, with the meaning the Rust `regex` crate gives the same text: `\w`, `\d`, `\s`
  and `\b` are Unicode's, `.` is any character but a line feed, `^` and `$` are the start and end
  of the text, and `(?i)` folds case by Unicode's simple case folding. It takes this subset, and a
  pattern outside it is refused (`400` on the pattern):

  ```
  pattern := alt                                 1 to 200 characters; may start with (?i)
  alt     := concat ("|" concat)*                an empty branch matches the empty text
  concat  := (atom [quant ["?"]])*               no quantifier on ^ $ \b \B; none stacked
  quant   := * | + | ? | {n} | {n,} | {n,m}      0 <= n <= m <= 1000, digits only
  atom    := character | . | ^ | $ | escape | class | ( alt ) | (?: alt ) | (?i: alt )
             (groups nest at most 8 deep; a character is anything but \ . + * ? ( ) | [ ] { } ^ $)
  escape  := \d \D \w \W \s \S \b \B \n \t \r \f \v | "\" + ASCII punctuation but < >
  class   := "[" ["^"] item+ "]"                 items: characters, escapes (not \b \B), ranges
             between two characters (low to high), \d \D \w \W \s \S; no nesting, no && ~~ --,
             "-" only first or last
  ```

  Its weight, near the size of its NFA, is at most 250: a character, class or assertion weighs 1,
  a sequence the sum, an alternation the sum plus one per `|`, `x{n,m}` weight(x)·max(m, 1) and
  `x{n,}` weight(x)·(n + 1) (`*` is `{0,}`, `+` is `{1,}`, `?` is `{0,1}`). The different patterns of
  one screen weigh at most 4,000 together (`400`, `field: "screen.rules"`).
- **Bounds.** A screen is compiled once per relay isolate. What one delivery can make it do is
  bounded: its keyed hashes read at most 256 KiB (path and value; each (path, value) is hashed
  once), its patterns and `contains` comparisons take at most 2,000,000 steps, and its field paths
  pass at most 1,000,000 payload nodes. A delivery that would need more is held, as if a rule had
  said `quarantine`, under the rule id `~over-budget` (not a valid rule id, so it names no rule).
- **Time windows** (`time`) hold when the delivery arrived, read as a wall clock in `tz` (an IANA
  name such as `Europe/Lisbon`; UTC when absent), on one of `days` (0 is Sunday; every day when
  absent) at or after `from` and before `to`. `from` is `00:00` to `23:59`, `to` is `00:00` to
  `24:00` and differs from `from`. A window whose `from` is later than its `to` runs past midnight,
  and is on the day it started: `{"days": [5], "from": "22:00", "to": "06:00"}` holds from Friday
  22:00 to Saturday 06:00. Daylight saving time is the zone's: a wall-clock time that is skipped
  never occurs, and one that repeats holds both times. The time is the relay's clock when the
  delivery arrives, the instant it signs as the event's `receivedAt`; the harness judges the same
  event by that `receivedAt` (not the device's clock), so both halves agree, and an event read
  late is judged by when it arrived. A zone's name is letters first, then letters, digits, `_`, `+`
  and `-` in parts joined by `/`, at most 64 characters (no offsets like `+01:00`; case is
  ignored and older names such as `US/Eastern` work), and must be in the zone database; an unknown
  zone, `Etc/Unknown` and `Factory` are refused (`400` on the condition's `tz`), as is a bad `from`,
  `to` or `days` (on that field). One screen's windows are in at most 8 different zones (no `tz`
  counts as `UTC`; `400`, `field: "screen.rules"`). Each zone's formatter is made once per relay
  isolate, and a delivery reads its wall clock once per zone. The two halves' zone databases
  (the runtime's ICU at the relay, the IANA database bundled with the harness) can differ for a
  zone whose rules changed recently, until both are updated.
- **Fingerprints** (`similar`): `shape` is the payload's shape hash (its field paths and types:
  every path `payload.a`, `payload.l[]`… with its types sorted and joined by `|`, the lines
  `path:types` sorted and joined by `\n`, then hex SHA-256; at most 2,000 fields, 32 levels and 50
  items of a list); `text` is a MinHash signature of every string of the payload (keys in
  code-point order, joined by spaces), lower-cased words (runs of letters and digits, at most
  10,000), word 5-grams (fewer words make one shingle), 64 slots of `fmix32(murmur3_32(shingle, 0) ^
  seed_i)` with `seed_i = fmix32(0x9e3779b9 · (i + 1))`, each slot big-endian, 256 bytes in unpadded
  base64url (342 characters). A fingerprint holds when the shape is equal (if given) and the share of
  equal slots is at least `threshold` (0.5 to 1; 0.8 when absent).

`fixtures/screen.v1.json` pins words, shapes, signatures, domains (with the caps), keyed hashes,
which patterns are in the edge's subset with their weights, what edge patterns match
(pathological inputs included), and when time windows hold (past midnight, days, daylight saving
transitions, `not`) with the windows and zones refused; the relay's tests and the harness's (`cli/hooks-screen`) both run
it.

**The hold.** A quarantined event is sealed to every device as usual, but with the associated data
`00hooks-seal-v1\n<hookId>\nheld\n<id>` (it has no seq yet), kept aside with its dedupe marks, and
counted in a quota of its own, **apart from the log**: at most `HELD_MAX_EVENTS` events (200) and
`HELD_MAX_BYTES` (16 MiB) per hook, and the account's quota again across hooks. A quarantine flood
fills only that hook's hold (deliveries the screen would hold answer `429` `quota` with
`scope: "held"`), never the log. It is not streamed.

- `GET /v1/held` (device, or `events:read`) → `{ "held": [{ "id", "hookId", "receivedAt",
  "verified", "strict", "preset", "eventType", "rule", "size", "expiresAt" }] }`, newest first,
  metadata only.
- `POST /v1/held/<id>/release` (device, or `hooks:write`) → `{ "released": "<id>", "seq" }`: the
  event takes the next seq, each envelope is signed for it with the extra line `held` (§5), and it
  is streamed like any event (devices revoked meanwhile get nothing). A second release is `404`.
- `DELETE /v1/held/<id>` (device, or `hooks:write`) → `204`: it is never streamed; `404` when it
  isn't held.
- `DELETE /v1/held?hookId=<hk_…>&rule=<rule id>` (device, or `hooks:write`) → `{ "dropped": n }`:
  drops every held event of that hook, held by that rule, or both; with neither, everything held.
  One audit line `held.dropped` (subject the hook id or `*`, name the rule).
- A release needs room in the log: when there is none it answers `429` `quota` and the event stays
  held.
- A held event waits `SCREEN_HELD_DAYS` (7 by default), then is dropped by the alarm.
- Audit: `screen.held` and `screen.dropped` are counted per hook per hour (`actor` null);
  `held.released` and `held.dropped` name the device or key.

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
"url"?: "…", "notice"?: true, "origin"?: { "ip"?, "asn"?, "country"? }}`, one newline byte
(`0x0a`), then the raw body bytes. JSON has no raw newline, so the first one is the boundary.
`notice` is present when the relay answered this delivery with the hook's offline notice (§4a);
`origin` is where the edge saw the delivery come from (§4b), for the device's own screen. A client
reads both only from the sealed content.

- `headers` keeps only an allowlist per preset (the provider's event and delivery headers,
  `content-type`, `user-agent`, and the runner's loop-prevention headers `00hooks-origin` and
  `00hooks-hop`), lowercased, each value at most 1,024 characters. None of them is
  covered by a signature. Never `cookie`, `authorization`, or any signature or token header: once
  verified they're no use to a reader, and a stored signature beside its body is a ready-made replay.
  A strict hook's envelope is the exception: it carries the signature headers its device needs
  (§3), sealed, and the device drops them once it has verified them.
- `contentType` is the sender's `Content-Type`, at most 200 characters; `url` (strict hooks only) is
  the public URL the relay was reached at.

**How it is sealed**: HPKE (RFC 9180) base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
ChaCha20-Poly1305 (suite `0x0020, 0x0001, 0x0003`), single-shot, to the device's sealing key:

- `info` = the UTF-8 bytes of `00hooks seal v1`;
- `aad` = the UTF-8 bytes of `00hooks-seal-v1\n<hookId>\n<seq>\n<id>`, so a stored ciphertext can't
  be moved to another event, hook or position; for an event the screen held and a device released
  (`"held": true`, §4b), `00hooks-seal-v1\n<hookId>\nheld\n<id>`, since it was sealed before it had
  a seq (the relay's signature binds the seq it got);
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
held                                    (only for a released event, "held": true)
```

HPKE alone says nothing about who sealed (anyone with a device's public key can seal to it); the
signature says it was this relay, for this device, with this metadata. A client:

1. verifies `sig` with the `relayKey` it pinned at login (§2);
2. opens `sealed` with the private key named by `kid`, with the `info` and `aad` above;
3. for a strict event, and for **any** event of a hook it keeps a strict secret for, verifies the
   provider's signature with its own settings (§3);

and hands over the event with `headers`, `contentType` and `body` (standard base64) restored, as in
version 1, so what runs automations never sees an envelope. An event that fails any step is
quarantined (§7), never handed over, except one that fails only for want of something the device
can get back (the sealing key it names, a strict hook's secret, a key store that is locked just now),
which is held first (§7). A version 2 client also refuses an event that arrives **unsealed**, and
the reference client won't stream at all without the keys to check and open events (an `Opener`):
it fails closed rather than accept what it can't check. An event whose seq is at or below what the
client already recorded, and which it never recorded, is an old one sent again: quarantined, never
run.

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
- **Gaps** (unsigned, so a client bounds them: it clamps `to` to the newest seq the relay has shown,
  `ready.head` or a later event, and ignores a gap that starts past it): when events after that
  point were already dropped by retention, a `gap` event comes before
  the next `hook`: `id: 30` `event: gap` `data: {"from": 12, "to": 30, "reason": "retention"}`
  (inclusive range of lost seqs; the `id` is `to`, so a resume starts after the gap). `reason` is
  `retention`; `no_key` for a single event with no envelope for this device (it had no sealing key
  when the event arrived: the relay keeps no plaintext to seal it later); or `too_large` for a single
  event whose message would pass the WebSocket message limit between the relay's Worker and its
  Durable Object (32 MiB). That can't happen within this version's limits (the largest event, a
  1,835,008-byte body sealed and base64-encoded with its headers, is under 2.5 MB); the rule exists
  so one undeliverable event can never wedge a stream.
- **Hook changes**: `event: hook-change` `data: {"n": 7, "kind": "hook.rotated", "hookId": "hk_…",
  "name": "…", "previousName"?: "…", "actor": "key_…" | "dev_…" | null, "at": <ms>}` says one of the
  account's hooks was created, rotated, renamed (with `previousName`) or deleted (`kind` is
  `hook.created`, `hook.rotated`, `hook.renamed` or `hook.deleted`; a client treats any other kind
  as a generic change). It has **no `id:` line**, so it never moves `Last-Event-ID`, and it is never
  acknowledged. After `ready`, a stream is sent the changes made since its device was last sent them
  at a stream's start (at most 100; changes from before the device existed, and the device's own,
  are never sent), then each new one as it happens. A change sent live is sent again when the device
  next opens a stream (a stream that went away unnoticed could have lost it), so delivery is at least
  once: `n` only grows within an account, and a client dedupes by it. It is a notice, not a record:
  the audit log (§9) is the record. A client should tell the person about a change it didn't make,
  above all `hook.rotated` (a secret now exists that the person didn't see).
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
  70 s without a byte (heartbeats included) counts as a drop: one deadline per connection, moved only
  by bytes received. Opening the stream (the response headers) is given 30 s. Re-sign every attempt
  (fresh time and nonce).
- **One stream per device**: a second stream for the same device replaces the first (`4409`).
- **Probe**: `GET /v1/stream?probe=1` (signed, `X-00h-Protocol: 2`) answers `retry`, `ready` and
  `closed {"code":1000,"reason":"probe"}`, then ends, without replacing the device's live stream and
  without sending events (for `00hooks doctor`).
- **Per-hook delivery**: an event of a hook with `deliverTo` (§3) has an envelope for that device
  only. Another device's stream skips it **silently**, with no `gap` (nothing was lost to it), so
  seqs a device receives need not be consecutive. Once its device acknowledges it (or is revoked),
  the event is deleted without waiting for the others. Every other event goes to every active
  device with a sealing key, which filters locally.

How the relay serves it (informative): the Worker holds the SSE response and connects to the
account's Durable Object over a WebSocket that the object accepts with the hibernation API, so the
object costs nothing while idle. The Worker pings every 30 s (answered by the object's auto-response
without waking it) and closes the stream with `1012` when no pong arrives for 75 s. Clients see only
SSE.

## 7. Acknowledging

`POST /v1/ack` (signed) `{ "through": 42 }` → `{ "acked": 42 }`. Acknowledge only after the event is
recorded locally (not after acting on it). Acks are per device and monotonic: a lower value is
ignored. A device's own envelopes are deleted as soon as it acknowledges them; an event acknowledged by
every device is deleted; unacknowledged events are kept 7 days (`RETENTION_DAYS`), counted from
when the event entered the log (when it was appended, or released from the screen's hold, §4b; not
when it was received), then dropped, which shows up as a `gap`. Only events that old are dropped,
each contiguous run of them as its own `gap`.

Clients dedupe by `id` before acting, so at-least-once delivery never runs an automation twice.
The reference client records an event (opened) before acknowledging it, and then hands it to its
consumer. By default it marks the event handed-over as it does (at most once to the consumer); a
consumer that records durably itself can ask to **confirm** instead (`SubscribeOptions::confirm`,
then `Subscription::confirm(id)` after its own record): an unconfirmed event is handed over again
after a restart, with the same `id`, so nothing is lost between the two records.

Because acks are cumulative, a client keeps an ack that failed and retries it with backoff (any later
ack covers it too) while it goes on recording and handing over newer events in order; otherwise the
relay keeps those events, and they hold every other device's deletions back, until retention. A
`hook` message a client can't read, open or verify (a bad relay signature, a strict event whose
provider signature fails, an unsealed event, a stale seq) still counts as received: the client
records it before acknowledging past it, so nothing is skipped silently. The reference client
appends it to `quarantine.jsonl` in its state directory with the reason and a kind, keeping the raw
message when it is small enough to look at, and only the ids, size and SHA-256 for a strict hook's
delivery that doesn't verify (anyone who knows a strict hook's URL can send those). The file is
rotated at 8 MiB, one old file kept, so a flood can't fill the disk. `00hooks quarantine list`
shows it.

**Held, not lost.** A message that fails only for want of something the device can get back (a
strict hook's secret not added yet, a sealing key the device doesn't hold, a key store that is locked
just now) is **not** acknowledged: the client drops the connection and the relay sends it again, with
a growing wait, 20 times by default. Only then is it quarantined, **whole**, and acknowledged; the
client opens it again on every reconnect and with `00hooks quarantine retry`, and hands it over once
it opens. A message larger than the client's limit (16 MiB) three times in a row is skipped by its
seq and noted.

## 8. Errors

Every error body is `{ "error": "<code>", "message": "<one plain sentence>" }`. Codes: `unauthorized`,
`clock_skew`, `not_found`, `too_large`, `rate_limited`, `quota` (a `429`: the account's log is full),
`signature`, `invalid` (with `field`), `conflict`, `forbidden` (a `403`: an API key without the
scope, or a route only a device may use), `unavailable` (a `503`: the relay is missing a safety
binding or its signing key and refuses rather than run without it), `push_failed` (a `502`: the push
service, Apple's or Google's, didn't take a push, §10.7), `internal` (a `500`; the relay logs the
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
| `hooks:write` | `POST /v1/hooks` (without a relay-generated secret or verify token), `PATCH`/`DELETE /v1/hooks/<id>` |
| `hooks:secrets` | `POST /v1/hooks/<id>/rotate`, `POST /v1/test/<hookId>`, and, with `hooks:write`, `POST /v1/hooks` for a hook whose secret or verify token the relay generates: the only scope ever shown a hook's secret |
| `events:read` | `GET /v1/events` |
| `devices:write` | `GET /v1/devices`, `PATCH /v1/devices/<id>` (rename), `DELETE /v1/devices/<id>` |
| `audit:read` | `GET /v1/audit` |
| `hooks:read` (screen) | `GET /v1/hooks/<id>/screen` |
| `hooks:write` (screen) | `PUT /v1/hooks/<id>/screen`, `POST /v1/held/<id>/release`, `DELETE /v1/held/<id>`, `DELETE /v1/held` |
| `events:read` (screen) | `GET /v1/held` |
| *(device only)* | `/v1/stream`, `/v1/ack`, `/v1/enrolments`, `PUT /v1/devices/<id>/seal-key`, `/v1/keys`, `/v1/screen/key`, `/v1/phone/*` (§10) |

The device-only routes are what would turn a stolen key into a reader of the account's events (a
stream, a new device, a sealing key) or into more keys. `hooks:secrets` is kept apart from
`hooks:write` for the same reason on the writing side: whoever holds a hook's secret can sign
deliveries the relay marks `verified: true`, so a CI key that only manages hooks can't obtain one.

**The audit log**: `GET /v1/audit?since=<ms>&limit=<1–500, default 100>` (device, or `audit:read`) →
`{ "entries": [{ "at", "kind", "actor", "subject", "name", "count"? }] }`, newest first, kept 90 days.
Names and ids only: never a secret, a token, a header value or a payload.

| `kind` | `subject` | `actor` | `name` |
|---|---|---|---|
| `hook.created`, `hook.rotated`, `hook.renamed`, `hook.deleted` | the hook | the device or key | the hook's name (the new one, for a rename) |
| `device.added` | the new device | itself (new account), or the device that issued the enrolment code | its name |
| `device.revoked` | the device | the device or key | its name |
| `device.seal_key` | the device | itself | the new kid |
| `key.created`, `key.revoked` | the key | the device | the key's name |
| `key.used` | the key | the key | the key's name; `count` uses in the hour starting at `at` |
| `verify.failed` | the hook | null | the hook's name, while it exists; `count` failures in the hour starting at `at` (approximate: counted at the edge, §4 step 4) |
| `hook.screen` | the hook | the device or key | the hook's name |
| `hook.delivery` | the hook | the device or key | the device its events now go to, or `*` for every device |
| `device.renamed` | the device | the device or key | its new name |
| `screen.held`, `screen.dropped` | the hook | null | the hook's name; `count` in the hour starting at `at` (`screen.dropped` is counted at the edge, like `verify.failed`) |
| `held.released`, `held.dropped` | the event | the device or key | null |
| `phone.pairing` | the pairing id | the node device | null |
| `phone.confirmed` | the phone | its node | the phone's name |

A phone added by a pairing is a `device.added` whose actor is its node; a phone revoked by itself is
a `device.revoked` whose actor is the phone.

**The events list**: `GET /v1/events?limit=<1–500, default 50>` (device, or `events:read`) →
`{ "events": [{ "seq", "id", "hookId", "receivedAt", "verified", "strict", "preset", "eventType",
"size", "deliveredTo": [dev…], "pendingFor": [dev…] }] }`: the events still in the log, newest first,
metadata only. `size` is the bytes held for it (its envelopes).

## 10. Phone links

The relay also carries the link between a **node** (a device of kind `device` that runs an agent
harness) and the person's **phones**. Everything between a phone and its node is
sealed end to end (HPKE to the recipient's X25519 key) and signed by the sender's Ed25519 key; the
format of the envelope's content is the harness's, not this document's. The relay routes sealed
bytes by device id, keeps them while a side is offline, says who is online, and rate-limits. It never
opens, verifies or logs an envelope's content (logs carry sizes and ids only), holds no key that
opens one, and keeps nothing of a pairing but a verifier of its proof.

A **phone** is a device of kind `phone` with exactly one node, its `peer`. It signs requests as in
§1, but may use only the routes of this section: every other signed route answers it `403`
`forbidden` ("A phone may use only the phone routes."), and an API key is `403` on all of them. A
phone never receives webhook events and is never a device of the account's event log. Its nonces are
spent in the account's phone object (below).

### 10.1 Pairing

1. **`POST /v1/phone/pairings`** (signed by a device of kind `device`)
   `{ "pairingId": <16 bytes, unpadded base64url: 22 characters>, "verifier": <32 bytes, unpadded
   base64url: 43 characters>, "expiresAt": <ms> }` → `201` `{ "pairingId", "expiresAt" }`.
   `expiresAt` must be in the future (`400` `invalid` otherwise) and is clamped to at most
   10 minutes from now; the answer says the expiry kept. An account has at most 5 open (unexpired,
   unused, not burned) pairings: a sixth is `429` `rate_limited` with `Retry-After: 60`. A `pairingId` already
   registered is `409` `conflict`. Audit: `phone.pairing`. The node computes `verifier =
   b64url(SHA-256(UTF-8(proof)))` from the proof it gives the phone out of band (a QR code,
   say); the relay never sees the proof until the phone shows it, nor the secret it comes from.
2. **`POST /v1/phone/pair`** (unsigned)
   `{ "pairingId", "proof": <43 characters>, "deviceName": <1–100 characters>, "publicKey": <the
   phone's Ed25519 key, as §2>, "sealKey": <the phone's X25519 key, as §2: required here>, "hello":
   { "enc": <43 characters>, "ct": <standard base64, 16 to 8,192 bytes decoded> } }` →
   `200` `{ "deviceId", "node" }`. In order:
   - Rate limits, before anything else: per client address (an IPv4 address or an IPv6 /64;
     `PAIR_IP_LIMIT`, 10 a minute), then for the whole relay (`PAIR_GLOBAL_LIMIT`, 120 a minute; an
     address past its own limit doesn't spend it) → `429` `rate_limited` with `Retry-After: 60`.
     Without either binding the relay answers `503` `unavailable`.
   - `pairingId` and `proof` (`400` `invalid` with `field`).
   - The proof, before any other field is read: `b64url(SHA-256(UTF-8(proof)))` is compared in
     constant time with the pairing's verifier. An unknown pairing or a wrong proof → `401`
     `unauthorized` "That pairing code isn't valid.". Each wrong proof counts against an open
     pairing; the **5th** burns it, and from then on even the right proof is `401` `unauthorized`
     "That pairing code was locked after too many wrong attempts; make a new one.". (Only someone
     who has the pairing code knows its `pairingId`, so only they can burn it.) The right proof for a
     used pairing → `409` `conflict` "That pairing code was already used."; for an expired one →
     `401` `unauthorized` "That pairing code has expired.".
   - The rest of the body (`400` `invalid` with `field`); a `sealKey` is refused as in §2 (malformed
     or low-order). A `publicKey` that belongs to a device is `409` `conflict` "That public key
     already belongs to a device.", and the pairing is not spent, so the phone may retry with another
     key. A key held by a phone that was never confirmed and whose pending time ran out (below) is
     freed first: that phone's record is deleted, and the key pairs again.
   - The pairing is spent atomically (one conditional update), so of parallel redemptions exactly one
     wins; the others see "already used". A pairing whose node has been revoked since is "isn't
     valid".
   - The phone is created as a **pending** device of the node's account: kind `phone`, `peer` the
     node, pending until the pairing's expiry plus 5 minutes. The node is queued a `pair` sys message
     (§10.4) carrying `hello` as given. Audit: `device.added`, with the node as actor. If the relay
     fails part-way here, the phone is removed again and the pairing released, so the phone retries
     with the same code.
   The relay doesn't open `hello` (it is sealed to the node's key) and the phone checks that `node`
   is the node it expected.
3. **`POST /v1/phone/devices/<id>/confirm`** (signed by the phone's node) → `200`
   `{ "device", "active": true }`. The phone must be pending, not revoked and within its pending
   time, and the caller must be its `peer`; anything else (another device of the account, a phone
   already confirmed, an unknown id) is `404`. From then on the phone may send. Audit:
   `phone.confirmed`.

A **pending** phone may open its socket (and receive) and unpair itself, nothing else: its sends are
refused `not_paired`, and nothing may be sent to it. Once its pending time passes unconfirmed, it is
as good as revoked: its requests are `401`, its socket is closed with `4401`, and it is no longer
listed. Its record is deleted when its account next registers a pairing, or when a phone pairs with
its public key, so the key is free again.

### 10.2 Listing and unpairing

- **`GET /v1/phone/devices`** (signed by a device of kind `device`) → `{ "phones": [{ "id", "name",
  "peer", "createdAt", "lastSeenAt", "pending", "online" }] }`: the account's phones that aren't
  revoked (nor pending past their time), oldest first. `online` is as in §10.4.
- **`DELETE /v1/phone/self`** (signed by a phone, pending or not) → `204`: the phone revokes itself.
- **`DELETE /v1/devices/<id>`** (§2) works on a phone too (signed by a device, or an API key with
  `devices:write`).

Revoking a phone, by either route: its socket closes at once with `4401`, its later requests are
`401`, everything queued to it or from it is deleted, and its node, when connected, sees it go
offline (`presence`) and is queued an `unpaired` sys message, **once**, whoever revoked it (the node
itself included, so a node never has to tell revocations apart). Revoking a device of kind `device`
also revokes every phone paired with it (no `unpaired` message: its node is the device being
revoked), closes the device's phone socket with `4401` and deletes its unused pairings. Both are
idempotent: a retry finishes a revocation that failed part-way.

### 10.3 The socket

**`GET /v1/phone/socket`** (signed as in §1, by a device of kind `device` or by a phone, pending or
not), with `Upgrade: websocket` → `101`. Without the upgrade header the relay answers `426`
`invalid` (`field: "Upgrade"`). The device's role on the socket is `node` (kind `device`) or `phone`.
A second socket for the same device closes the first with `4409`.

Frames are JSON text frames, one object each, with a `t` field; besides them, the text `ping` is
answered `pong` at any time (without waking the relay's object). A binary frame, a frame over the
size limit (64 KiB from a phone, 512 KiB from a node; checked before the frame is read), a frame
that isn't a JSON object, or a frame of an unknown `t` closes the socket with `4400`.

**Every frame** (`hello`, `send`, `ack`, valid or not; `ping` aside) spends a token of the device's
bucket (phone: 30, refilled 1 a second; node: 200, refilled 20 a second). The bucket belongs to the
device, not the socket: reconnecting doesn't refill it. With the bucket empty, a `send` is refused
`rate_limited` (§10.4), an `ack` is ignored (acks are cumulative: the next one, or the next `hello`,
covers it), and a `hello` closes the socket with `4429`.

Client → relay:

- `{"t":"hello","after":<seq ≥ 0>}`: must be the first frame (anything else first: `4400` "hello
  first"), and is sent once (a second: `4400`). It also acknowledges every row up to `after` for this
  device (`after` beyond the newest seq is clamped to it; the cursor never goes back). The relay
  answers `{"t":"ready","after":<the device's cursor: max(after, acknowledged)>,"head":<the newest
  seq queued for this device; 0 when none>,"peers":[{"device","online","since"}]}`, then
  `{"t":"gap","from","to"}` if rows after the cursor were dropped (the queue overflowed, or
  retention; at most one, see §10.4; `from` and `to` are inclusive seqs), then the backlog for this
  device in seq order: `{"t":"msg","seq","env"}` and `{"t":"sys","seq","sys"}`. Then the socket is
  live.
  `peers` is a phone's node, or each of a node's phones that isn't revoked (pending ones included).
- `{"t":"send","env":<envelope>}`: answered `{"t":"queued","id","seq"}` or
  `{"t":"refused","id","code","retryAfter"?}` (`id` is the envelope's, or null when it has none).
- `{"t":"ack","through":<seq>}`: deletes this device's rows up to `through`; monotonic, no answer.

Relay → client, besides the above: `{"t":"msg","seq","env"}` and `{"t":"sys","seq","sys"}` live, as
they are queued; `{"t":"presence","device","online","since"}` when a peer says `hello` (online) or
its socket goes (offline). Nothing is sent to a socket before its `hello`.

`seq` is per account (shared by every device's queue), strictly increasing, never reused, so a
device's seqs have holes; only a `gap` frame reports a loss. **Online** means a socket that is open,
past `hello`, and has shown life in the last 90 s (it opened, sent a frame, or was answered `pong`).
`since` is when the device came online, or when it was last seen going (null when never seen).

Close codes:

| code | meaning | client should |
|---|---|---|
| `4401` | the device was revoked, or a pending phone's time ran out | stop; a phone forgets the pairing |
| `4409` | a newer socket for this device replaced this one | stop (another process is connected) |
| `4400` | protocol error (no `hello` first, not JSON, unknown frame, a frame over the size limit) | fix the client; don't loop |
| `4429` | a `hello` found the device's token bucket empty | reconnect with backoff |
| `1012` | the relay is restarting (a deploy) | reconnect with jitter |

After any other drop, reconnect with backoff (1 s doubling to 30 s, with jitter; re-sign every
attempt) and send `hello` with the last seq recorded. A send that got no `queued` is sent again with
the same `id`.

### 10.4 What is routed

**The envelope** (`env`), checked for shape only:

```
{ "v": 1, "id": <22 base64url>, "from": "dev_…", "to": "dev_…", "at": <integer ms>,
  "kid": <22 base64url>, "enc": <43 base64url>, "ct": <standard padded base64>,
  "sig": <86 base64url>, "push"?: "approval" | "message" | "notice" }
```

Any other field, or any field of the wrong form, is refused `invalid`; so is `push` from a phone.
`push` is still accepted from a node, for older nodes, and carried as sent, but the relay no longer
acts on it: a node asks for a push with `POST /v1/phone/push` (§10.7). The
relay doesn't check `sig`, `kid` or `at` (the recipient does) and never opens `ct`. It stores the
envelope as the JSON text it parsed (`JSON.stringify` of the received object: the same fields and
values, in the order sent) and forwards it spliced into the `msg` frame without re-encoding, so
every field the recipient reads is byte-identical to what the sender sent.

Checks on a `send`, in order, each refusing with its `code`:

| code | when |
|---|---|
| `rate_limited` | the device's token bucket is empty (§10.3); `retryAfter` in seconds. Every frame spends a token, refused or not |
| `invalid` | the envelope's shape, or `push` from a phone |
| `forbidden` | `from` isn't the socket's device |
| `not_paired` | the sending phone is still pending |
| `forbidden` | from a phone, `to` isn't its node; from a node, `to` isn't one of its own phones that is confirmed and not revoked |
| `queue_full` | to a node: its queue already holds 1,000 rows or would pass 16 MiB |

A frame over the size limit is not refused but closes the socket (`4400`, §10.3); `too_large` is no
longer sent. A resent `id` from the same sender to the same recipient that is still queued is
answered `queued` with the seq it has and isn't stored again (the same `id` to another recipient is
another envelope). A phone's queue holds at most 500 rows and 16 MiB: past either, its **oldest**
rows are dropped to make room and the phone sees a `gap`. Rows are kept until the recipient
acknowledges them, or 7 days (`RETENTION_DAYS`), after which they are dropped (a `gap`).

**Gaps.** Rows are only ever dropped from the oldest end of a device's queue, so the relay keeps one
loss record per device, widened by each loss: `hello` sends at most one `gap`, before the backlog,
from the first seq lost after the cursor to the last seq lost. Seqs inside it that weren't the
device's are other devices' (seqs are per account); no row still queued is inside it. The record is
kept until the device acknowledges past it (or is revoked), however long that takes: a loss is never
itself lost.

**Sys messages** are the relay's own notices to a node, never content:

- `{"kind":"pair","pairingId","device","name","publicKey","sealKey","hello":{"enc","ct"},"at"}`: a
  phone redeemed the node's pairing (§10.1); `device` is the new phone, `publicKey` and `sealKey`
  its keys as it registered them, `hello` its sealed hello as given.
- `{"kind":"unpaired","device","at"}`: one of the node's phones was revoked (§10.2).

### 10.5 Limits

| | |
|---|---|
| pairings | at most 5 open per account; valid at most 10 minutes; one use |
| pairing attempts | 10 a minute per client address (`PAIR_IP_LIMIT`), 120 a minute for the relay (`PAIR_GLOBAL_LIMIT`) |
| wrong proofs | 5 per pairing, then it is burned |
| pending | the pairing's expiry plus 5 minutes |
| frame | 64 KiB from a phone, 512 KiB from a node |
| frames (every one) | per device, across reconnects: phone 30 at once, 1 a second; node 200 at once, 20 a second |
| queue to a node | 1,000 rows or 16 MiB, then `queue_full` |
| queue to a phone | 500 rows or 16 MiB, then the oldest are dropped (`gap`) |
| retention | 7 days (`RETENTION_DAYS`) |
| hello | 8 KiB of ciphertext |
| pushes (§10.7) | per phone: one per kind a minute, and 30 in a rolling hour (`PHONE_PUSH_PER_HOUR`); none while its socket is online |
| push preview | `ct` at most 1,400 base64 characters |

A relay operator may lower the queue limits with `PHONE_NODE_QUEUE_MAX`, `PHONE_PHONE_QUEUE_MAX` and
`PHONE_QUEUE_MAX_BYTES`, and change the hourly push cap with `PHONE_PUSH_PER_HOUR`.

### 10.6 How the relay serves it (informative)

One Durable Object per account (`PhoneObject`), separate from the account's event log, holds the
queue (seq, recipient, sender, `msg` or `sys`, id, the envelope text, size, time), each recipient's
row and byte counts (kept by triggers on the queue, so a send never scans it), each device's cursor,
gap record and token bucket, the account's phones (peer, pending, revoked: so a socket's sends are
checked without D1), the nodes revoked there (so a socket or pairing already past the Worker is
refused), the phones' request nonces, when each device was last seen, and each phone's pushes of
the last hour (phone, kind and time only). Its sockets use the
hibernation API: per-socket state (role, peer, `hello` time) is the socket's attachment, `ping` is
auto-answered, and an alarm prunes rows past retention, nonces, push counts older than an hour and
pending phones whose time ran out, so an idle account costs nothing. The Worker authenticates the upgrade
request, then hands it to the object, whose `101` goes back to the client.

### 10.7 Push

A node can ask the relay to wake one of its phones when the phone's socket isn't online: an iPhone
through Apple's push service (APNs), an Android phone through Firebase Cloud Messaging (FCM, below).
The **node** keeps each phone's device token (the phone sends it to its node, sealed, like everything
else) and decides what is worth a push; the **relay** holds only the operator's APNs key and FCM
service account, checks that the phone is the node's, applies the limits, and sends a fixed, opaque
alert. The relay stores no device token and puts nothing the node wrote into the alert.

**`POST /v1/phone/push`** (signed by a device of kind `device`; a phone, or an API key, is `403`
`forbidden` as on the other node-only phone routes):

```
{ "device": "dev_…", "platform"?: "ios" | "android",
  "token": <ios: the APNs device token: lowercase hex, 32 to 400 characters, an even number;
            android: the FCM registration token: 32 to 1,024 of A–Z a–z 0–9 - _ :>,
  "environment"?: "sandbox" | "production",
  "kind": "approval" | "ask" | "finished" | "handoff" | "reconnect" | "task" | "done" | "drive",
  "ref": <22 characters of unpadded base64url>,
  "preview"?: { "at": <integer ms>, "enc": <43 base64url>, "ct": <standard padded base64, at most 1,400 characters>, "sig": <86 base64url> } }
```

`platform` is `ios` when absent, so requests written before Android are iOS ones; `environment` is
for iOS only (with `android` it is `400` `invalid`). Steps 1 to 6 are the same for both platforms,
and a phone's limits are its own whichever platform it is pushed on; steps 7 and 8 are APNs', and
FCM's are under "Android" below.

`ref` is the node's own reference (what the phone opens when the alert is tapped); `preview`, when
given, is sealed to the phone by the node and carried as it is, so the phone's notification extension
can show the real text on the device. The relay reads neither. Checks, in order:

1. The shape: a missing or malformed field, or any other field (also inside `preview`), is `400`
   `invalid` with `field`.
2. `device` must be one of the calling node's own phones, confirmed and not revoked: anything else
   (a pending phone, a revoked one, another node's, another account's, an unknown id) is `403`
   `forbidden` "That phone isn't paired with this device.". Nothing is sent.
3. Push isn't configured on this relay for the request's platform (below): `200`
   `{ "sent": false, "reason": "unavailable" }`.
4. `environment` is given and isn't the relay's: `200` `{ "sent": false, "reason": "environment" }`.
   Without `environment` it isn't checked.
5. The phone's socket is online (§10.3): `200` `{ "sent": false, "reason": "online" }`. It gets the
   live message instead.
6. The phone's limits: one push per phone and kind a minute, and 30 per phone in a rolling hour
   (`PHONE_PUSH_PER_HOUR`). Past either, `429` `rate_limited` with `Retry-After` and `retryAfter`
   (seconds). Only a push that passes every check is counted, before it is sent, whatever APNs then
   answers; the answers above count nothing. The counts are kept in the account's phone object,
   pruned after an hour, and deleted with the phone when it is revoked.
7. The relay sends it: `POST https://api.push.apple.com/3/device/<token>` (sandbox:
   `https://api.sandbox.push.apple.com`), with `authorization: bearer <provider token>`,
   `apns-topic: <APNS_TOPIC>`, `apns-push-type: alert`, `apns-priority: 10`,
   `apns-expiration: <now + 86,400, Unix seconds>`, `apns-collapse-id: <kind>` and
   `content-type: application/json`. The body is built by the relay alone:

   ```
   { "aps": { "alert": { "title": T, "body": B }, "sound": "default", "category": C,
              "mutable-content": 1, "thread-id": "<kind>" },
     "zn": { "v": 1, "kind": "<kind>", "ref": "<ref>", "p": <preview, only when given> } }
   ```

   | kind | title (T) | body (B) | category (C) |
   |---|---|---|---|
   | `approval` | An agent needs you | Approval needed. | `APPROVAL` |
   | `ask` | An agent needs you | It asked you something. | `ASK` |
   | `finished` | An agent finished | Open the app to see what it did. | `FINISHED` |
   | `handoff` | Continue on your phone | A conversation was handed to this phone. | `HANDOFF` |
   | `reconnect` | Your Mac is back online | Open the app to reconnect. | `RECONNECT` |
   | `task` | Something needs you | An agent left you a task. | `TASK` |
   | `done` | Done | A task from a meeting is done. | `DONE` |
   | `drive` | Your Mac needs you | Open 00next on your Mac to decide. | `DRIVE` |

   Nothing else from the request goes into the payload: never the token, a device id, or any text
   from the node.
8. APNs' answer: `200` → `200` `{ "sent": true }`. `410`, or `400` with reason `BadDeviceToken`,
   `DeviceTokenNotForTopic` or `Unregistered` → `200` `{ "sent": false, "reason": "unregistered" }`:
   the node forgets that token. `403` `ExpiredProviderToken` or `InvalidProviderToken` → the relay
   mints a fresh provider token and tries once more, and answers from that second try. `429` →
   `429` `rate_limited` with `Retry-After: 60`. Anything else, a network error or a redirect →
   `502` `push_failed`. The relay logs the kind and APNs' status and reason word, never the token
   or the payload.

**The provider token** is an ES256 JWT: header `{"alg":"ES256","kid":<APNS_KEY_ID>}`, claims
`{"iss":<APNS_TEAM_ID>,"iat":<Unix seconds>}`, each unpadded base64url, signed with ECDSA P-256 and
SHA-256 over `header.claims` (the raw 64-byte r‖s signature, as JOSE writes it). Each Worker or
object instance reuses its token for 50 minutes (APNs refuses tokens older than an hour and
refreshes more often than every 20 minutes) and mints a new one when the key, key id or team
changes. Several instances may each hold their own token.

**Configuration** (Worker secrets): `APNS_KEY`, the contents of the `.p8` file Apple gives (a PKCS#8
PEM of a P-256 key, BEGIN and END lines included; surrounding whitespace and `\n` escapes are
fine); `APNS_KEY_ID` and `APNS_TEAM_ID` (10 characters each); `APNS_TOPIC`, the phone app's bundle
id; `APNS_ENVIRONMENT`, `sandbox` or `production` (the default when unset). Push is available only
when the first four are set and well formed, `APNS_ENVIRONMENT` is one of the two, and the key
imports; `/v1/info` says so (§2). The APNs hosts aren't configurable.

The requests were checked against a mock of APNs in the relay's tests, not against Apple's service.
APNs needs HTTP/2, which the Workers runtime negotiates for outbound HTTPS.

**Android.** With `"platform": "android"`, steps 1 to 6 are as above; then:

7. The relay sends `POST https://fcm.googleapis.com/v1/projects/<project_id>/messages:send` with
   `authorization: Bearer <access token>` and `content-type: application/json`. The body is built by
   the relay alone, with the same texts as the table above:

   ```
   { "message": { "token": "<token>",
                  "notification": { "title": T, "body": B },
                  "data": { "zn": "<the APNs payload's zn object, as JSON text>" },
                  "android": { "priority": "high", "ttl": "86400s", "collapse_key": "<kind>",
                               "notification": { "tag": "<kind>" } } } }
   ```

   `data.zn` is the same object APNs carries in `zn` (`v`, `kind`, `ref`, and `p` only when a preview
   is given), as a string because FCM's data values are strings. Nothing else from the request goes
   into the message.
8. FCM's answer: `200` → `200` `{ "sent": true }`. `404`, or the error code `UNREGISTERED` or
   `SENDER_ID_MISMATCH`, or `400` `INVALID_ARGUMENT` whose field violation is `message.token` →
   `200` `{ "sent": false, "reason": "unregistered" }`: the node forgets that token, as for APNs.
   Any other `INVALID_ARGUMENT` is about the relay's message and keeps the token. `401` → the relay
   fetches a fresh access token and tries once more, and answers from that second try. `429` →
   `429` `rate_limited` with `Retry-After: 60`. Anything else, a network error, a redirect, or no
   access token from Google → `502` `push_failed`. The relay logs the kind, FCM's status and error
   word, never the token, the access token or the message.

**The access token** is an OAuth2 token from `POST https://oauth2.googleapis.com/token`
(`application/x-www-form-urlencoded`: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and
`assertion=<JWT>`). The assertion is an RS256 JWT: header `{"alg":"RS256","typ":"JWT","kid":<private_key_id>}`
(no `kid` when the service account has none), claims `{"iss":<client_email>,"scope":"https://www.googleapis.com/auth/firebase.messaging","aud":"https://oauth2.googleapis.com/token","iat":<Unix seconds>,"exp":<iat + 3600>}`,
signed with RSASSA-PKCS1-v1_5 and SHA-256. Each instance reuses its access token until five
minutes before the `expires_in` Google gave (at most an hour), shares one exchange between parallel
pushes, and fetches a new one when the service account changes. A refused exchange isn't cached.

**Configuration** (Worker secret): `FCM_SERVICE_ACCOUNT`, the whole JSON key file of a Google service
account of the Firebase project (Firebase console → Project settings → Service accounts → Generate
new private key). The relay reads `type` (must be `service_account`), `project_id` (6 to 30 of
a–z 0–9 -), `client_email`, `private_key` (a PKCS#8 PEM of an RSA key of at least 2,048 bits) and,
when present, `private_key_id`; it ignores the rest, `token_uri` included. Android push is available
when it parses and the key imports; `/v1/info` says so (§2). The token endpoint and the FCM host
aren't configurable. As for APNs, the requests were checked against mocks, not against Google.

The envelope's `push` field (§10.4) is from an earlier design, in which the relay pushed when it
queued a tagged envelope. It is still accepted from a node and carried, and ignored.
