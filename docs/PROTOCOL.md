# 00hooks protocol (v1)

The contract between the relay (`relay/`) and its clients (the `00hooks` CLI and the `hooks-client`
crate). Both sides test against this document; a change here is a version bump. Phase 0 implements
everything below except where marked *(phase 1)*.

All JSON is UTF-8 with camelCase keys. Times are Unix milliseconds. Ids are lowercase base32
(Crockford, no padding) with a prefix: `acc_`, `dev_`, `hk_`, `evt_`, `enr_`.

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

- `POST /v1/accounts` `{ "deviceName": "…", "publicKey": "<base64url ed25519 public key>" }` → `201`
  `{ "accountId", "deviceId" }`. When the relay has a `SIGNUP_TOKEN` secret, the request must carry
  `Authorization: Bearer <SIGNUP_TOKEN>`; without the secret, signups are open (development only;
  `/v1/info` says so).
- `POST /v1/enrolments` (signed) → `{ "code": "ABCD-EFGH-JKMN", "expiresAt" }`: a one-time code,
  valid 10 minutes, for adding another device to the same account. A code is 12 Crockford base32
  characters (60 random bits) in three groups of four; redeeming reads it case-insensitively, ignores
  dashes and spaces, and takes `I`/`L` as `1` and `O` as `0`.
- `POST /v1/enrolments/redeem` `{ "code", "deviceName", "publicKey" }` → `{ "accountId", "deviceId" }`.
  Limits, all answering `429` `rate_limited` with `Retry-After`, keyed on the client address (an IPv4
  address, or an IPv6 address's /64):
  - at most 10 redemptions a minute per address and 300 a minute in all (the Rate Limiting binding,
    checked before anything else);
  - every attempt is counted, atomically, **before** the code is looked at, and a right code is
    refunded; the attempt after five wrong codes in 10 minutes blocks the address for 10 minutes,
    so parallel guesses each count.
- `GET /v1/devices` (signed) → `{ "devices": [{ "id", "name", "createdAt", "lastSeenAt", "current" }] }`
- `DELETE /v1/devices/<id>` (signed) → `204`: revokes it; its open stream closes at once with `4401`.
  Idempotent: revoking a device of this account that is already revoked answers `204` again and
  closes any stream it still has (so a retry after a failure part-way finishes the job); a device of
  another account, or none, is `404`.
- `POST /v1/enrolments` and `/redeem` answer `200`; a wrong, used or expired code answers `401`
  `unauthorized`. A newly enrolled device **starts at the head** of the log: it doesn't receive the
  older backlog and doesn't hold it back from deletion.
- `GET /v1/info` (unsigned) → `{ "version", "protocol": 1, "signupOpen": bool, "serverTime" }`.

## 3. Hooks

- `POST /v1/hooks` (signed) `{ "name", "verify": <Verify> }` → `201`
  `{ "hook": <Hook>, "url", "secret"? }`. `secret` appears **only here** and only for presets where the
  relay generates it.
- `GET /v1/hooks` → `{ "hooks": [<Hook>] }`; `GET /v1/hooks/<id>` → `<Hook>`.
- `PATCH /v1/hooks/<id>` `{ "name"?, "enabled"?, "maxBodyBytes"? }` → `<Hook>`.
- `POST /v1/hooks/<id>/rotate` → `{ "secret" }`; the previous secret keeps working for 24 h.
- `DELETE /v1/hooks/<id>` → `204`. Events already in the log stay until acknowledged.

`Hook`: `{ "id", "name", "url", "enabled", "verify": { "preset", …non-secret fields }, "maxBodyBytes",
"createdAt", "lastEventAt" }`.

`Verify` (phase 0 presets):

| `preset` | fields | check |
|---|---|---|
| `github` | `secret`? (generated when absent) | `X-Hub-Signature-256: sha256=<hex HMAC-SHA256(body)>`; dedupe on `X-GitHub-Delivery` **and** on the body's SHA-256 (always, since the delivery id isn't signed); answers `ping` events with `200` |
| `standard-webhooks` | `secret`? (`whsec_` + base64, generated when absent) | Standard Webhooks v1 HMAC over `id.timestamp.body`, timestamp within 300 s, dedupe on `webhook-id` (signed) |
| `hmac` | `header` (required), `algorithm` (`sha256` default, or `sha1`), `encoding` (`hex` default, or `base64`), `prefix`? (e.g. `sha256=`), `secret`? | HMAC of the raw body; dedupe on a body hash |
| `token` | `header` (default `Authorization`), `secret`? | constant-time compare with `Bearer <secret>` (or the raw value for other headers); medium strength; **no dedupe** (nothing identifies a delivery) |
| `unverified` | — | accepts anything; events carry `verified: false`; **no dedupe** |

What each preset's signature covers, and what the relay uses besides:

| `preset` | signed | used but **not** signed (the sender's claim) |
|---|---|---|
| `github` | the body | `X-GitHub-Delivery` (dedupe; the body hash backs it), `X-GitHub-Event` (`eventType`) |
| `standard-webhooks` | `webhook-id`, `webhook-timestamp`, the body (and so `eventType`, read from it) | — |
| `hmac` | the body | — |
| `token` | nothing (the token proves the sender knows the secret; the body has no integrity) | — |
| `unverified` | nothing | — |

Because GitHub's signature covers only the body, someone who captured one delivery could resend it
under a new `X-GitHub-Delivery`; the body-hash mark, kept as long as the delivery mark (7 days),
answers that as a duplicate. The cost: two genuinely different GitHub deliveries with byte-identical
bodies within 7 days are stored once.

GitHub's `ping` (sent when a webhook is created) is verified, deduped and stored as a normal event
with `eventType: "ping"`, so a new hook can be tested end to end. `maxBodyBytes` is at most
1,835,008 in phase 0 (bodies live in 2 MB SQLite rows; larger ones move to R2 in a later phase).

Stripe, Slack, Linear, Shopify, Twilio and Ed25519 Standard Webhooks follow in phase 1. Secrets are
stored encrypted with the relay's `SECRETS_KEY` (AES-256-GCM), never returned after creation.

## 4. Receiving

`POST /h/<hookId>` (also PUT and PATCH). In order:

0. A relay whose rate limit bindings are missing refuses everything here with `503` `unavailable`
   (it fails closed rather than take a flood at full cost).
1. Rate limit per client address (an IPv4 address, or an IPv6 /64; 600 requests per 10 s by
   default), **before** the hook is looked up → `429` `rate_limited` with `Retry-After`. Guessing hook
   ids costs the guesser this budget, not the relay a database read each.
2. Unknown or disabled hook → `404`. Body declared larger than the hook's `maxBodyBytes` (default
   1 MiB) in `Content-Length` → `413`.
3. Rate limit per hook (60 requests per 10 s by default) → `429` with `Retry-After`. Only then is the
   body read, and a body that turns out larger than the limit while streaming → `413`.
4. Verify with the preset → `401` `{"error":"signature"}` on failure (counted, not stored).
5. Dedupe → a duplicate (any of the delivery's marks seen before) answers `200` `{"duplicate":true}`
   and is not stored again.
6. Quota: an account's log holds at most `ACCOUNT_MAX_EVENTS` events (default 10,000) and
   `ACCOUNT_MAX_BYTES` of bodies and headers (default 256 MiB) waiting for acknowledgement; past
   either → `429` `quota` with `Retry-After: 60`. Acknowledging (or retention) frees it.
7. Append to the account log, in one Durable Object transaction with all its dedupe marks → `200`
   `{"received": "<evt_…>"}`.

## 5. Events

```json
{
  "seq": 42,
  "id": "evt_…",
  "hookId": "hk_…",
  "receivedAt": 1792233600000,
  "verified": true,
  "preset": "github",
  "eventType": "pull_request",
  "contentType": "application/json",
  "headers": { "x-github-event": "pull_request", "x-github-delivery": "…" },
  "body": "<standard base64 (RFC 4648 §4, with padding) of the raw bytes>"
}
```

- `seq` is per account, strictly increasing, never reused.
- `eventType` comes from the preset (`X-GitHub-Event`, the Standard Webhooks payload's `type`) or is
  `null`, at most 200 characters. **For `github` it is the sender's claim, not authenticated**: GitHub
  signs only the body, so treat it as a label and read the type from the body where it matters (the
  table in §3 says, per preset, what is signed). `contentType` is likewise the sender's header, at
  most 200 characters.
- `headers` keeps only an allowlist per preset (the provider's event and delivery headers,
  `content-type`, `user-agent`), lowercased, each value at most 1,024 characters. None of them is
  covered by a signature. Never `cookie`, `authorization`, or any signature or token header
  (`x-hub-signature-256`, `webhook-signature`, the `hmac` or `token` preset's own header): once
  verified they're no use to a reader, and a stored signature beside its body is a ready-made replay.
- *(phase 1)* `sealed`: the body and headers become an HPKE envelope; see PLAN §4.4.

## 6. Streaming

`GET /v1/stream` (signed), `Accept: text/event-stream`, optional `Last-Event-ID: <seq>`.

Response headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache, no-transform`,
`X-Accel-Buffering: no`.

The stream sends, in order:

```
retry: 5000

event: ready
data: {"accountId":"…","deviceId":"…","after":40,"head":42}

id: 41
event: hook
data: {…event…}

id: 42
event: hook
data: {…event…}

: hb
```

- **Where it starts**: after `max(Last-Event-ID, this device's acknowledged seq)`. `ready.after` says
  which; `ready.head` is the newest seq in the log.
- **Gaps**: when events after that point were already dropped by retention, a `gap` event comes before
  the next `hook`: `id: 30` `event: gap` `data: {"from": 12, "to": 30, "reason": "retention"}`
  (inclusive range of lost seqs; the `id` is `to`, so a resume starts after the gap). `reason` is
  `retention`, or `too_large` for a single event whose message would pass the WebSocket message limit
  between the relay's Worker and its Durable Object (32 MiB). That can't happen within this
  version's limits (the largest event, a 1,835,008-byte body base64-encoded with its headers, is
  under 2.5 MB); the rule exists so one undeliverable event can never wedge a stream.
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
  *(phase 1)* a probe mode (`?probe=1`) that answers `ready` and closes without replacing the live
  stream, for `00hooks doctor`; and per-hook delivery, so a device receives only the hooks routed to
  it (today every device receives every hook and filters locally).

How the relay serves it (informative): the Worker holds the SSE response and connects to the
account's Durable Object over a WebSocket that the object accepts with the hibernation API, so the
object costs nothing while idle. The Worker pings every 30 s (answered by the object's auto-response
without waking it) and closes the stream with `1012` when no pong arrives for 75 s. Clients see only
SSE.

## 7. Acknowledging

`POST /v1/ack` (signed) `{ "through": 42 }` → `{ "acked": 42 }`. Acknowledge only after the event is
recorded locally (not after acting on it). Acks are per device and monotonic: a lower value is
ignored. An event acknowledged by every device that receives its hook is deleted; unacknowledged events
are kept 7 days (`RETENTION_DAYS`), then dropped, which shows up as a `gap`.

Clients dedupe by `id` before acting, so at-least-once delivery never runs an automation twice.

## 8. Errors

Every error body is `{ "error": "<code>", "message": "<one plain sentence>" }`. Codes: `unauthorized`,
`clock_skew`, `not_found`, `too_large`, `rate_limited`, `quota` (a `429`: the account's log is full),
`signature`, `invalid` (with `field`), `conflict`, `unavailable` (a `503`: the relay is missing a
safety binding and refuses rather than run without it), `internal` (a `500`; the relay logs the
cause, never the payload). Messages never contain secrets, signatures or payload content.
