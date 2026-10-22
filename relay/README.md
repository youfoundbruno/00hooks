# 00hooks relay

The relay half of 00hooks: a Cloudflare Worker and two Durable Object classes. Webhooks arrive at
`/h/<hook id>`; the relay verifies them over the raw bytes, dedupes them, seals them to each of the
account's devices (HPKE, signed by the relay), appends them to the account's ordered log, and streams
them to the devices over SSE, resumably. It also carries phone links (PROTOCOL §10): a phone pairs
with a node device, and the relay routes the sealed envelopes between them over one WebSocket per
device, never seeing their content. The contract
with clients is [`docs/PROTOCOL.md`](../docs/PROTOCOL.md); the design and the security model are in
[`docs/PLAN.md`](../docs/PLAN.md).

```
provider ──POST /h/<hook>──▶ Worker ── verify, rate limit, size ──▶ AccountObject (one per account)
                                                                    SQLite: log, cursors, nonces,
CLI ◀──── SSE /v1/stream ─── Worker (SSE bridge) ◀── hibernatable ── dedupe marks; alarm prunes
                                                       WebSocket
```

- `src/index.ts`: routes. `src/auth.ts`: signed requests. `src/keys.ts`: API keys.
  `src/accounts.ts`: accounts, devices, enrolments, sealing keys. `src/hooks.ts`: the hook API.
  `src/presets.ts`: the preset table and its interpreter. `src/envelope.ts`: sealing and the relay's
  envelope signature. `src/receive.ts`: `/h/<id>`. `src/stream.ts` and `src/bridge.ts`: the SSE
  bridge. `src/audit.ts`: the audit log and events list. `src/account-object.ts`: the Durable
  Object. `src/phone.ts`: the phone routes; `src/phone-object.ts`: their Durable Object (mailbox,
  cursors, sockets); `src/phone-push.ts`, `src/apns.ts` and `src/fcm.ts`: waking a phone through APNs or FCM. `migrations/`: the D1 schema.
- `scripts/seal-interop.ts` seals events with `src/envelope.ts` under Node, for the CLI's interop
  tests (`fixtures/seal-interop.v1.json`).

## Develop

From the repository root (a pnpm workspace; `pnpm install` once):

```sh
cp relay/.dev.vars.example relay/.dev.vars    # then fill in the three secrets
pnpm --filter ./relay dev                     # applies the D1 migrations locally, then serves
                                              # http://localhost:8787, all local
pnpm --filter ./relay test                    # vitest inside workerd (Miniflare)
pnpm --filter ./relay typecheck
pnpm check                                    # everything a change must pass
```

To create accounts on a local relay, put `SIGNUP_TOKEN` (or `OPEN_SIGNUP=1`) in `.dev.vars`
(see "Settings" below).

The tests run the real Worker, Durable Objects (SQLite storage, alarms, hibernatable WebSockets),
D1 and Rate Limiting bindings in workerd. After changing `wrangler.jsonc`, regenerate the binding
types with `pnpm --filter ./relay types`.

## Self-hosting

You need a Cloudflare account on the Workers Paid plan (Durable Objects with SQLite storage and the
Rate Limiting binding) and `wrangler` (a dev dependency of `relay/`: run it with
`pnpm --filter ./relay exec wrangler …`, or from `relay/` with `pnpm exec wrangler …`).

The tracked `wrangler.jsonc` holds placeholder ids for development and tests. Don't edit it for a
deployment. Keep your account's ids in a copy that git ignores:

1. In `relay/`, copy the config: `cp wrangler.jsonc wrangler.deploy.jsonc`
   (`relay/wrangler.deploy.jsonc` is in `.gitignore`).
2. Create the database, `wrangler d1 create 00hooks`, and put its id in `wrangler.deploy.jsonc`
   (`d1_databases[0].database_id`).
3. Give each Rate Limiting binding a `namespace_id` of your own (a positive integer, as a string).
   Each `namespace_id` must be unique within your Cloudflare account: two Workers, or two bindings,
   that share one share its counters.
4. Set your variables in its `vars` (see "Settings").
5. Set the secrets with `wrangler secret put <NAME> -c wrangler.deploy.jsonc`:

   | Name | What | Example |
   |---|---|---|
   | `SECRETS_KEY` | AES-256-GCM key sealing hook signing secrets at rest: 32 random bytes, base64 | `openssl rand -base64 32` |
   | `HASH_PEPPER` | HMAC key for enrolment-code, client-IP, dedupe-mark and API-key hashes | `openssl rand -base64 32` |
   | `RELAY_SIGNING_KEY` | Ed25519 seed (32 bytes, base64) signing every sealed envelope. Its public half is `/v1/info`'s `relayKey`, which clients pin at login: changing it makes every device log in again. Without it the relay takes no deliveries | `openssl rand -base64 32` |
   | `SIGNUP_TOKEN` | Creating an account needs `Authorization: Bearer <token>`. The relay refuses every signup unless this is set or `OPEN_SIGNUP=1` is (`/v1/info` reports `signupOpen`) | `openssl rand -base64 24` |
   | `APNS_KEY` | Optional, for push (below): the contents of the `.p8` key file from your Apple developer account, BEGIN and END lines included | `wrangler secret put APNS_KEY -c wrangler.deploy.jsonc < AuthKey_XXXXXXXXXX.p8` |
   | `APNS_KEY_ID` | That key's 10-character key id | `wrangler secret put APNS_KEY_ID -c wrangler.deploy.jsonc` |
   | `APNS_TEAM_ID` | Your Apple developer team's 10-character id | `wrangler secret put APNS_TEAM_ID -c wrangler.deploy.jsonc` |
   | `APNS_TOPIC` | The phone app's bundle id | `wrangler secret put APNS_TOPIC -c wrangler.deploy.jsonc` |
   | `APNS_ENVIRONMENT` | `sandbox` for development builds of the app, `production` (the default when unset) for TestFlight and the App Store | `wrangler secret put APNS_ENVIRONMENT -c wrangler.deploy.jsonc` |
   | `FCM_SERVICE_ACCOUNT` | Optional, for Android push (below): the whole JSON key file of a service account of your Firebase project (Project settings → Service accounts → Generate new private key) | `wrangler secret put FCM_SERVICE_ACCOUNT -c wrangler.deploy.jsonc < service-account.json` |

   With `npx`: `npx wrangler secret put APNS_KEY -c wrangler.deploy.jsonc < AuthKey_XXXXXXXXXX.p8`,
   and so on for each name.

6. Apply the migrations, then deploy:

   ```sh
   wrangler d1 migrations apply DB --remote -c wrangler.deploy.jsonc
   wrangler deploy -c wrangler.deploy.jsonc
   ```

**Upgrading**: before each deploy, compare your `wrangler.deploy.jsonc` with `wrangler.jsonc` and
copy in what is new (bindings, Durable Object migrations, rate limits, the cron trigger), keeping
your own ids. Then apply the D1 migrations (`wrangler d1 migrations apply DB --remote -c
wrangler.deploy.jsonc`), and only then deploy: new code may need the new tables. The migrations:

| Migration | What |
|---|---|
| `0001_init.sql` | accounts, devices, hooks, enrolments |
| `0002_phase1.sql` | sealing keys, API keys |
| `0003_channels.sql` | Meta's verify token, offline notices |
| `0004_screen.sql` | the screen's rules |
| `0005_phone.sql` | phone links; needs the `PHONE` Durable Object binding, its `v2` migration and `PAIR_IP_LIMIT` |
| `0006_…` | hook names unique within an account |
| `0007_…` (when present) | phone hardening |

Then measure what idle streams cost on your deployment: [`docs/IDLE-COST.md`](docs/IDLE-COST.md).

### Bindings

All in `wrangler.jsonc`:

- `ACCOUNT`: the `AccountObject` Durable Object, SQLite-backed, one per account: the event log,
  cursors, nonces and dedupe marks.
- `PHONE`: the `PhoneObject` Durable Object, SQLite-backed, one per account, added by the migration
  tag `v2`: the phone links' queue and sockets.
- `DB`: D1. Accounts, devices, hooks with their sealed secrets, enrolments, API keys, the audit, and
  the routing from a hook id to its account.
- Eight Rate Limiting bindings. The relay answers `503` rather than run without them.

  | Binding | `namespace_id` in `wrangler.jsonc` | Limits |
  |---|---|---|
  | `HOOK_LIMIT` | 1001 | deliveries per hook: 60 per 10 s |
  | `RECEIVE_IP_LIMIT` | 1002 | deliveries per client address: 600 per 10 s, checked before the hook lookup |
  | `REDEEM_IP_LIMIT` | 1003 | enrolment redemptions per address: 10 a minute |
  | `REDEEM_GLOBAL_LIMIT` | 1004 | enrolment redemptions in all: 300 a minute |
  | `PAIR_IP_LIMIT` | 1005 | phone pairing attempts per address: 10 a minute |
  | `SIGNUP_IP_LIMIT` | 1006 | account creations per address, per minute |
  | `API_IP_LIMIT` | 1007 | management requests (`/v1/*`) per address, per 10 s, checked before any database read |
  | `PAIR_GLOBAL_LIMIT` | 1008 | phone pairing attempts in all, per minute |

  Addresses are counted by IPv4 address or IPv6 /64. Cloudflare counts Rate Limiting per location
  (data centre), and the counts are eventually consistent: a limit "in all" is per location, not
  for the whole relay. The exact quotas below are counted in the Durable Object.
- A daily cron trigger (`triggers.crons`) prunes expired D1 rows.
- `observability`: invocation logs are off, so request URLs and their query strings (Meta's
  `hub.verify_token`, for one) are not logged.

### Settings

Variables (`vars`), all optional unless noted:

| Name | Default | What |
|---|---|---|
| `OPEN_SIGNUP` | unset | `1` lets anyone create an account without `SIGNUP_TOKEN`. Set it only on purpose: for local development, or a relay meant to be open |
| `RETENTION_DAYS` | 7 | how long unacknowledged events are kept |
| `ACCOUNT_MAX_EVENTS`, `ACCOUNT_MAX_BYTES` | 10,000, 256 MiB | how much one account's log may hold before deliveries get `429` `quota` (events waiting for an acknowledgement; bytes of bodies and headers) |
| `HOOK_MAX_EVENTS`, `HOOK_MAX_BYTES` | half the account's | how much of the account's log one hook may hold |
| `UNCHECKED_HOOK_MAX_EVENTS`, `UNCHECKED_HOOK_MAX_BYTES` | 1/16 of the account's | the same for strict and unverified hooks, whose deliveries the relay can't fully check |
| `HELD_MAX_EVENTS`, `HELD_MAX_BYTES` | 200, 16 MiB per hook | how many events the screen may hold for review (quarantine). Held events have this quota of their own and don't count against the log's |
| `SCREEN_HELD_DAYS` | 7 | how long the screen holds an event before dropping it (PROTOCOL §4b) |
| `REPLAY_MARK_DAYS` | 180 | how long body-hash replay marks are kept for presets that sign no timestamp. After that, a captured body is accepted again as a new event (see PLAN §3.1) |
| `ACCOUNT_MAX_DEVICES` | 10 | node devices per account |
| `PHONE_NODE_QUEUE_MAX`, `PHONE_PHONE_QUEUE_MAX`, `PHONE_QUEUE_MAX_BYTES` | 1,000, 500, 16 MiB | how much a phone link's queue may hold (PROTOCOL §10.5) |
| `PHONE_PUSH_PER_HOUR` | 30 | pushes one phone may be sent in a rolling hour (PROTOCOL §10.7) |
| `HOSTED_EXTRAS` | unset | extras the operator offers, as JSON, announced as data in `/v1/info` `extras` (PROTOCOL §2). A self-hosted relay leaves it unset |

### Push

Push is off until its secrets above are set: every `POST /v1/phone/push` answers
`{ "sent": false, "reason": "unavailable" }` and nothing goes to Apple or Google. iPhones (requests
with no `platform`, or `"ios"`) need `APNS_KEY`, `APNS_KEY_ID`, `APNS_TEAM_ID` and `APNS_TOPIC`, with
a key that imports; Android phones (`"platform": "android"`) need `FCM_SERVICE_ACCOUNT`. Either can
be set without the other. `/v1/info` says which under `phone.push.platforms`
(`{ "ios": { "available", "environment" }, "android": { "available" } }`), and keeps
`phone.push.available` and `environment` for iOS. The node keeps each phone's device token and
sends it with each request; the relay keeps no token, sends a fixed alert per kind, and limits each
phone to one push per kind a minute and 30 an hour, whichever platform (PROTOCOL §10.7). The
service account is used only to get a token for sending messages
(`https://www.googleapis.com/auth/firebase.messaging`). The requests to Apple and Google were checked
against mocks in the tests, not against the real services: try one push on a development build
before relying on it.

## Security notes

- **Requests are signed by device keys** (Ed25519 over the device id, host, method, path and query,
  time, nonce and body hash; PROTOCOL §1 has a test vector the relay's tests check). The private key never leaves the device. Requests more than 300 s off the relay's
  clock are refused (`clock_skew`, with the server's time), and every nonce is spent in the
  account's Durable Object, strongly consistent, GET requests included, so a captured stream request
  can't be replayed into a live copy of the account's events.
- **Revoking a device** closes its open stream at once (`4401`) and stops it holding events back.
  The account's Durable Object is told first, every time, so revoking again finishes a revocation
  that failed part-way.
- **Enrolment codes** are 60 random bits. Every redemption attempt is counted atomically before the
  code is checked (IPv6 clients by /64); five wrong codes block the address for 10 minutes, and the
  Rate Limiting bindings cap attempts per address and in all.
- **Hook secrets** are generated from 32 random bytes, shown once (create or rotate), and stored
  sealed with AES-256-GCM under `SECRETS_KEY`, with the hook id as associated data. Rotation keeps
  the previous secret valid for 24 hours. A secret you supply is never echoed back. Creating a hook
  with a relay-generated secret, or rotating one, needs a device signature or an API key with the
  `hooks:secrets` scope: `hooks:write` alone can't obtain a secret.
- **Verification** runs over the raw bytes before anything is parsed, with constant-time
  comparisons, and checks every valid secret, not just until one matches. Failures answer `401`
  `signature` and are counted, never stored.
- **Replays**: GitHub deliveries dedupe on `X-GitHub-Delivery` and, since that header isn't signed,
  always on the body hash too (so a captured body can't come back under a new delivery id);
  Standard Webhooks on `webhook-id` within a 300 s timestamp window, generic HMAC on the body hash.
  Marks for presets that sign no timestamp are kept `REPLAY_MARK_DAYS` (180 days by default).
  The dedupe marks are written in the same Durable Object transaction as the event, so a crash
  can't lose an event that was marked. GitHub's `eventType` (`X-GitHub-Event`) is the sender's
  claim: PROTOCOL §3 lists what each preset signs.
- **Limits**: bodies are checked against the hook's limit (1 MiB by default) from `Content-Length`
  and again while streaming; each client address and each hook is rate limited at the edge, and so
  are signups, management requests and pairing attempts; each account's log has a quota, each hook
  a share of it, and held events a quota of their own.
- **What's kept**: only an allowlist of headers per preset (event and delivery headers,
  `content-type`, `user-agent`), never `cookie`, `authorization` or a signature or token header.
  Enrolment codes, client IPs, dedupe marks and API keys are stored only as HMACs under
  `HASH_PEPPER`.
- **Sealing**: the body and kept headers are sealed with HPKE (X25519, HKDF-SHA256,
  ChaCha20-Poly1305) to each device's key, with the hook, seq and event id as associated data, and
  each envelope is signed with `RELAY_SIGNING_KEY`. The object's SQLite holds routing metadata and
  ciphertext only (a test reads every table to check); the plaintext exists only in memory while it
  is verified and sealed. A device's envelopes are deleted once it acknowledges them.
- **Strict hooks** keep the provider's secret on the devices: the relay checks only the header's
  shape and timestamp, and the devices verify the signature (PROTOCOL §3).
- **API keys** (`hk_…`) are scoped, expire, are shown once, and can never stream, acknowledge,
  enrol a device, set a sealing key or create keys. Only the `hooks:secrets` scope lets one obtain a
  hook secret. The audit log records hooks, devices and keys,
  and counts key uses and verification failures per hour.
- **Phone links** (PROTOCOL §10): the relay routes sealed envelopes between a node and its phones
  and never opens them; it keeps a pairing only as a verifier of its proof (spent once, atomically),
  checks only routing (`from` is the signed-in device, `to` its peer), sizes, rates and queues, and
  stores envelopes as received until acknowledged. A phone may use only the phone routes. Push
  (PROTOCOL §10.7) sends only fixed alert texts and the node's sealed preview, to Apple or Google
  hosts that aren't configurable; the device token is never stored or logged.
- **Errors** are fixed sentences: they never quote a secret, a signature or payload content.
- **Webhook content is data**: the relay never acts on it.
