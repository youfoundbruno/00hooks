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
  cursors, sockets); `src/phone-push.ts`: the push hook (not built). `migrations/`: the D1 schema.
- `scripts/seal-interop.ts` seals events with `src/envelope.ts` under Node, for the CLI's interop
  tests (`fixtures/seal-interop.v1.json`).

## Develop

From the repository root (a pnpm workspace; `pnpm install` once):

```sh
cp relay/.dev.vars.example relay/.dev.vars    # then fill in the three secrets
pnpm --filter ./relay exec wrangler d1 migrations apply 00hooks --local
pnpm --filter ./relay dev                     # http://localhost:8787, all local
pnpm --filter ./relay test                    # vitest inside workerd (Miniflare)
pnpm --filter ./relay typecheck
pnpm check                                    # everything a change must pass
```

The tests run the real Worker, Durable Object (SQLite storage, alarms, hibernatable WebSockets), D1
and Rate Limiting binding in workerd. After changing `wrangler.jsonc`, regenerate the binding types
with `pnpm --filter ./relay types`.

## Self-hosting

You need a Cloudflare account on the Workers Paid plan (Durable Objects with SQLite storage and the
Rate Limiting binding). In `relay/`:

1. `wrangler d1 create 00hooks`, and put the database id in `wrangler.jsonc`.
2. `wrangler d1 migrations apply 00hooks --remote`.
3. Set the secrets with `wrangler secret put <NAME>`:

   | Name | What | Example |
   |---|---|---|
   | `SECRETS_KEY` | AES-256-GCM key sealing hook signing secrets at rest: 32 random bytes, base64 | `openssl rand -base64 32` |
   | `HASH_PEPPER` | HMAC key for enrolment-code, client-IP, dedupe-mark and API-key hashes | `openssl rand -base64 32` |
   | `RELAY_SIGNING_KEY` | Ed25519 seed (32 bytes, base64) signing every sealed envelope. Its public half is `/v1/info`'s `relayKey`, which clients pin at login: changing it makes every device log in again. Without it the relay takes no deliveries | `openssl rand -base64 32` |
   | `SIGNUP_TOKEN` | Optional. When set, creating an account needs `Authorization: Bearer <token>`. Without it, anyone can sign up: development only (`/v1/info` reports `signupOpen`) | `openssl rand -base64 24` |

4. `wrangler deploy`.

Bindings (all in `wrangler.jsonc`): `ACCOUNT` (the `AccountObject` Durable Object, SQLite-backed),
`PHONE` (the `PhoneObject` Durable Object, SQLite-backed, added by the migration tag `v2`: the phone
links' queue and sockets, one per account),
`DB` (D1: accounts, devices, hooks with their sealed secrets, enrolments, and the routing from a
hook id to its account), and four Rate Limiting bindings: `HOOK_LIMIT` (60 deliveries per 10 s per
hook), `RECEIVE_IP_LIMIT` (600 deliveries per 10 s per client address, checked before the hook
lookup), `REDEEM_IP_LIMIT` and `REDEEM_GLOBAL_LIMIT` (enrolment redemptions: 10 a minute per address,
300 a minute in all), and `PAIR_IP_LIMIT` (phone pairing attempts: 10 a minute per address). The
relay answers `503` rather than run without them. Variables:
`RETENTION_DAYS` (default 7), how long unacknowledged events are kept; `ACCOUNT_MAX_EVENTS` (10,000)
and `ACCOUNT_MAX_BYTES` (256 MiB), how much one account's log may hold before deliveries get `429`
`quota`; `PHONE_NODE_QUEUE_MAX` (1,000), `PHONE_PHONE_QUEUE_MAX` (500) and `PHONE_QUEUE_MAX_BYTES`
(16 MiB), optional, how much a phone link's queue may hold (PROTOCOL §10.5).

**Upgrading a relay deployed before phone links**: apply the D1 migration `0005_phone.sql`
(`wrangler d1 migrations apply 00hooks --remote`) before deploying, and copy into your own deploy
config the `PHONE` Durable Object binding, the `v2` migration (`new_sqlite_classes: ["PhoneObject"]`)
and the `PAIR_IP_LIMIT` rate limit from `wrangler.jsonc`. Without the binding, pairing answers
`503`.

Then measure what idle streams cost on your deployment: [`docs/IDLE-COST.md`](docs/IDLE-COST.md).

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
  the previous secret valid for 24 hours. A secret you supply is never echoed back.
- **Verification** runs over the raw bytes before anything is parsed, with constant-time
  comparisons, and checks every valid secret, not just until one matches. Failures answer `401`
  `signature` and are counted, never stored.
- **Replays**: GitHub deliveries dedupe on `X-GitHub-Delivery` and, since that header isn't signed,
  always on the body hash too (so a captured body can't come back under a new delivery id);
  Standard Webhooks on `webhook-id` within a 300 s timestamp window, generic HMAC on the body hash.
  The dedupe marks are written in the same Durable Object transaction as the event, so a crash
  can't lose an event that was marked. GitHub's `eventType` (`X-GitHub-Event`) is the sender's
  claim: PROTOCOL §3 lists what each preset signs.
- **Limits**: bodies are checked against the hook's limit (1 MiB by default) from `Content-Length`
  and again while streaming; each client address and each hook is rate limited at the edge; each
  account's log has a quota.
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
  enrol a device, set a sealing key or create keys. The audit log records hooks, devices and keys,
  and counts key uses and verification failures per hour.
- **Phone links** (PROTOCOL §10): the relay routes sealed envelopes between a node and its phones
  and never opens them; it keeps a pairing only as a verifier of its proof (spent once, atomically),
  checks only routing (`from` is the signed-in device, `to` its peer), sizes, rates and queues, and
  stores envelopes as received until acknowledged. A phone may use only the phone routes.
- **Errors** are fixed sentences: they never quote a secret, a signature or payload content.
- **Webhook content is data**: the relay never acts on it.
