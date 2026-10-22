# What the relay costs on Cloudflare

An **estimate** for a self-hosted relay: what one delivered webhook uses, what the Workers Paid
plan's $5 covers, and what more traffic adds. Prices are Cloudflare's
[Workers pricing page](https://developers.cloudflare.com/workers/platform/pricing/) and
[Durable Objects pricing page](https://developers.cloudflare.com/durable-objects/platform/pricing/)
as of **2026-10-22**; check them before relying on these numbers. Your own bill is the truth: the
dashboard's usage pages, and `scripts/idle-cost.ts` ([IDLE-COST.md](IDLE-COST.md)) for idle streams.

## Prices used (Workers Paid, standard model)

| | Included per month | Then |
| --- | --- | --- |
| Account minimum | | $5 / month |
| Worker requests | 10 million | $0.30 / million |
| Worker CPU time | 30 million ms | $0.02 / million ms (duration isn't charged) |
| Durable Object requests (HTTP, RPC calls, WebSocket connects, alarms) | 1 million | $0.15 / million; incoming WebSocket messages count 20:1, outgoing ones are free |
| Durable Object duration (billed at 128 MB) | 400,000 GB-s | $12.50 / million GB-s |
| Durable Object SQLite rows read | 25 billion | $0.001 / million |
| Durable Object SQLite rows written (deletes and each index entry count; so does `setAlarm`) | 50 million | $1.00 / million |
| Durable Object SQLite storage | 5 GB-month | $0.20 / GB-month |
| D1 rows read / written | 25 billion / 50 million | same prices as above |
| D1 storage | 5 GB | $0.75 / GB-month |
| Rate Limiting binding | no price listed on either page or in the binding's docs | |

## What one webhook uses

A delivery to a verified hook (GitHub's preset: two dedupe keys, a delivery id and a body hash),
1 KB body, the default plan (no rate limits or daily cap), every device connected and acknowledging
each event on its own. "Each extra device" is what one more recipient adds.

| | 1 device | Each extra device | Where |
| --- | --- | --- | --- |
| Worker requests | 2 | +1 | the delivery (`POST /h/<id>`, `src/receive.ts:110`) and the ack (`POST /v1/ack`, `src/index.ts:250`, `src/stream.ts:73`). The event reaches the device over its open SSE stream: no request (`deliverLive`, `src/account-object.ts:2176`; `src/bridge.ts:99`) |
| Durable Object requests | 3 | +2 | `append` (`src/receive.ts:205`); the ack's signed-request nonce (`spendNonce`, `src/auth.ts:142`) and the ack itself (`src/stream.ts:79`). The event goes to the bridge as an outgoing WebSocket message: free |
| SQLite rows written | ~18 | ~+7 | measured, below |
| SQLite rows read | ~120 | ~+55 | measured, below |
| D1 rows read | ~3 | +1 | the hook and its account in one query (`src/receive.ts:48`), the device on the ack (`src/auth.ts:100`) |
| D1 rows written | ~0 | 0 | `last_event_at` at most once a minute per hook (`src/receive.ts:265`), `last_seen_at` at most once a minute per device (`src/auth.ts:145`). The plan's daily counters live in the Durable Object, not D1 |
| Worker CPU | ~2 to 5 ms | ~+1 ms | estimate: HMAC check, keyed hashes of the dedupe keys (`src/receive.ts:199`), JSON; the ack's Ed25519 check (`src/auth.ts:134`) |
| Durable Object awake time | ~15 ms to 1 s | a few ms | estimate, below |

### Rows written, measured

Counted with the Durable Object's own per-query `rowsWritten` and `rowsRead` counters (and its
`setAlarm` calls), in the test runtime (workerd, the same SQLite schema), on one GitHub delivery
after a warm-up event. `test/costs.ts` runs the scenarios and `test/costs.test.ts` holds them to
upper bounds, so a change that raises them fails; `pnpm vitest run test/costs.test.ts
--reporter=verbose` prints them. An insert counts its row and each index entry; in this runtime a
delete counts one row.

| Step | Rows | Code |
| --- | --- | --- |
| `append`: dedupe marks, 2 per key (row and the `seen_long_at` index) | 4 | `writeMarks`, `src/account-object.ts:914` |
| `append`: the event row (row and the `events_stored` index) | 2 | `:1154` |
| `append`: one sealed envelope per device (row and the `envelopes_seq_device` index) | 2 per device | `:1170` |
| `append`: one row for the hook (its share of the log, today's count, its token bucket, its last delivery) and one for the account (the head, today's count, its token bucket) | 2 | `commitCounts`, `:1262` |
| **`append`, 1 device** | **10** (3 devices: 14) | |
| ack: nonce (no index) | 1 | `spendNonce`, `:846` |
| ack: cursor, delete own envelope, the hook's row | 3 | `ack` `:1751`, `deleteEnvelopes` `:772`, `applyUsage` `:712` |
| last ack of an event: delete the event (the hook's row is the same write) | +1 | `pruneAcknowledged` `:2226`, `deleteRange` `:786` |
| **acks, 1 device** | **5** (3 devices: 4 + 4 + 5) | |
| later, in the hourly alarm: the nonce, and the two dedupe marks after 7 or 180 days | 3 (+1 per device) | `alarm`, `:2280` |

So about **18 rows written per webhook for one device, and about 7 more per extra device**. The
alarm's own `setAlarm` (one row) is shared by everything it prunes that hour, so it isn't counted
per webhook. Rows read are about 35 for the `append`, 40 to 45 per ack and 40 for the alarm.

Measured, before and after the schema 8 change that brought it down (rows written):

| Scenario | Before | After |
| --- | --- | --- |
| 1 device (append + ack + alarm) | 36 (21 + 12 + 3) | 18 (10 + 5 + 3) |
| 3 devices | 58 (27 + 26 + 5) | 32 (14 + 13 + 5) |
| Plan with a hook rate, an account rate and a daily cap, 1 device | 38 | 18 |
| A duplicate | 0 | 0 |
| A held delivery | 15 | 12 |

How it stays low (schema 8, `migrateTo8`):

- **Counters share rows.** Every count an append makes (the head, today's count for the account and
  the hook, the token buckets, the hook's last delivery, its share of the log) is written in the
  commit's transaction, in one row for the account (`counters`) and one for the hook
  (`hook_usage`). Deliveries decided but still being sealed are counted from memory until they
  commit, so the daily cap and the buckets stay exact, and a delivery lost before its commit was
  never stored and is never counted. What the log holds in all is the sum of the hooks' rows.
- **Only the indexes a query reads.** The event row keeps `events_stored` (retention), an envelope
  `envelopes_seq_device`, a dedupe mark `seen_long_at` (its expiry), and nonces none: the hourly
  alarm scans them (at most the last hour's), and between alarms only a nonce just spent can move
  the alarm earlier.
- **A step writes each counter once.** An ack, a revoke or the alarm gathers what its deletes take
  from each hook and writes the hook's row once, in one transaction.

Assumptions that move this:

- **Dedupe keys.** 0 to 2 per preset (2 rows each, and 1 more when the alarm deletes it):
  `unverified` has none, GitHub two.
- **Batched acks.** The reference client acknowledges what it read in one go, so a burst shares one
  ack (one Worker request, two Durable Object requests, one nonce, one cursor and one write of the
  hook's row), though each event's deletes still count.
- **Plans.** Rate limits and the daily cap add no rows: they are columns of the two counter rows.
  Refusals are counted in rows of their own (`daily`, `refusals`, `limit_notices`).
- **The screen.** A dropped delivery never reaches the object (counted at the edge,
  `src/edge-counts.ts`). A held one is written to the hold instead of the log (12 rows with the
  GitHub preset and one device), plus one Durable Object request for its audit count
  (`src/receive.ts:268`), and a release later is another request.
- **Duplicates** cost one Durable Object request and no writes (`src/account-object.ts:1024`).
  **Forged signatures** cost Worker CPU only; the object hears of them at most once a minute per hook.
- **Rate Limiting.** Two `limit()` calls per delivery (`src/receive.ts:117`, `:135`), with no listed
  price.

### Awake time (estimate)

The object is billed for wall-clock time while it runs a request. It is awake for the `append`
(sealing to each device with HPKE, signing each envelope with Ed25519, one SQLite transaction), then
briefly for the nonce and the ack. In between it holds nothing but hibernatable WebSockets: no timers,
no pending promises, so it is eligible for hibernation, and Cloudflare doesn't bill duration for an
idle object that can hibernate. The alarm that prunes runs at most hourly (`ALARM_BUCKET_MS`,
`src/account-object.ts:2336`).

That gives roughly **15 ms per webhook for a 1 KB body and one device**, more with large bodies (the
sealing is in JavaScript, once per device) and many devices. We use **0.1 s** as the planning figure
(0.0128 GB-s at 128 MB) and **1 s** as a pessimistic one. This hasn't been measured under load: run
`scripts/idle-cost.ts` with `CF_ACCOUNT_ID` and `CF_API_TOKEN` over a window with real traffic (it
reads awake time from the analytics API) to see yours.

## What $5 covers

With one device, per webhook: 3 Durable Object requests, ~18 rows written, 2 Worker requests,
~5 ms CPU, ~0.0128 GB-s. Each allowance runs out at:

| Allowance | Webhooks a month, 1 device | 3 devices |
| --- | --- | --- |
| **Durable Object requests (1 M)** | **~330,000 (first)** | **~140,000 (first)** |
| SQLite rows written (50 M) | ~2.8 million | ~1.6 million |
| Worker requests (10 M) | 5 million | 2.5 million |
| Worker CPU (30 M ms) | ~6 million | ~4 million |
| Duration (400,000 GB-s) | ~31 million at 0.1 s; ~3 million at 1 s | about the same |
| SQLite rows read (25 B) | ~200 million | ~100 million |

Durable Object requests run out first, but they are cheap; rows written are what cost money after.

## What more costs

Per extra million webhooks, once each allowance is used up (1 device):

| | Usage | Cost |
| --- | --- | --- |
| SQLite rows written | 18 million | $18.00 |
| Worker requests | 2 million | $0.60 |
| Durable Object requests | 3 million | $0.45 |
| Duration (0.1 s each) | 12,800 GB-s | $0.16 (at 1 s: $1.60) |
| Worker CPU | 5 million ms | $0.10 |
| **Total** | | **~$19** |

Each extra device adds about $7.60 per million (7 million rows written, 1 million Worker requests,
2 million Durable Object requests).

**Formula.** For W webhooks a month to N devices, in millions of W:

```
$5
+ $0.15 × max(0, W × (1 + 2N) − 1)            Durable Object requests
+ $1.00 × max(0, W × (18 + 7 × (N − 1)) − 50)  rows written
+ $0.30 × max(0, W × (1 + N) − 10)             Worker requests
+ CPU and duration: cents, until tens of millions
```

**Worked examples** (prices as of 2026-10-22, estimates):

| Traffic | Over the allowances | Monthly |
| --- | --- | --- |
| 100,000 webhooks, 1 device | nothing (300,000 DO requests, 1.8 M rows written) | **$5** |
| 1 million, 1 device | 2 M DO requests ($0.30) | **~$5.30** |
| 2 million, 1 device | 5 M DO requests ($0.75); 36 M rows written are within the 50 M | **~$5.75** |
| 5 million, 1 device | 14 M DO requests ($2.10), 40 M rows written ($40) | **~$47** |
| 10 million, 3 devices | 69 M DO requests ($10.35), 270 M rows written ($270), 30 M Worker requests ($9), CPU ($0.60) | **~$295** |

## Idle connections

A connected device that receives nothing costs fractions of a cent a month:

- **Connecting** is 1 Worker request, 2 Durable Object requests (the nonce, `src/auth.ts:142`, and the
  WebSocket, `src/stream.ts:52`), ~2 rows written (the nonce, `streamSeen`,
  `src/account-object.ts:2031`; a `setAlarm` too when none is set), and one alarm about 10 minutes
  later that clears the nonce.
- **The 15 s heartbeats** are written by the Worker alone (`src/bridge.ts:217`), and Worker duration
  isn't billed.
- **The 30 s pings** to the object (`src/bridge.ts:231`) are answered by its WebSocket auto-response
  (`src/account-object.ts:375`), which doesn't wake it. Even if every ping were billed as an incoming
  message (20:1), that is about 4,400 requests a month: $0.0007.
- **Duration** is a few GB-s a month (the connect, the alarm, reconnects): well under a cent.

If the object didn't hibernate it would cost about $4.20 per always-on connection a month; that's
what [IDLE-COST.md](IDLE-COST.md) measures.

## Caveats

- **Workers Paid is required** ($5 a month minimum per account): Durable Objects with SQLite storage
  and the Rate Limiting binding need it. Other Workers on the same Cloudflare account share the
  allowances.
- **Body size.** Rows written don't depend on size, but storage does: each device gets its own sealed
  copy, kept until it acknowledges or for up to 7 days. The account's backlog quota (256 MiB by
  default) caps it, so one account stays well inside the 5 GB included. Large bodies also take longer
  to seal, once per device (awake time).
- **Many devices** multiply the envelopes, acks and rows written (~7 rows each per webhook).
  Sending a hook to the one device that needs it (`00hooks hooks deliver-to`) saves the rest.
- **Long offline periods** cost little by themselves (events wait in storage, and reading the backlog
  on reconnect is cheap reads), but events older than 7 days are dropped, and a full backlog
  (10,000 events) refuses new deliveries.
- **Replay marks** for presets that sign no timestamp (GitHub's body hash) are kept 180 days
  (`REPLAY_MARK_DAYS`), about 100 bytes each: at a million webhooks a month that is around 1 GB of
  storage after six months.
- These figures come from reading the code and a local count, not from a bill. Prices change.
