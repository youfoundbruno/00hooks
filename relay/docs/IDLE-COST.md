# Measuring what an idle stream costs

The relay's design rests on one claim (PLAN §10): the Worker holds each client's SSE response and
talks to the account's Durable Object over a **hibernatable WebSocket**, so the object sleeps, and
costs nothing, while the stream idles. If the object held the SSE response itself it would stay
awake: about **$4.20 per always-on connection per month** in duration alone (730 h × 3600 s ×
0.128 GB × $12.50 per million GB-s).

The claim comes from the documentation, so phase 0 measures it on a real deployment before anything
depends on it. `scripts/idle-cost.ts` does the measuring.

## What it does

1. Creates one account per connection (each always-on user has their own Durable Object).
2. Opens one signed SSE stream per account and holds it for the whole window, reconnecting the way a
   client does (PROTOCOL §6: a random wait between half and all of `min(30 s, retry × 2^attempt)`,
   reset by `ready`; 70 s without a byte counts as a drop). It
   logs reconnects and closes, a summary every 10 minutes, and at the end the heartbeat count against
   the expected one (one per connection every 15 s).
3. When `CF_ACCOUNT_ID` and `CF_API_TOKEN` are in the environment, queries Cloudflare's GraphQL
   Analytics API (`durableObjectsPeriodicGroups` for awake time, CPU and WebSocket messages;
   `durableObjectsInvocationsAdaptiveGroups` for requests) over the window, a day at a time, and
   prints the cost per connection per month with a verdict.

Nothing is sent to Cloudflare's API unless both variables are set, and neither is stored or printed.
The token needs only **Account Analytics: Read**.

## Running it after a deploy

The deploy itself is a separate, deliberate step (see the README's self-hosting section). Then:

```sh
# 1. Hold 10 idle streams for 24 hours (a week, --hours 168, is the phase 0 exit test).
#    SIGNUP_TOKEN only if the relay has one.
SIGNUP_TOKEN=… pnpm --filter ./relay idle-cost -- \
  --relay https://<your relay> --connections 10 --hours 24 | tee idle-cost.log

# 2. Analytics lag a few minutes behind. Afterwards, analyse the exact window the run printed:
CF_ACCOUNT_ID=<32 hex> CF_API_TOKEN=<analytics-read token> \
  pnpm --filter ./relay idle-cost -- --relay https://<your relay> --connections 10 \
  --start <start from the log> --end <end from the log> --namespace-id <the ACCOUNT namespace id>
```

`--namespace-id` (the Durable Object namespace's id, shown in the dashboard under the Worker's
Durable Objects) keeps other Workers' objects on the same account out of the sums. Without it, the
script sums every namespace and says so. Run it on an otherwise quiet relay: real webhook traffic in
the window is billed too, and would be counted against the idle streams.

If the API answers with an unknown-field error, the dataset's fields have changed. Check them with
GraphQL introspection and adjust `buildQuery` in `scripts/idle-cost-lib.ts`. Its tests pin the
parsing and the arithmetic.

## Reading the result

The report prints the measured totals, the extrapolated cost per always-on connection per month
(duration and requests, as marginal prices before the account's included allowances), the
always-awake baseline, and the share of the window the objects were awake.

- **The bridge works** when the objects were awake for **under 1%** of the window: duration per
  connection-month is a few GB-s, a cost of fractions of a cent. Expect small, bounded wakes: the
  stream connect itself, and one alarm about 10 minutes later that clears the connect's nonce. The
  Worker's 30 s liveness pings are answered by the object's WebSocket auto-response, which doesn't
  wake it and isn't billed, and the 15 s heartbeats are written by the Worker alone.
- **The bridge doesn't hibernate** when the objects were awake for **most of the window** (the
  script says "always-awake", near $4.20 per connection-month). Something keeps them awake: a timer
  or a pending promise in the object, a WebSocket accepted with `accept()` instead of
  `ctx.acceptWebSocket()`, or messages that need the object's code. The fallback is a direct
  WebSocket from the CLI to the object (PLAN §10).
- **In between** is inconclusive: look for traffic during the window, unexpected alarms, or a client
  reconnecting in a loop (the log's reconnect count).

The requests figure is an upper bound: analytics count incoming WebSocket messages one for one,
while billing counts them 20 to 1. The Worker side is billed by CPU time only, which an idle stream
barely uses, and isn't included.
