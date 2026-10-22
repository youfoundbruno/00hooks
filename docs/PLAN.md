# 00hooks — the plan

**00hooks** brings events from the internet to your own computer, in real time and safely. Any service
that can send a webhook (GitHub, Stripe, Shopify, Slack, a form builder, your own app) points at a
hook URL. A small relay on Cloudflare checks that the event is genuine, seals it so only your devices
can read it, and streams it to the `00hooks` CLI on your Mac or Linux machine. There, it triggers an
automation: a plain action (notify me, call this URL, run this allowed command, write a file). A
program that embeds the runner and runs AI agents can also hand an event to an agent, with
instructions and a tightly limited set of permissions (§5.2, §6); the CLI itself runs plain actions
only.

It's a standalone open-source project (Apache-2.0). You can run your own relay, with exactly the
behaviour described here and no limits beyond the ones you set; there is also a hosted relay, whose
accounts come with the Overblast Plan (§4.6). The CLI works on its own, and its libraries can be
embedded by other programs.

Status: phases 0 to 3, 5 and 6 are built (§7): the relay (hooks, presets, replay protection,
sealing, device pairing, API keys, the audit, the edge screen, one-device delivery, static
responses, signed test events, a one-command installer), the CLI (`login`, `devices`,
`hooks`, `keys`, `audit`, `listen`, `doctor`, `run`, `automations`, `kinds`, `runs`, `replay`,
`service`, `secrets`, `screen`, `test`, `relay status`), the runner, the `hooks-screen` crate, the runner's interface
for programs that run agents, and phone links: a phone pairs with a node device,
and the relay routes the sealed envelopes between them, keeps them while a side is offline and says
who is online, without ever seeing their content (PROTOCOL §10), and can wake a phone with a
push that carries no readable content (APNs for iPhones, FCM for Android). Anything marked *(not built)* is not built;
anything marked *not planned* was weighed and left out, and says why.

---

## 1. The shape

```
 GitHub ─┐                    Cloudflare (your own account)
 Stripe ─┤   POST /h/<hook>   ┌────────────────────────────────────────────────┐
 Shopify ┼──────────────────▶ │ Worker: limits, verify the signature, dedupe   │
 Forms  ─┘   (any webhook)    │   │                                            │
                              │   ▼                                            │
                              │ Account Durable Object                         │
                              │   ordered log (sealed payloads), cursors, acks │
                              └───────────────┬────────────────────────────────┘
                                              │ SSE stream, resumable
                                              ▼
                     00hooks CLI (or a program that embeds its libraries)
                     unseal ▸ match automations ▸ run actions ▸ record the run
                         │                 │                    │
                   notify me      call a URL / allowed     an agent with an
                   (no LLM)       command (no LLM)         access profile (LLM,
                                                           embedding programs only)
```

Three rules hold it together:

1. **Verify at the edge, act at home.** The relay only accepts events it can prove came from the
   service (or that you explicitly marked as unverified), and it never acts on them. Everything that
   *does* something happens on your machine, under rules you set there.
2. **The relay can't read your events.** Each event is sealed to your devices' public keys right after
   it's verified. The relay stores and forwards ciphertext. Always on since protocol 2.
3. **Webhook content is data, never instructions.** No field of a payload is ever interpolated into a
   shell, a file path or an agent's instructions. Agents see payloads as quoted, untrusted data, and act
   only within their access profile.

## 2. Concepts

| Concept | What it is |
|---|---|
| **Account** | Yours. Owns hooks, devices and keys. One Durable Object holds its event log. |
| **Device** | A machine running the CLI (or a program embedding `hooks-client`). Holds a private signing key and a sealing key, kept in the OS keychain. Approved once; revocable. |
| **Hook** | A public URL `https://<relay>/h/<hook_id>` plus how to verify what arrives at it (a provider preset and its signing secret). One per service is the norm. |
| **Event** | One verified delivery: id, hook, received time, provider event type, and the sealed body and headers. |
| **Automation** | Lives on your machine: *when* (hook + event type + filter), *then* (one or more actions), *as* (an access profile, for agent actions). |
| **Access profile** | What an agent working on outside input may use: websites, network, secrets by name, folders, tools, budget. Enforced by the program that runs the agent, not by this repository (§6). |

## 3. The relay (Cloudflare Worker + Durable Objects)

### 3.1 Receiving

`POST /h/<hook_id>` (also `PUT` and `PATCH`; `GET` only for a preset's endpoint check):

1. **Cheap checks first**: a per-address rate limit, checked before the hook lookup; the hook exists,
   is enabled and isn't paused; a per-hook rate limit (Cloudflare Rate Limiting bindings); the body is
   at most 1 MiB by default (configurable per hook up to 1.75 MiB, since bodies are kept in the Durable
   Object's SQLite rows). The account's log has a quota, and each hook a share of it, counted exactly
   in the Durable Object; an account's plan (§4.6) can add a daily cap and per-hook and per-account
   rates, counted there too. Without a plan configured there are none.
2. **Verify** with the hook's preset (§4.2). Failures answer `401` with no detail and are counted, not
   stored.
3. **Replay protection**: a timestamp window where the provider signs one (5 minutes; 60 s for
   Linear), and a seen-id set per hook in the Durable Object, written in the same transaction as the
   event. GitHub, Shopify, Twilio, Meta, Typeform, PagerDuty and Zoom (whose timestamp is
   signed but has no documented window) sign no checked timestamp and retry for hours, so for them the
   marks (the delivery id where there is one, and the body hash) are the only defence; they are kept
   `REPLAY_MARK_DAYS` (180 days by default). Once a mark expires, a captured body is accepted again,
   as a new event with a new id. So the runner also dedupes by a hash of the content, not only by
   event id (§5.3).
4. **Handshakes**: providers that verify an endpoint before use (Slack's `url_verification`, Meta's
   `hub.challenge`, Twitch, Microsoft Graph) are answered by the preset, after verification. Slack's
   and Meta's are built (Meta's is a `GET` carrying the hook's verify token, kept as a keyed hash);
   Twitch's `webhook_callback_verification` and Zoom's `endpoint.url_validation` (answered with the
   HMAC of its token under the hook's secret) are answered after verification too. *Not planned:*
   Microsoft Graph's: its `validationToken` is an unauthenticated echo, and Graph signs no content
   (only a `clientState` secret inside the body), so it has no preset to answer from.
5. **Seal and store**: the body and the headers the preset keeps are sealed to every device on the
   account (§4.4) and appended to the account's log with a monotonic sequence number.
6. **Answer fast**: `200` as soon as the event is durably stored, so providers never time out or
   retry needlessly. A hook can carry a **static response** (`PATCH /v1/hooks/<id>` `response`: a
   2xx status, text, JSON or XML, at most 4 KiB, never HTML) for providers that want a specific
   reply; duplicates and screen drops get it too, so they look the same. Dynamic responses
   produced by an agent are out of scope: they'd be too slow for a provider's timeout. Twilio gets
   TwiML (empty).
7. **Offline notices** (PROTOCOL §4a): a hook whose provider takes its reply in the response
   (Twilio, Slack slash commands) can carry a fixed notice the relay sends while no device has been
   connected for a set time, at most once a day per sender (kept only as a keyed hash). Providers
   that answer through an API call (Meta's) can't: there, a notice needs something that is on.

### 3.2 Streaming

`GET /v1/stream` with `Accept: text/event-stream`, authenticated as a device (§4.3):

- Events are sent as `id: <seq>` + `event: hook` + `data: <sealed envelope>`.
- **Resume**: the client sends `Last-Event-ID`; the stream replays everything after it that this device
  hasn't acknowledged, then goes live.
- **Heartbeats**: a comment line every 15 s (with `Cache-Control: no-cache` and
  `X-Accel-Buffering: no`) keeps proxies from buffering or closing the stream; 70 s without a byte
  counts as dead and the CLI reconnects with jitter (1 s to 30 s).
- **Gaps are said, not hidden**: resuming from an id that retention already dropped gets an explicit
  `gap {from, to}` event, so the CLI can tell you what was lost.
- **Acknowledgement**: `POST /v1/ack {through: <seq>}` after the CLI has *recorded* the event locally
  (not after running it), so delivery is at-least-once and the CLI dedupes by event id.
- **Retention**: unacknowledged events are kept 7 days (configurable down to 1 hour) in the Durable
  Object's SQLite log, pruned by an alarm, then dropped and counted; acknowledged events are deleted
  at once. Bodies stay under the 2 MB row limit (§3.1). Hooks, keys and devices live in D1.
  *Not planned: larger bodies in R2 with a pointer in the log.* R2 writes can't join the Durable
  Object's transaction, so an append, an ack or retention could leave an orphaned object or a
  pointer to nothing; each envelope is per device, so one large body would be several R2 objects
  to delete on every ack; and the frame between the object and the Worker, and the CLI's 16 MiB
  message limit, would need a second, chunked path. The providers 00hooks serves send far less than
  1.75 MiB (and the big ones cap their own payloads), so the cost buys little.
- **Deploys drop connections** (Cloudflare closes every socket on a code update), so resume isn't an
  edge case: it's exercised on every release.
- **Several devices**: each has its own cursor, and every hook is delivered to all of the account's
  devices, unless the hook names **one device** (`deliverTo`, *the Mac in the office*): then only
  that device gets an envelope, the others' streams pass the event by, and an automation doesn't run
  twice. A revoked target sends the hook back to every device rather than to nobody.

**How it stays cheap while always on.** The account's Durable Object talks to each device over a
*hibernatable WebSocket*, so it costs nothing while nothing happens; the Worker in front bridges that
socket to SSE for the CLI. *Not planned: clients taking the WebSocket directly.* It was the
fallback in case the bridge proved costly (§10), and nobody has measured that it does; doing it
anyway would mean a second client protocol (framing, resume, backpressure, close codes) to keep
in step with SSE, for a saving nobody has shown. The bridge:
- sends `retry: 5000`, a first `ready` event and a final `closed {code}`;
- handles bursts: per-hook coalescing is *not* done (every event matters here); past a 256 KB
  backlog the stream sends one `resync {after}` instead of queueing, and the CLI catches up from
  its cursor (there is no rate shaping);
- closes with clear codes: `4401` revoked, `4408` too slow, `4409` replaced by a newer connection of
  the same device.

### 3.3 Management API

`/v1/hooks` (create, list, update, rotate secret, pause, delete, the screen's rules),
`/v1/devices` (list, revoke, set a sealing key), `/v1/enrolments` (add a device), `/v1/keys` (API
keys: create, list, revoke), `/v1/events` (recent deliveries: time, hook, size, verified or not,
delivered to which devices; never the content), `/v1/audit`, `/v1/held` (events the screen holds),
and the phone routes (PROTOCOL §10). PROTOCOL has the full list. Renaming a device is
`PATCH /v1/devices/<id>`. `POST /v1/test/<hook_id>` sends a **signed sample event**: the relay
signs a sample with the hook's own secret, the way its preset's provider would, and sends it
through the hook's own path (limits, verification, the screen, dedupe, sealing), with the routing
event type `00hooks.test`, so runners show it and run only automations that ask for that kind. It
needs a device or the `hooks:secrets` scope, and can't sign for a strict or Ed25519 hook.

## 4. Security model

### 4.1 Threats we design against

- Someone who learns a hook URL sends fake events → **signature verification per provider**; a bare
  URL is never enough unless you choose the weak mode knowingly.
- An attacker replays a genuine event → **timestamp window + seen-id set**, and the CLI dedupes by
  event id, and by content hash for providers that sign no timestamp (§5.3).
- The relay's storage or operator is compromised → **payloads are sealed to device keys**; secrets are
  hashed or encrypted at rest; there's nothing useful in logs.
- A stolen API key → **scoped, expiring keys**; every use is logged. It can't become a reader of
  events: streaming and acknowledging need a *device* key that never leaves the machine. It can't
  obtain hook secrets either: creating a hook with a relay-generated secret, or rotating one, needs
  a device signature or the `hooks:secrets` scope, never just `hooks:write`. And automations pin to
  hook ids, so a hook the key creates can't take an existing automation's events.
- A malicious payload tries to make an agent misbehave → **access profiles enforced by the program
  that runs the agent** (egress allowlist, secret handles, approvals; §6), payloads framed as data,
  no shell interpolation (§5).
- Floods and loops → rate limits at the relay (and a plan's exact limits, with pauses for a hook that
  floods, §4.6) and per automation, a circuit breaker, loop detection.

### 4.2 Verifying what arrives (provider presets)

| Preset | How it's checked | Strength |
|---|---|---|
| Standard Webhooks (Svix, Resend, Clerk, many others) | `webhook-id`, `webhook-timestamp`, HMAC-SHA256 or Ed25519 `webhook-signature` | strong |
| Standard Webhooks with Ed25519 (`v1a`) | the relay holds only the sender's *public* key | strongest: a leak of the relay's stored secrets can't forge events (a compromised relay still can, unless the hook is strict) |
| Stripe | `Stripe-Signature` (`t=…,v1=…`) within 5 minutes | strong |
| Slack | `v0:<ts>:<body>` HMAC, timestamp within 5 minutes | strong |
| Linear | `Linear-Signature` HMAC, `webhookTimestamp` within 60 s | strong |
| GitHub | `X-Hub-Signature-256` HMAC over the raw body | medium: no timestamp, so `X-GitHub-Delivery` dedupe is the replay defence |
| Shopify | `X-Shopify-Hmac-SHA256` (base64) | medium: dedupe on `X-Shopify-Webhook-Id` |
| Twilio | HMAC-SHA1 over the exact public URL and sorted parameters | medium: verified against the URL the provider was given, byte for byte |
| Meta (WhatsApp Cloud API, Messenger, Instagram) | `X-Hub-Signature-256` HMAC over the raw body under the app secret; the GET verify-token handshake answered at the edge | medium: no timestamp, so the body hash is the replay defence |
| Calendly | `Calendly-Webhook-Signature` (`t=…,v1=…`) within 3 minutes | strong |
| Paddle Billing | `Paddle-Signature` (`ts=…;h1=…`) within 5 s, as Paddle's own libraries check | strong |
| Twitch EventSub | HMAC over the message id, timestamp and body, within 10 minutes; the `webhook_callback_verification` challenge answered | strong |
| Typeform | `Typeform-Signature` base64 HMAC of the body | medium: dedupe on the signed `event_id` and the body hash |
| PagerDuty (v3) | `X-PagerDuty-Signature` HMAC of the body | medium: dedupe on the signed `event.id` and the body hash |
| Zoom | `x-zm-signature` over `v0:ts:body`; `endpoint.url_validation` answered with the token's HMAC | medium: Zoom documents no window, so the body hash is the replay defence; can't be strict |
| *(not built)* HubSpot v3 and more | each provider's documented HMAC, added as table entries | per provider. HubSpot signs the request URI with its own decoding rules, worth a change of its own |
| *Not planned:* Mailgun, Microsoft Graph | — | weak: Mailgun's signature covers a timestamp and token, not the body; Graph signs no content at all. Lemon Squeezy needs no preset: it is the generic HMAC |
| Generic HMAC | you choose the header, algorithm and encoding | strong if the sender supports it |
| Secret header or bearer token | constant-time compare | medium: no body integrity |
| *Not planned:* secret in the URL path | the URL itself is the secret | weak: URLs end up in logs, proxies, browser history and providers' dashboards, and it covers no content. The `token` preset already does better (a header, compared in constant time) |
| Unverified | anything that arrives | marked `unverified`; automations refuse it unless you allow it per automation |

Verifiers are a declarative table (provider → headers, signed content, algorithm, encoding, timestamp
rule), always over the **raw bytes** before any parsing, with constant-time comparison
(`crypto.subtle.verify`) and several accepted signatures so secrets can rotate. Each event carries a
`verified` flag that the runner shows and checks. An optional **IP allowlist** per hook (the
screen's address lists, §6a) is defence in depth only, never the sole check. The suggested **test
URL** per hook is answered by the signed test event instead (§3.3): it travels the hook's own
path, so it proves the real one works, and runners don't act on it; a second public URL per hook
would be a second door to guard. Signing secrets the relay needs in order to verify are **encrypted at rest** with a
Worker secret (they can't be hashed, since the relay must recompute signatures), shown only once
when generated, and rotatable with an overlap window so the old and new secrets both work for a set
time.

### 4.3 Who may do what

- **Device keys**: `00hooks login` creates an Ed25519 signing key and an X25519 sealing key in the OS
  keychain (macOS Keychain, Secret Service on Linux, a 0600 file as the fallback). The first device
  creates the account (with the relay's signup token unless signups are open). Another device needs
  a one-time enrolment code made by an approved device (`00hooks devices add`), redeemed by
  `00hooks login` on the new one. There is no dashboard. Every request is signed with the device
  key (PROTOCOL §1: the device, host, method, path, time, a single-use nonce and the body's hash), so
  no secret, long-lived or short, crosses the network.
- **API keys** (`hk_…`) are for management and CI only: shown once, stored as a salted hash keyed
  with `HASH_PEPPER`, scoped (`hooks:read`, `hooks:write`, `hooks:secrets`, `events:read`,
  `devices:write`, and `audit:read`), with an expiry. An API key can never open the stream, enrol a
  device, set a sealing key or make more keys (PROTOCOL §9). Only `hooks:secrets` lets one obtain a
  hook secret (create a hook with a relay-generated secret, or rotate one).
- **Audit**: hook created or deleted, secret rotated, device added or revoked, key created or used,
  verification failures (counted per hour). Names and ids only.

### 4.4 Sealing (always on; PROTOCOL §5)

Each device publishes its X25519 public key when it pairs. After verification the relay (the
account's Durable Object, so the sequence number is known) seals the body and kept headers with HPKE (RFC 9180, DHKEM-X25519, HKDF-SHA256, ChaCha20-Poly1305) once per
device, with the hook id, sequence number and event id as associated data (so stored
ciphertexts can't be spliced or reordered) and the device key's id in the envelope (so keys can
rotate), then forgets the plaintext. The relay also signs each envelope with its own Ed25519 key, so
the CLI knows it came from your relay. The relay still sees metadata: when, which hook, size, the provider's event
type when it's in a header, and whether it verified. Trade-off: the payload is briefly in the Worker's
memory during verification; that is unavoidable for signature checks, and is why §4.2's secrets are
encrypted and the code is open for inspection. For people who can't accept that, a hook can use
**verify on your machine** *(strict mode)*: the edge only checks the cheap things (size, rate, that
the signature header is there and well formed, a header timestamp's window), seals the raw body and
signature headers together, and the CLI verifies the provider's signature itself with the secret kept
in your keychain. The relay never holds the secret, at the cost of accepting some junk at the edge.
The device decides on its own terms (PROTOCOL §3): it verifies every event of a hook it keeps a
strict secret for, whatever the relay's metadata says, with the settings it was given when the secret
was kept, refuses a preset relabelled by the relay, and keeps its own replay marks for 8 days, so a
breached relay can't forge, downgrade or replay a strict hook's events. It can still withhold or
delay them, and it sees each payload in memory while it seals it. Routing at the relay only ever uses plaintext metadata (hook
id, provider, event type), and that metadata is visible to the operator.

**The local trust boundary.** Sealing ends at the device: once opened, an event is plaintext on your
machine. The client's inbox holds opened events until they are handed over (`inbox.jsonl` in the
state directory), and the runner keeps the newest 1,000 events (`events.jsonl`), the catalogue's
samples and the run details under `<HOOKS_HOME>/runner/`, every file 0600 in a 0700 folder. So the
protection at rest on your machine is the operating system's: your user account, disk encryption,
backups you choose. Strict hooks' secrets and the sealing keys sit in the keychain (or a 0600 file).
*Not planned: `--seal-at-rest`* (the runner keeping its stored events sealed to the device's own
key). It would cover only `events.jsonl`, while the catalogue's samples, the run records (agent
replies included), the inbox and the quarantine stay readable; on Linux without a Secret Service
the key store is a 0600 file in the same `HOOKS_HOME`, so a copy of the folder carries its key; and
full-disk encryption already answers a lost or stolen machine. It would cost a key-store access per
read and every `grep` through history for a protection that holds only in part.

### 4.5 Self-hosting

With your own Cloudflare account: a Worker, two Durable Object classes (`AccountObject` for the
event log, `PhoneObject` for phone links), a D1 database, Rate Limiting bindings, a daily cron
trigger, and the secrets `SECRETS_KEY` (encrypting hook secrets), `HASH_PEPPER` (keyed hashes),
`RELAY_SIGNING_KEY` (signing sealed envelopes) and `SIGNUP_TOKEN` (signups are refused without it
unless `OPEN_SIGNUP=1`). No other services. Your account's ids go in a gitignored copy of
`wrangler.jsonc`, deployed with `wrangler deploy -c wrangler.deploy.jsonc` after applying the D1
migrations; `relay/README.md` ("Self-hosting") has the steps. The CLI takes the relay URL at login
(`00hooks login --relay`).

**The installer.** `pnpm --filter ./relay setup` does all of that with the person's own `wrangler
login`: it creates the D1 database, writes the gitignored deploy config (rate-limit namespace ids
from a random base; on upgrades, new bindings are merged in and the ids kept), applies the
migrations, generates `SECRETS_KEY`, `HASH_PEPPER`, `RELAY_SIGNING_KEY` and `SIGNUP_TOKEN` locally
(a CSPRNG) and pipes each to `wrangler secret put` on stdin before the first deploy (never as an
argument, a file or a log line; only the signup token is shown, once, because pairing needs it),
asks for the optional APNs and FCM keys (file paths, validated, hidden input, a terminal only),
deploys, and checks `/v1/info`. Re-running continues where it stopped and never replaces a secret
without a typed confirmation; `--dry-run` shows every step and runs nothing; `--check-only` checks
a deployed relay. There is no "Deploy to Cloudflare" button: it couldn't give each account its own
rate-limit ids, would build `relay/` without the workspace's lockfile, and would take the secrets
through a web form seeded with `.dev.vars.example`'s placeholders, which the relay would accept.

### 4.6 Plans and the hosted relay

Every account works under a **plan**: limits from the operator's configuration (`PLANS`; PROTOCOL
§2a): hooks and devices at once, deliveries a day, a token bucket per hook and per account,
retention, body size, the backlog, hook creations a day. A relay without `PLANS` has one plan,
`default`, equal to the behaviour before plans, so **self-hosting is unchanged**. The limits are
counted exactly in the account's Durable Object (rows in its SQLite, no timers, so it still
hibernates); the hook and device caps in the D1 insert itself. A refusal says which limit
(`scope`) and exactly when to retry; a hook may take deliveries past the daily cap and drop them
(`accept_and_drop`, reported to the devices as a gap) instead of refusing; a hook refused hundreds
of times in minutes is paused, answered from D1 without waking the Durable Object, until the pause
ends or a device lifts it. Devices hear of limits on the stream (`limit`) and read their plan and
usage with `GET /v1/account`.

**The hosted relay** is this code with a `PLANS` configuration whose accounts come with the
**Overblast Plan**: Overblast signs an **entitlement** (PROTOCOL §2b) for a workspace, which creates
the workspace's account (instead of a signup token) or refreshes its plan. The relay pins
Overblast's public keys, links one account to one workspace, and, when an entitlement isn't renewed,
falls back after a grace period to a suspended plan that takes nothing new but keeps the backlog
readable. A relay without the keys takes no entitlements. The suggested hosted limits are in
`docs/plans.example.json`, marked as suggestions.

## 5. Running automations on your machine

### 5.0 The event catalogue

The first time a new kind of event arrives, its structure is saved, so filters, field rules (§6a) and
automations can be built later by picking real fields instead of typing paths.

- **A kind** is the hook (or messaging channel) plus the provider's event type (`pull_request`,
  `checkout.session.completed`), or, when there is none, the payload's shape hash (its field paths and
  types, not values).
- **What's kept for each kind**:
  - its **field tree**: every path with its type (`repository.full_name: string`,
    `pull_request.additions: number`, `labels[]: object`) and how often it's present;
  - **one sample event**, the first one, so the builder can show real values next to each field;
  - for short, repeating fields (status, action, currency), the **values seen**, up to 20, so a filter
    can offer "action is one of opened / closed / reopened" as a menu;
  - first seen, last seen and a count.
- **Kept on your machine only**, in the runner's store, never at the relay. Samples and
  seen values are content, so each kind has *Clear sample*, the whole catalogue can be cleared, and a
  hook can be set to keep structure only (no sample, no values) for sensitive sources.
- **Noticed, not noisy**: a new kind is noted once, and so is a known kind gaining or losing fields
  (*shape changed on 14 Oct: added `pull_request.auto_merge`*); the `new_kind` and `shape_changed`
  triggers (§5.1) can turn either into a notification. A program with a user interface can offer
  *Add an automation* and *Add a screen rule* right there.
- **Bounded**: a hook without event types has a kind per payload shape, which a sender can vary at
  will, so a hook keeps at most 200 kinds (more aren't recorded, and the run says so), and at most 10
  new kinds an hour count as *new* (fire `new_kind` triggers); the rest are recorded quietly.
- **Used everywhere a field is chosen**: filters, the screen's field rules, and templates
  (`{{payload.pull_request.title}}`). `00hooks automations check` flags a filter on a field a kind
  no longer has, instead of it silently never matching.

### 5.1 Matching

An automation's **trigger is one or more kinds** from the catalogue (§5.0), plus optional filters.
The CLI reads them from `automations.yaml`; a program with a user interface can offer them as menus:
- **kinds**: *When GitHub sends “pull_request”*, picked from a menu of the kinds actually seen, with
  their counts and last-seen times. Several kinds can share one automation (*“issues” or
  “issue_comment”*), and *any kind from this hook* is a choice too. Choosing a kind that hasn't been
  seen yet is possible by typing it, for services you're setting up now; it's marked *not seen yet*.
- **filters on that kind's fields**, chosen from its field tree with the sample's values as hints
  (`action is opened`, `pull_request.additions > 500`, `repository.full_name is one of [...]`), in a
  small expression language that can't run code;
- verified only (the default).

The catalogue also gives two triggers of its own, useful with a *notify me* action:
- **a new kind arrived** on a hook or channel (*tell me when Stripe starts sending something new*);
- **a kind changed shape** (*tell me when GitHub's pull_request payload gains or loses fields*), so an
  automation that depends on a field hears about it before it breaks.

When a kind's shape changes, the automations and screen rules that use a field it lost are listed
with a warning, rather than silently never matching again.

### 5.2 Actions

Plain actions, no AI:
- **Notify me**: a macOS or Linux notification, with a template like
  `New order {{payload.id}} for {{payload.amount | money}}`.
- **Call a URL**: method, URL, headers (secrets by name, injected at send time) and a JSON body template.
  The URL's host must be in the automation's allowlist.
- **Run a command**: an allowed executable and an argument list. Template values are passed as
  separate arguments or environment variables, **never through a shell**; the executable must be on
  the automation's allowlist; it runs without your shell's environment, in a private folder of its
  own (removed afterwards), with a time limit, and everything it started is killed when it exits.
  An argument that begins with an event value can't begin with `-` (it would be an option), unless
  the action puts `options_end: "--"` before such arguments or says `raw: true`.
- **Write a file**: append a line or write a JSON file in a chosen folder (templated name, sanitised).

AI actions, only in a program that embeds the runner and runs agents:
- **Ask an agent**: choose an agent or "a new agent for each event", write its instructions, choose its
  **access profile** (§6). The event arrives as a quoted block marked as untrusted data, with the hook
  and the verified/unverified flag. The agent's reply can feed a following action (for example *notify
  me with the agent's summary*).
  - *Built in the runner for hosts*: a host that runs agents gives the runner its
    automations as data (`Runner::open_with`, `set_automations`) and runs `ActionKind::Ask` through
    the `ask::Asker` trait. The event reaches the agent through `ask::quote_event`: a header saying
    it is untrusted outside content, the hook, the kind and the verified flag, then the payload in a
    fence its content can't close. The reply is `{{agent.reply}}` (with `agent.name`, `agent.id`)
    for the actions after it, and the run record keeps it (`output`). The CLI has no agents, so
    there the action fails and says why; `automations.yaml` doesn't write it.

### 5.3 Reliability

- Every event gets a **run record**: matched automations, each action's result, timings, errors.
- **Exactly once into the run log**: the runner takes events from the stream with a confirmed
  handover (`SubscribeOptions { confirm: true }`) and confirms each one only after its run's start
  record is fsynced. A crash before that hands the event over again on restart; a crash after it
  finds the event already handled and closes the run as interrupted (replay runs it by hand).
- **Dedupe**: by event id, against the run records, and by a hash of the content: a provider that
  signs no timestamp can be replayed at the relay once its body-hash mark expires (§3.1), and the
  replay arrives as a new event with a new id. The runner keeps SHA-256 of the hook id and body for
  verified events of presets that sign no checked timestamp (read from the preset table), fsynced
  before the run's start record, so a crash between them neither loses the event (its own id
  passes) nor runs a copy under another id; at most 100,000 marks for 400 days, hashes only. A
  replay is recorded as a dropped run naming the event it repeats; `00hooks replay` still runs
  anything on purpose.
- **Test events** (`00hooks test`, kind `00hooks.test`) are recorded and shown, run only the
  automations that list that kind, and stay out of the catalogue.
- **Retries** with backoff for failed actions that are safe to retry (notify, call a URL with an
  idempotency key); never for commands unless the automation says they're idempotent.
- **Replay** any recorded event from the run history.
- **Rate limits** per automation (default 30 runs an hour) and a **circuit breaker** that pauses an
  automation after repeated failures and tells you.
- **Loop prevention**: actions that call out carry an `00hooks-origin` header and a hop count; an event
  arriving with our own origin header, **or** with a hop count over the limit (from any origin), is
  dropped.
- **Offline**: events wait at the relay (7 days by default) and run when the machine is back, oldest
  first, with a summary notification if many were waiting.

### 5.4 The CLI on its own

```
00hooks login                         create an account, or join one with an enrolment code
00hooks hooks create --preset github  prints the URL and, once, the signing secret
00hooks listen                        stream events to the terminal (or --json)
00hooks run                           run automations from ~/.config/00hooks/automations.yaml
00hooks replay <event>                run an event again
00hooks doctor                        check keys, clock skew, connectivity, the relay version
00hooks service install               run `00hooks run` at login (launchd / systemd --user)
```

`00hooks test <hook>` sends a signed sample event (§3.3), `00hooks devices rename` renames a
device, `00hooks hooks deliver-to` and `00hooks hooks response` set a hook's one device and static
response, and `00hooks relay status` checks a relay (`/v1/info`).

Written in Rust: one binary, for macOS and Linux. Its core (`hooks-client`: pair, stream, unseal,
ack) is a library crate, as are the runner and the screen, so another program can embed them
without a separate process.

## 6. Programs that run agents

The `00hooks` CLI runs plain actions only. A program that embeds the runner and runs AI agents (a
*host*, §5.2) owns the agent side. This section is the model such a host should follow; none of it
is in this repository.

### 6.1 Who answers

**Nothing triggered from outside runs with the host's full reach.** Webhook events, incoming
messages and anything else that brings outside content are handled by a **responder**: an agent in
its own sandbox working under an access profile. Scheduled work follows the same rule when it acts
on outside content (a feed, an inbox). The host's main agent can *read* what responders did and be
asked by them, but outside content never gets its reach into your machine.

### 6.2 Access profiles

A profile is a named, reusable set of limits, enforced by the host, not by instructions in a prompt:

| Limit | What it controls | Enforced by |
|---|---|---|
| Websites | domains the agent may reach (`api.github.com`, `*.stripe.com`); everything else is blocked | an egress proxy every sandbox must use |
| Network | none / allowed websites only / open internet; local network on or off | sandbox network rules + the proxy |
| Secrets | which secrets, by name, and for which domains; the proxy adds them to requests, so the value never enters the sandbox | the egress proxy |
| Folders | which folders it may work in (read-only or read-write) | sandbox mounts |
| Tools | can it run commands, write files, send messages, publish, spend money | approvals |
| Approvals | what it may do alone and what always asks you | approvals |
| Budget | tokens a day, runs an hour | the host's budgets |
| Model | which model accounts it uses | the host's settings |

Example profiles: **Read only** (no network but allowed APIs, no writes outside its workspace, asks
before anything outward), **Replier** (can send a reply on the channel it came from, nothing else),
**Builder** (one folder read-write, allowed package registries, no secrets), **Open** (anything,
every outward act reviewed).

## 6a. The screen: a firewall for everything that comes from outside

An optional firewall that decides what happens to each incoming item **before** any automation or
agent sees it. It covers webhooks; a host can run the same screen on other outside content
(incoming messages, fetched feeds). It runs in two places, each doing what it's best at:

| Where | What it does | Why there |
|---|---|---|
| **Edge** (the relay) | cheap, deterministic, private checks: origin, rules, rate, and fingerprints of things you blocked | drops floods and known junk before it's stored or streamed; works with sealing, because it only uses metadata and fingerprints taken during verification |
| **Harness** (the CLI's runner, or a host that embeds `hooks-screen`) | the same rules and similarity memory, plus an optional **AI evaluator** | sees the full content with no third party in between, can use your own models (or a local one), and is the last stop before an agent |

The AI never runs at the edge: content would leave the sealed path, and the relay operator would be in
the loop.

### Verdicts

Every item gets one of three verdicts:

- **Pass**: delivered to automations as usual.
- **Quarantine**: kept aside, not acted on, with a notification ("2 webhooks held for review"). From
  the quarantine list you **Release** it (it runs now) or **Drop** it.
- **Drop**: discarded. At the edge, the provider still gets `200` so it doesn't retry (forged
  signatures keep their `401`); in the harness it's recorded as dropped with the reason.

Each decision you make can be turned into a rule with **Always** ("always pass/quarantine/drop items
like this") and any rule switched **Off**. Learned rules show what they matched on and when, and expire
unless they keep matching (default 90 days).

### What it looks at

1. **Origin**: for webhooks, the IP, network (ASN), country and TLS fingerprint the edge sees, and
   whether the IP is in the provider's published ranges (GitHub and Stripe publish theirs); for
   messages, the sender, channel and whether they're a known person. An unexpected origin for a
   provider is a signal, not a verdict, except where you make it one.
2. **Rules**: allow and block lists (IPs, networks, countries, senders), header and field conditions
   (`payload.sender.login in [...]`, `body size > 200 KB`), time windows, per-hook or per-channel
   rates. Deterministic and explainable: the reason shown is the rule's name.
3. **Similarity to what you blocked**: when you drop or quarantine something, the screen keeps a
   fingerprint, never the content:
   - the **shape**: a hash of the payload's field structure (keys and types, not values);
   - the **text**: a MinHash signature of its normalised text (word 5-grams);
   - the **origin** features above.

   A new item that's close enough to a blocked one (Jaccard ≥ 0.8 by default, adjustable) gets the
   same verdict, with the reason "similar to an item you dropped on 12 October". Fingerprints can be
   synced to the edge *(optional)*, so repeats are dropped before they're even delivered; a MinHash
   signature reveals almost nothing about the text it came from.
4. **Field rules: blocking on content.** Sometimes the value is the point: a sender's address, a
   repository, a product id, a phrase. When you drop or quarantine an item, the item opens with its
   fields listed, and you tick the ones to block on. For each, choose how it matches:

   | Match | Example | Notes |
   |---|---|---|
   | is | `sender.email` is `promo@deals.example` | case-folded and trimmed first |
   | domain is | `sender.email` domain is `deals.example` | for addresses and URLs |
   | contains | `message.text` contains `free crypto` | words, case-insensitive |
   | pattern | `order.note` matches `/bit\.ly\/\w+/` | a regular expression, with a time limit |
   | similar text | `message.text` is like this one | MinHash on that one field, so a long template with a changed name still matches |
   | one of | `repository.full_name` is one of a list you keep | for allow lists too |

   The fields come from the event catalogue (§5.0), so a rule can also be written before anything is
   blocked, by picking a kind and its fields. Field rules keep the values you chose, because that is
   what they match on. Only the ticked
   fields' values are kept, never the rest of the item, and they stay **in the harness** (your
   machine), shown in plain text in the rule so you can see exactly what's blocked. A rule can also
   be pushed to the edge *(optional)*: `is`, `domain is` and `one of` go as keyed hashes (the relay
   compares a hash of the incoming field and never stores the value), while `contains`, `pattern` and
   `similar text` need the relay to see the words, so pushing one of those says so and asks first.
   Rules can combine conditions (`sender.domain is X` **and** `message.text contains Y`) and say
   *pass*, *quarantine* or *drop*, so the same tool builds allow rules ("always pass `repository`
   one of my repos").
5. **The AI evaluator** *(optional)*, only for items the rules and similarity didn't settle, through a
   **Decisions API** (bounded questions with typed answers and probabilities):
   - `verdict`: *choice* of `pass`, `quarantine`, `drop`;
   - `injection`: *yes/no*, whether it tries to instruct an AI;
   - `spam`: *score* from 0 to 4;
   - `matches_purpose`: *yes/no*, whether it fits what this hook or channel is for (from the
     automation's own description).

   The item is the **state**, framed as untrusted data, plus the hook's or channel's purpose. Thresholds
   turn probabilities into verdicts (default: drop when `drop` ≥ 0.9; quarantine when `pass` < 0.7 or
   `injection` ≥ 0.5; otherwise pass). Verdicts are cached by fingerprint, so a repeated item isn't
   evaluated twice.

### Keeping the evaluator itself safe

- It can only **answer typed questions**: it has no tools and no output that becomes an action. The
  worst a manipulated evaluator can do is pass something, and passing never grants anything: the
  item still meets its automation's access profile, approvals and budgets (§6.2).
- **If it fails, times out, or its daily cap is reached**, the screen falls back to a per-source
  default: quarantine whenever anything beyond a notification would act on the item (an agent, a
  command, a call, a file written), pass only when every action is a notification. Someone who can
  exhaust the cap or slow the evaluator gains nothing that way.
- **Providers**: any Decisions endpoint (OpenRouter's, and others as they appear), any chat model through
  a structured-output adapter, or a **local model** for full privacy. Requests to hosted models ask for
  zero data retention and no training on the data where the provider supports it, and a model that
  can't offer that is refused when the source is marked sensitive.
- **Cost** is visible per source (evaluations today, and what they cost on your account), with a daily
  cap after which items fall back to the default verdict.

### Operator extras

A relay can announce extras its operator offers, as data in `/v1/info` (`extras`, set with
`HOSTED_EXTRAS`); clients show what is announced and never hard-code a list. This repository
implements no extras, and a relay that sets nothing announces none.

### Built (phase 5)

- **Edge** (`relay/src/screen.ts`, `held.ts`; PROTOCOL §4b; tests in `relay/test/screen.test.ts`
  under Miniflare). Per-hook rules a device pushes (`PUT /v1/hooks/<id>/screen`): address and CIDR
  lists (`not` makes an allow list; a provider's published ranges go as a list labelled with
  `preset`, the relay fetches none), ASN and country from `request.cf`, header conditions, size; time windows (hours, days and an IANA
  time zone, past midnight allowed, read on the relay's clock at receipt);
  fingerprints (shape hash and MinHash); field rules `is`, `domain is` and `one of` as keyed hashes
  under the account's screen key; `contains`, `pattern` (a safe subset for a backtracking engine)
  and `similar text` only with `consent.words`. Drop answers `200` with an id that names nothing;
  quarantine seals the event with held associated data and keeps it aside until a device releases
  it (`/v1/held`), then it is signed for its new seq with a `held` line and streamed; forged
  signatures keep `401`; decisions keep only the rule's id and hourly counts. The origin the edge saw
  travels sealed, for the devices' own screen. `/v1/info` announces `screen` and the operator's
  `extras` (`HOSTED_EXTRAS`), as data.
- **Harness** (`cli/hooks-screen`): the same rules (time windows judged by the event's relay-signed
  `receivedAt`, not the device clock, with the IANA zones bundled in the harness) plus learned rules (*Always … similar*, *Block on
  fields…*, *Off*, 90-day expiry unless matched), MinHash over word 5-grams with a configurable
  Jaccard threshold (0.8 by default), per-field MinHash for *similar text*, field rules of every kind
  joined by and/or, each saying pass, quarantine or drop; the quarantine list (Release once, Drop,
  Always, fields for the picker; content cleared once decided); the evaluator behind a `Decider`
  trait: an OpenRouter-style Decisions endpoint (`state` plus `noul`, `choice` and `score`
  questions, URL configurable), any chat model through structured output, or a local model on
  loopback; thresholds configurable; verdicts cached by fingerprint; no tools; zero retention and no
  training asked for, and a decider that can't promise it refused for a sensitive source; a daily cap
  and cost per source; it fails closed to the source's fallback (quarantine when anything beyond a
  notification would act, pass when only notifications would). A rule that doesn't compile isn't
  dropped: it is reported, and what it applies to is quarantined until it is fixed. `fixtures/screen.v1.json` holds both halves to the same words, shapes, signatures,
  domains and keyed hashes, and to when time windows hold (daylight saving changes included).
- **Runner and CLI**: the runner screens every live event before any automation (not replays,
  releases, or events released at the relay); a held event's run is `held`, a dropped one's
  `dropped`, and `Runner::release` runs a held one once. `00hooks screen status|on|off|held|release|
  drop [--always]|rules|sync`.
- **Not built**: per-hook or per-channel rates beyond the relay's limits (they belong with the
  relay's plans and limits).
- **Not planned**:
  - *TLS fingerprints.* A Worker sees a client's JA3/JA4 only with Cloudflare's Bot Management, an
    Enterprise add-on, so a self-hosted relay can't count on it; and a webhook sender's TLS stack
    changes whenever the provider updates a library, so a fingerprint rule would break genuine
    deliveries silently.
  - *Edge reputation lists.* The relay fetches nothing by design (it is what keeps it simple and
    its behaviour reviewable), a public list's false positives would drop genuine deliveries before
    anyone sees them, and the signature already refuses forgeries whatever their address. A list
    you trust can already be pushed as an address list rule.
  - *Fingerprint sync across devices.* Field rules keep their values on the device, in plain text,
    by design; syncing them would need a sealed channel between devices that doesn't exist, or would
    put the values on the relay. What can go to the edge already does (`screen sync`), and it
    protects every device.
- Known differences
  between the halves: the edge's `pattern` is JavaScript's syntax over 2,048 characters, the
  harness's is Rust's over 64 KiB; a JSON number written `1.0` reads `1.0` in the harness and `1` at
  the edge; time zones come from the runtime's ICU at the edge and from the bundled IANA database
  in the harness, which can differ for a zone whose rules changed recently until both are updated.

## 7. Phases

| # | Phase | Exit test |
|---|---|---|
| 0 ✓ | relay skeleton (hooks, generic HMAC, DO log, the SSE bridge with resume, gaps and acks), CLI `login`/`hooks`/`listen` | a GitHub test delivery reaches the terminal within a second; killing the CLI, or redeploying the relay, resumes without loss or duplicates; a week of idle connections costs what §10 predicts |
| 1 ✓ | provider presets, replay protection, sealing, device pairing, API keys, audit | a replayed or forged event is refused; the relay's storage holds only ciphertext |
| 2 ✓ | CLI `run` with plain actions, run records, retries, rate limits, service install | a Stripe test event sends a notification and appends a line to a file, at most once |
| 3 ✓ | the runner for hosts: automations as data (`Runner::open_with`, `set_automations`), agent actions through `ask::Asker`, events quoted as untrusted data. The agent side and access profiles are the host's (§6) | a host's agent gets the event only as a quoted block and its reply feeds the next action; the CLI refuses an agent action and says why |
| 4 | email-in hooks: *not planned* (§8) | — |
| 5 ✓ | the screen: rules and similarity at the edge and in the harness, quarantine with Release/Drop/Always, the Decisions-API evaluator, local-model option, operator extras announced as data | a flood of near-identical junk is dropped at the edge after one Drop + Always; a prompt-injection message is quarantined before any agent runs; the evaluator failing quarantines instead of passing |
| 6 ✓ | phone links (PROTOCOL §10): pairing, the socket, a queue per device | the relay routes sealed envelopes between a node and its phone, keeps them while one is offline, and never opens them |

## 8. Open questions

Decided: SSE to the CLI, bridged by the Worker from a hibernatable WebSocket on the Durable Object
(§3.2); sealing always on (§4.4).

Decided: the name is `00hooks`.

Not planned: **email-in hooks** (Cloudflare Email Routing to an Email Worker, so "when an email
arrives at invoices@…" becomes a trigger). Its exit test was "arrives as a *verified* event", and
the relay can't promise that: Email Routing only requires an incoming message to pass SPF *or*
DKIM for *some* domain, and rejects on DMARC only when the sender's domain publishes a policy that
says so. Neither binds the `From:` address a rule would trust, and an Email Worker gets no
structured authentication result, only headers a sender can also write. Every email event would
be `unverified` in all but name. It also needs a domain on Cloudflare with Email Routing, and MIME
parsing at the edge. A provider's inbound-email webhook, verified by its preset, is the better
route when it signs its deliveries.

## 9. Design rationale

| Choice | Why |
|---|---|
| The event itself is the payload, sealed to the device | no second fetch, and no content at rest in plain text |
| A per-account ordered log with sequence numbers, `Last-Event-ID` resume and per-device acks | catching up by wall-clock time brings duplicates and depends on clocks |
| At-least-once delivery, deduped by event id in the CLI's run records | at-most-once delivery or dedupe in memory loses events on a crash |
| Timestamped signatures where the provider offers them; a seen-id set in the Durable Object (strongly consistent), written in the same transaction as the event | marks in an eventually consistent store, or written before the event, let replays through or lose events on a crash |
| A body-size limit (1 MiB by default, per hook) | an unbounded body is a cheap way to exhaust storage |
| Revoking a device closes its socket at once (the Durable Object holds both) | a revoked device shouldn't keep reading until a poll notices |
| Commands get an argument list, never a shell; payloads go to stdin or a file | text from strangers must never be parsed by a shell |
| Cloudflare's Rate Limiting bindings at the edge, plus exact quotas in the Durable Object | the bindings are cheap but approximate; quotas need exact counts |
| API-key hashes keyed with a pepper, though the keys have 256 bits | defence in depth: without the pepper, a stolen table matches nothing |

## 10. Cloudflare limits and costs

- **Workers**: no wall-clock limit while the client stays connected, and on the Standard plan wall
  time isn't billed, only CPU time (30 s default, up to 5 minutes). Bodies up to 100 MB on Free and
  Pro. That's why the Worker, not the Durable Object, holds the SSE response.
- **Durable Objects**: one per account; single-threaded, so events are ordered; SQLite up to 10 GB and
  2 MB per row; roughly 1,000 requests a second each. Duration is billed while the object is awake:
  an SSE stream held *by the object* would keep it awake, about $4 per always-on user per month,
  while a hibernating WebSocket costs almost nothing idle (incoming messages billed at 20:1, outgoing
  free) and holds up to 32,768 sockets.
- **The bridge** (Worker holds SSE, Durable Object holds a hibernating WebSocket to it) is built.
  Its cost is inferred from the documentation, so measure it on your deployment with a week of idle
  connections (`relay/docs/IDLE-COST.md`). The fallback, if it costs too much, would be a direct
  WebSocket from the CLI, which needs no bridge; it is not planned until a measurement says so (§3.2).
- **Rate Limiting binding**: 10 or 60 s periods, counted per location and eventually consistent, so
  it's for cheap shedding at the edge; exact quotas are counted in the Durable Object.
- **Queues** (128 KB messages, up to 14 days) are not the event log; at most they carry side work.

Sources: Cloudflare's Workers, Durable Objects (limits, pricing, lifecycle, WebSockets) and Rate
Limiting documentation; the WHATWG SSE specification; RFC 9180 (HPKE); the Standard Webhooks
specification; GitHub, Stripe, Slack, Shopify, Twilio and Linear webhook documentation; and prior art
in smee.io, Hookdeck, ngrok's verify-webhook, Svix and n8n.
