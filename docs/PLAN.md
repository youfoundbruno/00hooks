# 00hooks — the plan

**00hooks** brings events from the internet to your own computer, in real time and safely. Any service
that can send a webhook (GitHub, Stripe, Shopify, Slack, a form builder, your own app) points at a
hook URL. A small relay on Cloudflare checks that the event is genuine, seals it so only your devices
can read it, and streams it to the `00hooks` CLI on your Mac or Linux machine. There, it triggers an
automation: a plain action (notify me, call this URL, run this allowed command) or an AI agent with
instructions and a tightly limited set of permissions.

It's a standalone open-source project (Apache-2.0). 00next bundles it as its **Automations** feature,
and anyone can use the CLI on its own or run their own relay.

Status: phases 0 and 1 are built (the relay, the CLI's `login`/`devices`/`hooks`/`keys`/`audit`/
`listen`, presets, sealing, API keys and the audit); the rest is planned. Sections marked
*(suggestion)* go beyond the original brief and are open for a decision.

---

## 1. The shape

```
 GitHub ─┐                    Cloudflare (yours or a hosted one)
 Stripe ─┤   POST /h/<hook>   ┌────────────────────────────────────────────────┐
 Shopify ┼──────────────────▶ │ Worker: limits, verify the signature, dedupe   │
 Forms  ─┤   (any webhook)    │   │                                            │
 Email  ─┘   (suggestion)     │   ▼                                            │
                              │ Account Durable Object                         │
                              │   ordered log (sealed payloads), cursors, acks │
                              └───────────────┬────────────────────────────────┘
                                              │ SSE stream, resumable
                                              ▼
                     00hooks CLI (or the 00next node, which embeds it)
                     unseal ▸ match automations ▸ run actions ▸ record the run
                         │                 │                    │
                   notify me      call a URL / allowed     an agent with an
                   (no LLM)       command (no LLM)         access profile (LLM)
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
| **Device** | A machine running the CLI (or 00next). Holds a private signing key and a sealing key, kept in the OS keychain. Approved once; revocable. |
| **Hook** | A public URL `https://<relay>/h/<hook_id>` plus how to verify what arrives at it (a provider preset and its signing secret). One per service is the norm. |
| **Event** | One verified delivery: id, hook, received time, provider event type, and the sealed body and headers. |
| **Automation** | Lives on your machine: *when* (hook + event type + filter), *then* (one or more actions), *as* (an access profile, for agent actions). |
| **Access profile** | What an agent working on outside input may use: websites, network, secrets by name, folders, tools, budget. Shared by automations, incoming messages and routines (§6). |

## 3. The relay (Cloudflare Worker + Durable Objects)

### 3.1 Receiving

`POST /h/<hook_id>` (any method the hook allows, default POST):

1. **Cheap checks first**: the hook exists and is enabled; the body is at most 1 MB (configurable per
   hook up to the platform limit); a per-hook and per-account rate limit (Cloudflare Rate Limiting
   binding).
2. **Verify** with the hook's preset (§4.2). Failures answer `401` with no detail and are counted, not
   stored.
3. **Replay protection**: a timestamp window where the provider signs one (5 minutes; 60 s for
   Linear), and a seen-id set per hook in the Durable Object, written in the same transaction as the
   event and kept 7 days: GitHub, Shopify and Twilio sign no timestamp and retry for hours, so for
   them the id is the only defence.
4. **Handshakes**: providers that verify an endpoint before use (Slack's `url_verification`, Meta's
   `hub.challenge`, Twitch, Microsoft Graph) are answered by the preset, after verification.
5. **Seal and store**: the body and the headers you chose to keep are sealed to every device allowed on
   this hook (§4.4) and appended to the account's log with a monotonic sequence number.
6. **Answer fast**: `200` (or the hook's configured static response) as soon as the event is durably
   stored, so providers never time out or retry needlessly. Dynamic responses produced by an agent are
   out of scope: they'd be too slow for a provider's timeout. *(Static responses cover Slack slash
   commands that only need an acknowledgement and Twilio's empty TwiML.)*

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
  at once. Bodies over 2 MB go to R2 with a pointer in the log. Hooks, keys and devices live in D1.
- **Deploys drop connections** (Cloudflare closes every socket on a code update), so resume isn't an
  edge case: it's exercised on every release.
- **Several devices**: each has its own cursor. A hook can be delivered to all devices or to a chosen
  one (*the Mac in the office*), so an automation doesn't run twice.

**How it stays cheap while always on.** The account's Durable Object talks to each device over a
*hibernatable WebSocket*, so it costs nothing while nothing happens; the Worker in front bridges that
socket to SSE for the CLI (a pattern proven in an earlier watch CLI). Clients that prefer it
can take the WebSocket directly. The bridge:
- sends `retry: 5000`, a first `ready` event and a final `closed {code}`;
- shapes bursts: per-hook coalescing is *not* done (every event matters here), but a token bucket
  (50/s, burst 100) protects slow clients, and past a 256 KB backlog the stream sends one
  `resync {after}` instead of queueing, and the CLI catches up from its cursor;
- closes with clear codes: `4401` revoked, `4408` too slow, `4409` replaced by a newer connection of
  the same device.

### 3.3 Management API

`/v1/hooks` (create, list, update, rotate secret, pause, delete), `/v1/devices` (list, rename,
revoke), `/v1/keys` (API keys: create, list, revoke), `/v1/events` (recent deliveries: time, hook,
size, verified or not, delivered to which devices; never the content), `/v1/test/<hook_id>` (send a
signed sample event).

## 4. Security model

### 4.1 Threats we design against

- Someone who learns a hook URL sends fake events → **signature verification per provider**; a bare
  URL is never enough unless you choose the weak mode knowingly.
- An attacker replays a genuine event → **timestamp window + seen-id set**, and the CLI dedupes too.
- The relay's storage or operator is compromised → **payloads are sealed to device keys**; secrets are
  hashed or encrypted at rest; there's nothing useful in logs.
- A stolen API key → **scoped, expiring keys**; streaming needs a *device* key that never leaves the
  machine; every use is logged with the device.
- A malicious payload tries to make an agent misbehave → **access profiles enforced by 00next's node**
  (egress allowlist, secret handles, approvals), payloads framed as data, no shell interpolation (§5).
- Floods and loops → rate limits at the relay and per automation, a circuit breaker, loop detection.

### 4.2 Verifying what arrives (provider presets)

| Preset | How it's checked | Strength |
|---|---|---|
| Standard Webhooks (Svix, Resend, Clerk, many others) | `webhook-id`, `webhook-timestamp`, HMAC-SHA256 or Ed25519 `webhook-signature` | strong |
| Standard Webhooks with Ed25519 (`v1a`) | the relay holds only the sender's *public* key | strongest: a relay breach can't forge events |
| Stripe | `Stripe-Signature` (`t=…,v1=…`) within 5 minutes | strong |
| Slack | `v0:<ts>:<body>` HMAC, timestamp within 5 minutes | strong |
| Linear | `Linear-Signature` HMAC, `webhookTimestamp` within 60 s | strong |
| GitHub | `X-Hub-Signature-256` HMAC over the raw body | medium: no timestamp, so `X-GitHub-Delivery` dedupe is the replay defence |
| Shopify | `X-Shopify-Hmac-SHA256` (base64) | medium: dedupe on `X-Shopify-Webhook-Id` |
| Twilio | HMAC-SHA1 over the exact public URL and sorted parameters | medium: verified against the URL the provider was given, byte for byte |
| Meta, Calendly, Typeform and more | each provider's documented HMAC, added as table entries | per provider |
| Generic HMAC | you choose the header, algorithm and encoding | strong if the sender supports it |
| Secret header or bearer token | constant-time compare | medium: no body integrity |
| Secret in the URL path | the URL itself is the secret | weak: labelled as such |
| Unverified | anything that arrives | marked `unverified`; automations refuse it unless you allow it per automation |

Verifiers are a declarative table (provider → headers, signed content, algorithm, encoding, timestamp
rule), always over the **raw bytes** before any parsing, with constant-time comparison
(`crypto.subtle.verify`) and several accepted signatures so secrets can rotate. Each event carries a
`verified` flag that the runner shows and checks. An optional **IP allowlist** per hook is defence in
depth only, never the sole check. Each hook also has a **test URL** *(suggestion, from n8n)*: events
sent there reach `00hooks listen` and the builder's preview, but never run automations. Signing
secrets the relay needs in order to verify are **encrypted at rest** with a Worker secret (they can't
be hashed, since the relay must recompute signatures), shown only once when generated, and rotatable
with an overlap window so the old and new secrets both work for a set time.

### 4.3 Who may do what

- **Device keys**: `00hooks login` creates an Ed25519 signing key and an X25519 sealing key in the OS
  keychain (macOS Keychain, Secret Service on Linux, a 0600 file as the fallback). Pairing a device
  needs either an existing approved device to approve it (a short code, like a TV sign-in) or a
  one-time enrolment token from the dashboard. Requests are signed (a short-lived token minted from a
  signed challenge), so no long-lived secret crosses the network.
- **API keys** (`hk_…`) are for management and CI only: shown once, stored as a salted hash keyed
  with `HASH_PEPPER`, scoped (`hooks:read`, `hooks:write`, `events:read`, `devices:write`, and
  `audit:read`), with an expiry. An API key can never open the stream, enrol a device, set a
  sealing key or make more keys (PROTOCOL §9).
- **Audit**: hook created or deleted, secret rotated, device added or revoked, key created or used,
  verification failures (counted per hour). Names and ids only.

### 4.4 Sealing (always on; PROTOCOL §5)

Each device publishes its X25519 public key when it pairs. After verification the relay (the
account's Durable Object, so the sequence number is known) seals the body and kept headers with HPKE (RFC 9180, DHKEM-X25519, HKDF-SHA256, ChaCha20-Poly1305) once per
allowed device, with the hook id, sequence number and event id as associated data (so stored
ciphertexts can't be spliced or reordered) and the device key's id in the envelope (so keys can
rotate), then forgets the plaintext. The relay also signs each envelope with its own Ed25519 key, so
the CLI knows it came from your relay. The relay still sees metadata: when, which hook, size, the provider's event
type when it's in a header, and whether it verified. Trade-off: the payload is briefly in the Worker's
memory during verification; that is unavoidable for signature checks, and is why §4.2's secrets are
encrypted and the code is open for inspection. For people who can't accept that, a hook can use
**verify on your machine** *(strict mode)*: the edge only checks the cheap things (size, rate, a
header token), seals the raw body and signature headers together, and the CLI verifies the provider's
signature itself with the secret kept in your keychain. The relay then never sees plaintext, at the
cost of accepting some junk at the edge. Routing at the relay only ever uses plaintext metadata (hook
id, provider, event type), and that metadata is visible to the operator.

### 4.5 Self-hosting

`pnpm deploy` in `relay/` with your own Cloudflare account: a Worker, one Durable Object class, Rate
Limiting bindings, three secrets (`SECRETS_KEY` for encrypting hook secrets, `HASH_PEPPER` for key
hashes, `RELAY_SIGNING_KEY` for signing sealed envelopes). No other services. The CLI and 00next take the relay URL as a setting, so a hosted relay and
a self-hosted one are interchangeable.

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
- **Kept on your machine only**, in the runner's store (or 00next's), never at the relay. Samples and
  seen values are content, so each kind has *Clear sample*, the whole catalogue can be cleared, and a
  hook can be set to keep structure only (no sample, no values) for sensitive sources.
- **Noticed, not noisy**: a new kind shows up once in the Automations screen as *New from GitHub:
  "issues.labeled"*, with *Add an automation* and *Add a screen rule* right there, and it's marked when
  a known kind gains or loses fields (*shape changed on 14 Oct: added `pull_request.auto_merge`*).
- **Used everywhere a field is chosen**: the automation builder's filters, the screen's field rules,
  and templates (`{{payload.pull_request.title}}` with autocomplete and the sample's value as a
  preview). Filters on a field a kind no longer has are flagged instead of silently never matching.

### 5.1 Matching

An automation's **trigger is one or more kinds** from the catalogue (§5.0), plus optional filters:
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
- **Notify me**: a macOS or Linux notification, the 00next notch, or a message on a channel you've
  connected in 00next (Telegram, Signal, email…), with a template like
  `New order {{payload.id}} for {{payload.amount | money}}`.
- **Call a URL**: method, URL, headers (secrets by name, injected at send time) and a JSON body template.
  The URL's host must be in the automation's allowlist.
- **Run a command**: an allowed executable and an argument list. Template values are passed as
  separate arguments or environment variables, **never through a shell**; the executable must be on
  the automation's allowlist; it runs without your shell's environment and with a time limit.
- **Write a file**: append a line or write a JSON file in a chosen folder (templated name, sanitised).
- **Start a routine** or **add a task** (00next).

AI actions:
- **Ask an agent**: choose an agent or "a new agent for each event", write its instructions, choose its
  **access profile** (§6). The event arrives as a quoted block marked as untrusted data, with the hook
  and the verified/unverified flag. The agent's reply can feed a following action (for example *notify
  me with the agent's summary*).

### 5.3 Reliability

- Every event gets a **run record**: matched automations, each action's result, timings, errors.
- **Retries** with backoff for failed actions that are safe to retry (notify, call a URL with an
  idempotency key); never for commands unless the automation says they're idempotent.
- **Replay** any recorded event from the run history.
- **Rate limits** per automation (default 30 runs an hour) and a **circuit breaker** that pauses an
  automation after repeated failures and tells you.
- **Loop prevention**: actions that call out carry an `00hooks-origin` header and a hop count; an event
  arriving with our own origin header and a hop count over the limit is dropped.
- **Offline**: events wait at the relay (7 days by default) and run when the machine is back, oldest
  first, with a summary notification if many were waiting.

### 5.4 The CLI on its own

```
00hooks login                         pair this machine (or approve it from another device)
00hooks hooks create --preset github  prints the URL and, once, the signing secret
00hooks listen                        stream events to the terminal (or --json)
00hooks run                           run automations from ~/.config/00hooks/automations.yaml
00hooks test <hook>                   send a signed sample event
00hooks replay <event>                run an event again
00hooks doctor                        check keys, clock skew, connectivity, the relay version
00hooks service install               run `00hooks run` at login (launchd / systemd --user)
```

Written in Rust: one small static binary for macOS, Linux and Windows. Its core (`hooks-client`: pair,
stream, unseal, ack) is a library crate that the 00next node embeds directly, so 00next needs no
separate process.

## 6. In 00next: Automations and access profiles

### 6.1 Who answers

**Nothing triggered from outside runs as the supervisor.** Webhook events, incoming messages on
messaging apps and anything else that brings outside content are handled by a **responder**: a
subagent in its own computer (VM) working under an access profile. Routines follow the same rule
when they act on outside content (a feed, an inbox); a routine whose brief is entirely your own may
still go to the supervisor. The supervisor can *read* what responders did and be asked by them, but
outside content never gets the supervisor's reach into your machine.

### 6.2 Access profiles (one place for all three)

A profile is a named, reusable set of limits, enforced by the node, not by instructions in a prompt:

| Limit | What it controls | Enforced by |
|---|---|---|
| Websites | domains the agent may reach (`api.github.com`, `*.stripe.com`); everything else is blocked | the egress broker (an HTTP(S) proxy in the node that every VM must use) |
| Network | none / allowed websites only / open internet; local network on or off | VM network rules + the broker |
| Secrets | which vault secrets, by name, and for which domains; the broker adds them to requests, so the value never enters the VM | the egress broker |
| Folders | which folders it may work in (read-only or read-write) | VM mounts |
| Tools | can it run commands, write files, send messages, publish, spend money | approvals and the reviewer |
| Approvals | what it may do alone, what goes to the reviewer, what always asks you | approvals |
| Budget | tokens a day, runs an hour | the node's budgets |
| Model | which accounts it thinks with | the brain picker |

Starter profiles, editable: **Read only** (no network but allowed APIs, no writes outside its
workplace, asks before anything outward), **Replier** (can send a reply on the channel it came from,
nothing else), **Builder** (one folder read-write, allowed package registries, no secrets), **Open**
(anything, every outward act reviewed).

The UI is a single **Access** screen in Settings: a list of profiles, each a card of plain switches and
chips ("Websites: api.github.com, docs.stripe.com · Secrets: STRIPE_KEY for api.stripe.com · Can send
messages: only replies"). Automations, messaging routes and routines pick a profile from a menu; a
"What can this do?" line on each shows the profile's summary.

### 6.3 The Automations screen (Zapier-like)

- **List**: each automation as a sentence: *When GitHub sends “pull request opened” on 00next, the
  Reviewer agent reviews it (profile: Read only) and notifies me.* With last run, run count and a
  switch.
- **Builder**: three steps, *When* (pick or create a hook: choose the service, get the URL and secret
  with copy buttons and the service's setup steps), *Only if* (filters, with a live preview against the
  last real events for that hook), *Then* (one or more actions, each with its own small form).
- **Runs**: the event (decrypted locally), what matched, each action's result, *Replay*.
- **Templates**: ready-made automations (*GitHub PR → review agent*, *Stripe payment → thank-you email
  draft + notify me*, *Form submission → task*, *Uptime alert → notify me*).

## 6a. The screen: a firewall for everything that comes from outside

An optional firewall that decides what happens to each incoming item **before** any automation or
agent sees it. It covers webhooks and, in 00next, incoming messages and the outside content routines
fetch. It runs in two places, each doing what it's best at:

| Where | What it does | Why there |
|---|---|---|
| **Edge** (the relay) | cheap, deterministic, private checks: origin, rules, rate, and fingerprints of things you blocked | drops floods and known junk before it's stored or streamed; works with sealing, because it only uses metadata and fingerprints taken during verification |
| **Harness** (the CLI's runner, or 00next) | the same rules and similarity memory, plus an optional **AI evaluator** | sees the full content with no third party in between, can use your own models (or a local one), and is the last stop before an agent |

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
- **If it fails or times out**, the screen falls back to a per-source default (quarantine for anything
  bound for an agent, pass for plain notifications), never to silently passing.
- **Providers**: any Decisions endpoint (OpenRouter's, and others as they appear), any chat model through
  a structured-output adapter, or a **local model** for full privacy. Requests to hosted models ask for
  zero data retention and no training on the data where the provider supports it, and a model that
  can't offer that is refused when the source is marked sensitive.
- **Cost** is visible per source (evaluations today, and what they cost on your account), with a daily
  cap after which items fall back to the default verdict.

### Optional and paid

Everything above is in the open-source code and works with your own model accounts. A hosted relay can
offer extras as **entitlements** the server announces (never hard-coded in the clients): edge
reputation lists (networks and fingerprints seen abusing many accounts, shared only as hashes),
fingerprint sync across devices, longer quarantine retention and evaluator credits. Self-hosted relays
simply don't announce them.

### In 00next

One **Screen** settings page per source type (webhooks, each messaging channel, routines that fetch
outside content): on or off, the rules, the learned rules with their matches, the evaluator (model,
thresholds, fallback, daily cap) and a **Quarantine** list shared by all of them, with Release, Drop,
Always and a preview of the item as untrusted text. The screen runs before the access profile's
responder is ever woken, so a dropped message costs no agent turn.

## 7. Phases

| # | Phase | Exit test |
|---|---|---|
| 0 | relay skeleton (hooks, generic HMAC, DO log, the SSE bridge with resume, gaps and acks), CLI `login`/`hooks`/`listen` | a GitHub test delivery reaches the terminal within a second; killing the CLI, or redeploying the relay, resumes without loss or duplicates; a week of idle connections costs what §10 predicts |
| 1 | provider presets, replay protection, sealing, device pairing, API keys, audit | a replayed or forged event is refused; the relay's storage holds only ciphertext |
| 2 | CLI `run` with plain actions, run records, retries, rate limits, service install | a Stripe test event sends a notification and appends a line to a file, at most once |
| 3 | 00next: hooks-client in the node, Access profiles + egress broker, Automations screen, agent actions | a GitHub PR event wakes a responder agent that can reach only api.github.com and comments with an approved token, and the supervisor never ran |
| 4 | messaging and routines use access profiles; templates; email-in hooks *(suggestion)* | an inbound Telegram message is answered by a Replier-profile agent that cannot reach any other site |
| 5 | the screen: rules and similarity at the edge and in the harness, quarantine with Release/Drop/Always, the Decisions-API evaluator, local-model option, entitlements for hosted extras | a flood of near-identical junk is dropped at the edge after one Drop + Always; a prompt-injection message is quarantined before any agent runs; the evaluator failing quarantines instead of passing |

## 8. Decisions to make

1. **Transport**: SSE to the CLI as briefed, bridged by the Worker from a hibernatable WebSocket on the
   Durable Object (§3.2), so an always-on connection costs almost nothing while idle.
2. **Sealing on by default**: recommended yes.
3. **Hosted relay**: run one for 00next users (free tier with limits) or self-host only at first.
4. **Name**: `00hooks` is a working name.
5. **Email-in hooks** *(suggestion)*: each hook can also have an email address (Cloudflare Email
   Routing), so "when an email arrives at invoices@…" becomes a trigger.

## 9. Lessons from an earlier watch CLI

Its design (a hibernating Durable Object per workspace, an SSE bridge in the Worker, content-free
"doorbell" frames, Ed25519-signed requests with single-use nonces, keys kept in the Keychain) is the
starting point. 00hooks keeps the good parts and fixes what it left open:

| The earlier watch CLI | 00hooks |
|---|---|
| Doorbells only; the client fetches content over REST | the event itself is the payload, sealed to the device, so there's no second fetch and no content at rest in plain text |
| No durable cursor: catch-up by wall-clock `since` minus a 5-minute margin, which brings duplicates and depends on clocks | a per-account ordered log with sequence numbers, `Last-Event-ID` resume and per-device acks |
| At-most-once doorbells, dedupe in memory only | at-least-once delivery, dedupe by event id persisted in the CLI's run records |
| Inbound HMAC without a timestamp; replay dedupe in eventually-consistent KV, marked *before* processing (a crash loses the event) | timestamped signatures where the provider offers them, a seen-id set in the Durable Object (strongly consistent), written in the same transaction as the event |
| No body-size limit on webhooks | 1 MB default, per-hook configurable |
| Revocation can take up to 4 minutes to reach a watcher | revoking a device closes its socket at once (the Durable Object holds both) |
| `--exec` runs through a shell, with stranger text in environment variables | commands get an argument list, never a shell; payloads go to stdin or a file, and agent actions get them as quoted data |
| Approximate fixed-window rate limit in KV | Cloudflare's Rate Limiting binding at the edge plus exact counters in the Durable Object |
| Unsalted key hashes (acceptable for 256-bit keys) | salted with a pepper anyway |

Worth reusing (rewritten, since 00hooks is Apache-2.0 and must not carry another product's hosts,
key formats or provider details): the SSE bridge and its backpressure handling, the token-bucket
shaper, a hand-rolled SSE reader with jittered reconnects (1 s to 30 s, 70 s without bytes counts as
dead), a bounded drain-aware output queue, the request-signing scheme (host, method, path, time,
nonce, body hash) and storing keys in the OS keychain through stdin rather than arguments.

## 10. Cloudflare limits and costs

- **Workers**: no wall-clock limit while the client stays connected, and on the Standard plan wall
  time isn't billed, only CPU time (30 s default, up to 5 minutes). Bodies up to 100 MB on Free and
  Pro. That's why the Worker, not the Durable Object, holds the SSE response.
- **Durable Objects**: one per account; single-threaded, so events are ordered; SQLite up to 10 GB and
  2 MB per row; roughly 1,000 requests a second each. Duration is billed while the object is awake:
  an SSE stream held *by the object* would keep it awake, about $4 per always-on user per month,
  while a hibernating WebSocket costs almost nothing idle (incoming messages billed at 20:1, outgoing
  free) and holds up to 32,768 sockets.
- **The bridge** (Worker holds SSE, Durable Object holds a hibernating WebSocket to it) is the design
  but is inferred from the documentation: **phase 0 builds it first and measures the bill** with a
  week of idle connections before anything else depends on it. The fallback is a direct WebSocket
  from the CLI, which needs no bridge.
- **Rate Limiting binding**: 10 or 60 s periods, counted per location and eventually consistent, so
  it's for cheap shedding at the edge; exact quotas are counted in the Durable Object.
- **Queues** (128 KB messages, up to 14 days) are not the event log; at most they carry side work.

Sources: Cloudflare's Workers, Durable Objects (limits, pricing, lifecycle, WebSockets) and Rate
Limiting documentation; the WHATWG SSE specification; RFC 9180 (HPKE); the Standard Webhooks
specification; GitHub, Stripe, Slack, Shopify, Twilio and Linear webhook documentation; and prior art
in smee.io, Hookdeck, ngrok's verify-webhook, Svix and n8n.
