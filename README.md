# 00hooks

Webhooks from anywhere, delivered to your own computer in real time, safely.

Point any service that sends webhooks (GitHub, Stripe, Shopify, Slack, Meta, your own app) at a
hook URL. A small relay on Cloudflare, which you run on your own account, checks the event is
genuine, seals it so only your devices can read it, and streams it to the `00hooks` CLI on your Mac
or Linux machine. There it runs your automations: notify you, call a URL, run an allowed command or
write to a file.

> Status: built are the relay (hooks, presets, sealing, device pairing, API keys, the audit, the
> screen and phone links), the CLI and its automation runner: phases 0, 1, 2 and 5 of
> [`docs/PLAN.md`](docs/PLAN.md) §7. PLAN marks what is not built. The wire contract is
> [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Why

- **Real time without opening a port.** Your machine connects out to the relay; nothing listens on it.
- **Verified at the edge.** Provider signatures (Standard Webhooks, Stripe, GitHub, Slack and more),
  timestamp windows and replay protection, before anything is stored.
- **Sealed to your devices.** Events are stored and streamed as ciphertext only your devices can open.
- **Nothing is lost.** An ordered log with resume and acknowledgements: if your laptop sleeps, events
  wait and run when it's back, once.
- **Safe to act on.** Webhook content is data: it is never interpolated into a shell command or a
  file path.
- **Yours to run.** You deploy the relay on your own Cloudflare account; there is no hosted relay.

## Components

- `relay/`: the Cloudflare Worker and its two Durable Object classes (TypeScript). How to run,
  test and self-host it: [`relay/README.md`](relay/README.md).
- `cli/`: the `00hooks` CLI (the `hooks-cli` crate), the `hooks-client` library, the `hooks-runner`
  automation runner and the `hooks-screen` library (Rust). The libraries can be embedded by other
  programs.

## Install the CLI

You need a Rust toolchain (`rustup`; `rust-toolchain.toml` picks the stable channel). From the
repository root:

```sh
cargo install --locked --path cli/00hooks    # installs the `00hooks` binary into ~/.cargo/bin
00hooks --help
```

The crates are not published to crates.io. To build without installing, run
`cargo build --release -p hooks-cli`; the binary is `target/release/00hooks`.

Then deploy your relay ([`relay/README.md`](relay/README.md), "Self-hosting") and log in to it.

## Hooks, keys and the audit

```
00hooks login --relay https://relay.example.com          pair this computer (signing + sealing keys)
00hooks hooks create --name ci --preset github             the URL and, once, the secret
00hooks hooks create --name pay --preset stripe --secret-stdin   providers that issue their own secret
00hooks hooks create --name pay --preset stripe --strict --secret-stdin
                                                           verify here: the relay never holds it
00hooks hooks secret <hook> --secret-stdin                 a strict hook's secret on another computer
00hooks devices seal-key                                   a sealing key for a login from before sealing
00hooks keys create --name ci --scope hooks:read           an API key for CI (never the stream)
00hooks audit                                              hooks, devices and keys changed; failures counted
```

Presets: `github`, `standard-webhooks`, `standard-webhooks-ed25519`, `stripe`, `slack`, `linear`,
`shopify`, `twilio`, `meta`, `hmac`, `token`, `unverified` (PROTOCOL §3 says what each one signs).

## Automations

`00hooks run` listens and runs the automations in `~/.config/00hooks/automations.yaml` (or
`--automations <file>`, or `HOOKS_AUTOMATIONS`); `00hooks service install` runs it at login.

```yaml
version: 1
notify: system                # or `none`: notifications are only recorded
hooks:
  payments: { structure_only: true }   # the catalogue keeps no sample or values for this hook
automations:
  - name: New issues
    when: { hook: github, kinds: [issues] }   # or `kinds: any`, `new_kind: true`, `shape_changed: true`
    only_if: payload.action == "opened" and payload.repository.full_name in ["acme/web"]
    verified_only: true       # the default
    rate_limit: 30/hour       # the default; repeated failures pause it (pause_after: 5, pause_for: 15m)
    allow_hosts: [api.example.com]
    allow_commands: [/usr/bin/say]
    then:
      - notify: "#{{payload.issue.number}} {{payload.issue.title | truncate:60}}"
      - call:
          url: https://api.example.com/issues/{{payload.issue.number}}
          headers: { Authorization: "Bearer {{secret.API_TOKEN}}" }   # `00hooks secrets set API_TOKEN`
          body: { title: "{{payload.issue.title}}" }
      - run: { command: say, args: ["New issue {{payload.issue.number}}"], timeout: 10s }
      - write: { append: ~/hooks/issues.jsonl }
```

- **Filters** compare fields (`payload.…`, `headers.…`, `event.…`) with `==`, `!=`, `>`, `<`, `>=`,
  `<=`, `in`, `contains`, `matches` (a literal regular expression) and combine them with `and`,
  `or`, `not`. They can't run anything.
- **Templates** fill `{{path}}` slots, with the filters `money`, `truncate`, `json` and `upper`.
- **Actions** never use a shell: a command gets an argument list and the event on stdin (or in a
  file named by `HOOKS_EVENT_FILE`), with only `PATH`, `HOME` and `LANG` from your environment; a
  call's host must be in `allow_hosts`; a file's folder is fixed and its name sanitised.
- `00hooks kinds` lists the kinds of events seen and `00hooks kinds show <hook/kind>` their fields;
  `00hooks automations check` validates the file against them; `00hooks runs` and
  `00hooks replay <event>` show and repeat runs.
- **Agent actions** (`ask`) run only in a program that embeds the runner and supplies an agent
  (the `ask::Asker` trait). The `00hooks` CLI runs plain actions only.
- **The screen** (optional, `00hooks screen on`) decides before any automation whether an event
  passes, is held for you or is dropped: rules on origin, headers, size and fields, similarity to
  what you dropped, and an optional AI evaluator that only answers typed questions (it has no tools
  and starts no action).
  `00hooks screen held`, `release`, `drop --always` and `sync` (the rules that can run at the relay,
  with field values as keyed hashes). See PLAN §6a and PROTOCOL §4b.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
