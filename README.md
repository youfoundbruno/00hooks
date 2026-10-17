# 00hooks

Webhooks from anywhere, delivered to your own computer in real time, safely.

Point any service that sends webhooks (GitHub, Stripe, Shopify, Slack, your own app) at a hook URL.
A small relay on Cloudflare checks the event is genuine, seals it so only your devices can read it,
and streams it to the `00hooks` CLI on your Mac or Linux machine, where it runs your automations:
notify you, call a URL, run an allowed command, or hand it to an AI agent that can only do what you
allowed.

> Status: planning. The design and security model are in [`docs/PLAN.md`](docs/PLAN.md).

## Why

- **Real time without opening a port.** Your machine connects out to the relay; nothing listens on it.
- **Verified at the edge.** Provider signatures (Standard Webhooks, Stripe, GitHub, Slack and more),
  timestamp windows and replay protection, before anything is stored.
- **Sealed to your devices.** Events are stored and streamed as ciphertext only your devices can open.
- **Nothing is lost.** An ordered log with resume and acknowledgements: if your laptop sleeps, events
  wait and run when it's back, once.
- **Safe to act on.** Webhook content is data: never interpolated into a shell, and AI agents get it
  as quoted, untrusted input under an access profile.
- **Yours to run.** Self-host the relay on your own Cloudflare account, or use a hosted one.

## Components

- `relay/`: the Cloudflare Worker and Durable Object (TypeScript). How to run, test and self-host
  it: [`relay/README.md`](relay/README.md).
- `cli/`: the `00hooks` CLI and the `hooks-client` library (Rust), also embedded by
  [00next](https://github.com/youfoundbruno/00next).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
