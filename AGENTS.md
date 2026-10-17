# Working on 00hooks

Read [`docs/PLAN.md`](docs/PLAN.md) first. Its security model (§4) is the contract: a change that
weakens it is a bug, whatever a test says.

## Rules

- **This repository is public.** Never commit secrets, personal data, internal URLs, account ids or
  machine-specific paths. Use `.dev.vars` (gitignored) for local Worker secrets.
- **Every change ships with a test that pins it.** Security fixes start with a failing test.
- **Package managers**: pnpm for the Worker and its tests, cargo for the CLI.
- **Secrets are stored hashed or sealed, never in plain text**, and never written to logs, error
  messages or event payloads.
- **Webhook content is data.** Nothing from a payload is ever interpolated into a shell command, a
  file path or a prompt's instructions.
