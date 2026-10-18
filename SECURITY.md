# Security policy

00hooks carries events from the internet to programs on your computer, so we take security reports
seriously.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. Don't open a public issue.

We aim to acknowledge reports within three working days and to share a fix timeline within ten.

## Scope

Of particular interest:
- getting an event accepted for a hook without its signing secret;
- reading another account's events, or any event payload as the relay operator (events are always
  sealed to the account's devices);
- replaying an old event so it runs again;
- making the CLI run something an automation didn't allow, from a payload;
- reading an API key, hook secret or device key from storage, logs or errors;
- obtaining a hook secret with an API key that lacks the `hooks:secrets` scope (`hooks:write` alone
  can't create a hook with a relay-generated secret or rotate one; a device signature or
  `hooks:secrets` is needed).

The security model is [`docs/PLAN.md`](docs/PLAN.md) §4.
