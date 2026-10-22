#!/usr/bin/env node
// `pnpm check`: what a change must pass before it lands. The relay's type check and tests (and its
// installer's), then the CLI's formatting, lint and tests.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const steps = [];
if (existsSync(join(root, "relay/package.json"))) {
  steps.push(["Relay types", "pnpm", ["--filter", "./relay", "typecheck"]]);
  steps.push(["Relay tests", "pnpm", ["--filter", "./relay", "test"]]);
  // The installer runs under Node, not workerd: its own runner.
  steps.push(["Relay installer tests", "node", ["--test", "relay/scripts/setup.nodetest.mjs"]]);
}
if (existsSync(join(root, "cli/00hooks/Cargo.toml"))) {
  steps.push(["CLI formatting", "cargo", ["fmt", "--all", "--check"]]);
  steps.push(["CLI lint", "cargo", ["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"]]);
  steps.push(["CLI tests", "cargo", ["test", "--workspace", "-q"]]);
}
for (const [label, cmd, args] of steps) {
  console.log(`\n▸ ${label}`);
  // The CLI's interop test runs the relay's sealing code under Node; here it must not skip.
  const r = spawnSync(cmd, args, { cwd: root, stdio: "inherit", env: { ...process.env, HOOKS_REQUIRE_NODE: "1" } });
  if (r.status !== 0) {
    console.error(`\n✗ ${label} failed.`);
    process.exit(r.status ?? 1);
  }
}
console.log("\n✓ Everything passes.");
