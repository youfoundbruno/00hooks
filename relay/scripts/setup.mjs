#!/usr/bin/env node
// Installs the 00hooks relay on your own Cloudflare account: `pnpm --filter ./relay setup`, or
// `node relay/scripts/setup.mjs [options]` (`--help` lists them). The logic is in setup-lib.mjs;
// this file is the real wrangler, terminal and files.

import { spawn } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { HELP, SetupError, parseArgs, setup } from "./setup-lib.mjs";

const relayDir = dirname(dirname(fileURLToPath(import.meta.url)));
const wranglerJs = join(relayDir, "node_modules", "wrangler", "bin", "wrangler.js");

/**
 * Runs wrangler in relay/. Without `input`, its output is shown as it comes and captured; with
 * `input` (a secret), the secret goes to its stdin and its output is only captured, so the caller
 * decides whether it's safe to show.
 */
function runWrangler(args, { input } = {}) {
  if (!existsSync(wranglerJs)) {
    return Promise.reject(new SetupError("wrangler isn't installed in relay/: run `pnpm install` at the repository root first."));
  }
  return new Promise((res, rej) => {
    // stdin is never the terminal, so wrangler never prompts: its confirmations take their defaults.
    const child = spawn(process.execPath, [wranglerJs, ...args], {
      cwd: relayDir,
      stdio: [input ? "pipe" : "ignore", "pipe", "pipe"],
      env: { ...process.env, WRANGLER_SEND_METRICS: process.env.WRANGLER_SEND_METRICS ?? "false" },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d;
      if (!input) process.stdout.write(d);
    });
    child.stderr.on("data", (d) => {
      stderr += d;
      if (!input) process.stderr.write(d);
    });
    // A failed spawn's error carries no stdin, but say only that it failed.
    child.on("error", () => rej(new SetupError("Couldn't start wrangler.")));
    child.on("close", (code) => res({ code: code ?? 1, stdout, stderr }));
    if (input) {
      child.stdin.on("error", () => {});
      child.stdin.end(input);
    }
  });
}

function terminalIO() {
  const tty = !!process.stdin.isTTY && !!process.stdout.isTTY;
  return {
    tty,
    print: (s) => process.stdout.write(`${s}\n`),
    async ask(q) {
      if (!tty) throw new SetupError("Setup asks questions in a terminal only.");
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try {
        return await rl.question(q);
      } finally {
        rl.close();
      }
    },
    askHidden: (q) => readHidden(process.stdin, process.stdout, q),
  };
}

/** Reads a line without echo into a Buffer (zeroed as it grows). Refuses anything but a terminal. */
export function readHidden(stdin, stdout, q) {
  if (!stdin.isTTY || typeof stdin.setRawMode !== "function") {
    return Promise.reject(new SetupError("Secrets are read from a terminal only: use --from-env or --from-file <json> otherwise."));
  }
  return new Promise((res, rej) => {
    let buf = Buffer.alloc(128);
    let len = 0;
    stdout.write(q);
    stdin.setRawMode(true);
    stdin.resume();
    const done = (err) => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
      stdout.write("\n");
      if (err) {
        buf.fill(0);
        rej(err);
      } else {
        const out = Buffer.from(buf.subarray(0, len));
        buf.fill(0);
        res(out);
      }
    };
    const onData = (chunk) => {
      for (const byte of chunk) {
        if (byte === 3) return done(new SetupError("Cancelled."));
        if (byte === 13 || byte === 10 || byte === 4) return done();
        if (byte === 127 || byte === 8) {
          if (len > 0) buf[--len] = 0;
          continue;
        }
        if (len === buf.length) {
          const bigger = Buffer.alloc(buf.length * 2);
          buf.copy(bigger);
          buf.fill(0);
          buf = bigger;
        }
        buf[len++] = byte;
      }
      if (Buffer.isBuffer(chunk)) chunk.fill(0);
    };
    stdin.on("data", onData);
  });
}

const files = {
  read(name) {
    const p = join(relayDir, name);
    return existsSync(p) ? readFileSync(p, "utf8") : null;
  },
  write(name, text) {
    writeFileSync(join(relayDir, name), text);
  },
  /** A key file chosen by the person: read as bytes, never as a string, never shown. */
  readSecretFile(path) {
    try {
      return readFileSync(resolve(path.replace(/^~(?=\/)/, process.env.HOME ?? "~")));
    } catch {
      return null;
    }
  },
};

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write(HELP);
    return;
  }
  let fromFileData;
  if (opts.fromFile) {
    const buf = files.readSecretFile(opts.fromFile);
    if (!buf) throw new SetupError("Couldn't read the --from-file JSON.");
    try {
      fromFileData = JSON.parse(buf.toString("utf8"));
    } catch {
      throw new SetupError("The --from-file file isn't JSON.");
    } finally {
      buf.fill(0);
    }
  }
  await setup(opts, { run: runWrangler, io: terminalIO(), fs: files, fetch, env: process.env, fromFileData });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    // Our own errors are fixed sentences; anything else is reported without its message, which
    // could in principle quote a value.
    process.stderr.write(`\n✗ ${e instanceof SetupError ? e.message : "Setup stopped on an unexpected error."}\n`);
    process.exit(1);
  });
}
