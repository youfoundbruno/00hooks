// The relay installer's tests (setup-lib.mjs), under Node's test runner: `node --test
// relay/scripts/setup.nodetest.mjs`, a step of `pnpm check`. Not `*.test.*`: the relay's vitest runs
// in workerd, which has no child processes or node:test. Needs Node 22.18+ (it imports the relay's
// own TypeScript, as the relay imports keys, to check that what setup generates is what it accepts).
//
// A fake wrangler records every call (arguments and stdin), so the tests can check what it would
// have done and that no secret reaches an argument, a printed line or a written file.

import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { PassThrough } from "node:stream";
import { describe, it } from "node:test";
import { importRelayKey } from "../src/envelope.ts";
import { openSecret, sealSecret } from "../src/seal.ts";
import { apnsConfig, resetApnsCache } from "../src/apns.ts";
import {
  DEPLOY_CONFIG,
  ROTATION_WARNINGS,
  SetupError,
  base64Buffer,
  checkApnsEnvironment,
  checkApnsKey,
  checkAppleId,
  checkFcmServiceAccount,
  checkTopic,
  generateSecret,
  mergeDeployConfig,
  parseArgs,
  parseDeployUrl,
  parseJsonc,
  readSetupState,
  renderDeployConfig,
  setup,
  stripJsonc,
} from "./setup-lib.mjs";
import { readHidden } from "./setup.mjs";

const TEMPLATE_TEXT = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");
const TEMPLATE = parseJsonc(TEMPLATE_TEXT);
const DB_ID = "3f2a9c1e-1111-4222-8333-444455556666";

const p8 = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "pem" });
const rsaPem = () => generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" });
const serviceAccount = (over = {}) =>
  JSON.stringify({ type: "service_account", project_id: "demo-project", client_email: "relay@demo-project.iam.gserviceaccount.com", private_key: rsaPem(), ...over });

/** A fake Cloudflare: wrangler calls, the terminal, the files and /v1/info. */
function world({
  loggedIn = true,
  accounts = [{ id: "a".repeat(32), name: "Me" }],
  secrets = null, // null: the Worker doesn't exist yet
  dbs = [],
  tty = false,
  answers = [],
  hidden = [],
  files = {},
  env = {},
  info = null,
  secretListFails = false,
  putEchoesSecret = false,
} = {}) {
  const calls = [];
  const printed = [];
  const written = {};
  const fs = {
    read: (n) => written[n] ?? (n === "wrangler.jsonc" ? TEMPLATE_TEXT : (files[n] ?? null)),
    write: (n, t) => {
      written[n] = t;
    },
    readSecretFile: (p) => (files[p] === undefined ? null : Buffer.from(files[p])),
  };
  const state = { secrets: secrets === null ? null : new Set(secrets), dbs: [...dbs], deployed: false };
  const run = async (args, { input } = {}) => {
    const call = { args: [...args], input: input ? Buffer.from(input) : null, inputRef: input ?? null };
    calls.push(call);
    const cmd = args.slice(0, 2).join(" ");
    if (args[0] === "whoami") return loggedIn ? { code: 0, stdout: JSON.stringify({ loggedIn: true, email: "me@example.com", accounts }), stderr: "" } : { code: 1, stdout: '{"loggedIn":false}', stderr: "" };
    if (cmd === "d1 list") return { code: 0, stdout: JSON.stringify(state.dbs), stderr: "" };
    if (cmd === "d1 create") {
      state.dbs.push({ uuid: DB_ID, name: args[2] });
      return { code: 0, stdout: "✅ Successfully created DB", stderr: "" };
    }
    if (cmd === "d1 migrations") return { code: 0, stdout: "Migrations to be applied:\n0001_init.sql", stderr: "" };
    if (cmd === "secret list") {
      if (secretListFails) return { code: 1, stdout: "", stderr: "✘ [ERROR] Authentication error [code: 10000]" };
      if (state.secrets === null) return { code: 1, stdout: "", stderr: `✘ [ERROR] Worker "00hooks-relay" not found.\n\nIf this is a new Worker, run \`wrangler deploy\` first to create it.` };
      return { code: 0, stdout: JSON.stringify([...state.secrets].map((name) => ({ name, type: "secret_text" }))), stderr: "" };
    }
    if (cmd === "secret put") {
      if (putEchoesSecret) return { code: 1, stdout: `value was ${input.toString()}`, stderr: "" };
      state.secrets ??= new Set(); // wrangler makes a draft Worker
      state.secrets.add(args[2]);
      return { code: 0, stdout: `✨ Success! Uploaded secret ${args[2]}`, stderr: "" };
    }
    if (args[0] === "deploy") {
      state.deployed = true;
      return { code: 0, stdout: "Uploaded 00hooks-relay (3.1 sec)\nDeployed 00hooks-relay triggers (0.5 sec)\n  https://00hooks-relay.someone.workers.dev\n  schedule: 17 4 * * *\nCurrent Version ID: x", stderr: "" };
    }
    throw new Error(`unexpected wrangler call: ${args.join(" ")}`);
  };
  const io = {
    tty,
    print: (s) => printed.push(s),
    ask: async (q) => {
      printed.push(q);
      if (!answers.length) throw new Error(`unexpected question: ${q}`);
      return answers.shift();
    },
    askHidden: async (q) => {
      printed.push(q);
      if (!hidden.length) throw new Error(`unexpected hidden question: ${q}`);
      return Buffer.from(hidden.shift());
    },
  };
  const fetch = async (url) => {
    assert.equal(url, "https://00hooks-relay.someone.workers.dev/v1/info");
    const s = state.secrets ?? new Set();
    const body = info ?? {
      version: "0.2.0",
      protocol: 2,
      protocols: [2],
      signupOpen: !s.has("SIGNUP_TOKEN"),
      relayKey: s.has("RELAY_SIGNING_KEY") ? "A".repeat(43) : null,
      phone: { protocol: 1, push: { available: ["APNS_KEY", "APNS_KEY_ID", "APNS_TEAM_ID", "APNS_TOPIC"].every((n) => s.has(n)), environment: "sandbox" } },
    };
    return { ok: true, status: 200, json: async () => body };
  };
  return { deps: { run, io, fs, fetch, env, sleep: async () => {}, checkTries: 2 }, calls, printed, written, state };
}

/** Every secret value the fake wrangler received on stdin. */
const stdinValues = (calls) => calls.filter((c) => c.input).map((c) => ({ name: c.args[2], value: c.input.toString() }));

/** No secret anywhere but stdin (SIGNUP_TOKEN: printed exactly once, at the end). */
function assertNoLeaks(w, extra = []) {
  const values = [...stdinValues(w.calls), ...extra];
  const argv = w.calls.map((c) => c.args.join(" ")).join("\n");
  const printed = w.printed.join("\n");
  const files = Object.values(w.written).join("\n");
  for (const { name, value } of values) {
    // A choice between two public words, asked in the open.
    if (name === "APNS_ENVIRONMENT") continue;
    for (const part of [value, ...value.split("\n").filter((l) => l.length >= 16 && !l.startsWith("-----"))]) {
      assert.ok(!argv.includes(part), `${name} in an argument`);
      assert.ok(!files.includes(part), `${name} in a written file`);
      if (name === "SIGNUP_TOKEN") assert.equal(printed.split(part).length - 1, 1, "SIGNUP_TOKEN printed once");
      else assert.ok(!printed.includes(part), `${name} printed`);
    }
  }
  // Each secret's Buffer was zeroed once wrangler had it.
  for (const c of w.calls) if (c.inputRef) assert.ok(c.inputRef.every((b) => b === 0), `${c.args[2]} not zeroed`);
}

describe("generated secrets", () => {
  it("base64Buffer encodes like Buffer, padded and url-safe", () => {
    for (let n = 0; n < 40; n++) {
      const raw = randomBytes(n);
      assert.equal(base64Buffer(raw).toString(), raw.toString("base64"));
      assert.equal(base64Buffer(raw, { url: true }).toString(), raw.toString("base64url"));
    }
  });

  it("SECRETS_KEY is 32 bytes of base64 and seals with the relay's seal.ts (AES-256-GCM)", async () => {
    const k = generateSecret("SECRETS_KEY").toString();
    assert.match(k, /^[A-Za-z0-9+/]{43}=$/);
    assert.equal(Buffer.from(k, "base64").length, 32);
    const sealed = await sealSecret(k, "hk_1", "whsec_abc");
    assert.equal(await openSecret(k, "hk_1", sealed), "whsec_abc");
    const raw = await crypto.subtle.importKey("raw", Buffer.from(k, "base64"), { name: "AES-GCM" }, true, ["encrypt"]);
    assert.equal(raw.algorithm.length, 256);
  });

  it("RELAY_SIGNING_KEY imports with the relay's importRelayKey", async () => {
    const seen = new Set();
    for (let i = 0; i < 5; i++) {
      const k = generateSecret("RELAY_SIGNING_KEY").toString();
      assert.match(k, /^[A-Za-z0-9+/]{43}=$/);
      const relay = await importRelayKey(k);
      assert.ok(relay, "imports");
      assert.match(relay.publicKey, /^[A-Za-z0-9_-]{43}$/);
      seen.add(k);
    }
    assert.equal(seen.size, 5);
  });

  it("HASH_PEPPER and SIGNUP_TOKEN are long and random", () => {
    assert.equal(Buffer.from(generateSecret("HASH_PEPPER").toString(), "base64").length, 32);
    const t = generateSecret("SIGNUP_TOKEN").toString();
    assert.match(t, /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(t, generateSecret("SIGNUP_TOKEN").toString());
  });

  it("warns about what each rotation breaks", () => {
    assert.match(ROTATION_WARNINGS.RELAY_SIGNING_KEY, /log in again/);
    assert.match(ROTATION_WARNINGS.SECRETS_KEY, /can't be opened/);
    assert.match(ROTATION_WARNINGS.HASH_PEPPER, /API key/);
  });
});

describe("asked secrets are checked before upload", () => {
  it("accepts an APNs .p8 the relay accepts, and refuses others", async () => {
    const good = p8();
    assert.equal(checkApnsKey(Buffer.from(good)), null);
    resetApnsCache();
    const c = await apnsConfig({ APNS_KEY: good, APNS_KEY_ID: "ABC123DEFG", APNS_TEAM_ID: "TEAM123456", APNS_TOPIC: "com.example.phone", APNS_ENVIRONMENT: "sandbox" });
    assert.ok(c, "the relay accepts it too");
    const p384 = generateKeyPairSync("ec", { namedCurve: "secp384r1" }).privateKey.export({ type: "pkcs8", format: "pem" });
    assert.match(checkApnsKey(Buffer.from(p384)), /P-256/);
    assert.match(checkApnsKey(Buffer.from(rsaPem())), /P-256/);
    const sec1 = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "sec1", format: "pem" });
    assert.match(checkApnsKey(Buffer.from(sec1)), /PKCS#8/);
    assert.match(checkApnsKey(Buffer.from("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")), /readable/);
    assert.match(checkApnsKey(Buffer.from("hello")), /\.p8/);
  });

  it("checks the ids, the topic and the environment", () => {
    assert.equal(checkAppleId("ABC123DEFG", "x"), null);
    for (const bad of ["ABC123DEF", "ABC123DEFGH", "abc123defg", "ABC-23DEFG", ""]) assert.ok(checkAppleId(bad, "x"));
    assert.equal(checkTopic("com.example.phone"), null);
    assert.equal(checkTopic("com.example-co.app2"), null);
    for (const bad of ["phone", "com..x", "com.example/x", "com.ex ample", `${"a".repeat(250)}.bcdefg`]) assert.ok(checkTopic(bad), bad);
    assert.equal(checkApnsEnvironment("sandbox"), null);
    assert.equal(checkApnsEnvironment("production"), null);
    assert.ok(checkApnsEnvironment("prod"));
  });

  it("checks the FCM service account JSON", () => {
    assert.equal(checkFcmServiceAccount(Buffer.from(serviceAccount())), null);
    assert.match(checkFcmServiceAccount(Buffer.from("{nope")), /isn't JSON/);
    assert.match(checkFcmServiceAccount(Buffer.from(serviceAccount({ type: "authorized_user" }))), /service_account/);
    assert.match(checkFcmServiceAccount(Buffer.from(serviceAccount({ project_id: "" }))), /project_id/);
    assert.match(checkFcmServiceAccount(Buffer.from(serviceAccount({ client_email: "nobody" }))), /client_email/);
    assert.match(checkFcmServiceAccount(Buffer.from(serviceAccount({ private_key: p8() }))), /RSA/);
    assert.match(checkFcmServiceAccount(Buffer.from(serviceAccount({ private_key: "-----BEGIN PRIVATE KEY-----\nxx\n-----END PRIVATE KEY-----" }))), /can't be read/);
  });
});

describe("terminal", () => {
  it("hidden input refuses anything but a terminal", async () => {
    const stdin = new PassThrough();
    stdin.end("secret\n");
    await assert.rejects(readHidden(stdin, new PassThrough(), "Key: "), /terminal only/);
  });

  it("hidden input reads without echo, with backspace", async () => {
    const stdin = new PassThrough();
    stdin.isTTY = true;
    const modes = [];
    stdin.setRawMode = (m) => modes.push(m);
    const stdout = new PassThrough();
    let shown = "";
    stdout.on("data", (d) => (shown += d));
    const p = readHidden(stdin, stdout, "Key: ");
    stdin.write(Buffer.from("ABX\x7fC\r"));
    const v = await p;
    assert.equal(v.toString(), "ABC");
    assert.deepEqual(modes, [true, false]);
    assert.ok(!shown.includes("AB"), "nothing echoed");
  });

  it("without a terminal, setup refuses to ask for push keys", async () => {
    const w = world({ secrets: [] });
    await assert.rejects(setup({}, w.deps), /terminal only.*--from-env/s);
    // Refused before anything was set.
    assert.ok(!w.calls.some((c) => c.args[1] === "put"));
    assert.ok(!w.state.deployed);
  });
});

describe("the install", () => {
  it("installs from nothing: database, migrations, secrets before the deploy, then the check", async () => {
    const w = world();
    const r = await setup({ skipPush: true, ratelimitBase: 5_000_000 }, w.deps);
    assert.equal(r.ok, true);
    const order = w.calls.map((c) => c.args.slice(0, 3).join(" "));
    assert.deepEqual(order, [
      "whoami --json",
      "d1 list --json",
      "d1 create 00hooks",
      "d1 list --json",
      "d1 migrations apply",
      "secret list -c",
      "secret put SECRETS_KEY",
      "secret put HASH_PEPPER",
      "secret put RELAY_SIGNING_KEY",
      "secret put SIGNUP_TOKEN",
      "deploy -c wrangler.deploy.jsonc",
    ]);
    for (const c of w.calls.slice(1)) assert.ok(c.args.join(" ").includes(`-c ${DEPLOY_CONFIG}`), c.args.join(" "));
    const cfgText = w.written[DEPLOY_CONFIG];
    const cfg = parseJsonc(cfgText);
    assert.equal(cfg.d1_databases[0].database_id, DB_ID);
    // One id per binding the template names, from the chosen base (new bindings get the next ones).
    assert.deepEqual(cfg.ratelimits.map((r) => r.namespace_id), TEMPLATE.ratelimits.map((_, i) => String(5_000_001 + i)));
    assert.deepEqual(readSetupState(cfgText), { ratelimitBase: 5_000_000, url: "https://00hooks-relay.someone.workers.dev" });
    const printed = w.printed.join("\n");
    assert.match(printed, /00hooks login --relay https:\/\/00hooks-relay\.someone\.workers\.dev/);
    assert.match(printed, /HOOKS_SIGNUP_TOKEN/);
    assert.match(printed, /00next/);
    assertNoLeaks(w);
  });

  it("re-running keeps every secret already set and asks nothing", async () => {
    const all = ["SECRETS_KEY", "HASH_PEPPER", "RELAY_SIGNING_KEY", "SIGNUP_TOKEN", "APNS_KEY", "APNS_KEY_ID", "APNS_TEAM_ID", "APNS_TOPIC", "APNS_ENVIRONMENT", "FCM_SERVICE_ACCOUNT"];
    const existing = renderDeployConfig(mergeDeployConfig(TEMPLATE, null, { ratelimitBase: 7_000 }).config, { ratelimitBase: 7_000 }).replace("00000000-0000-0000-0000-000000000000", DB_ID);
    const w = world({ secrets: all, dbs: [{ uuid: DB_ID, name: "00hooks" }], files: { [DEPLOY_CONFIG]: existing } });
    await setup({}, w.deps);
    assert.ok(!w.calls.some((c) => c.args[0] === "secret" && c.args[1] === "put"), "nothing replaced");
    assert.ok(!w.calls.some((c) => c.args[1] === "create"));
    assert.match(w.printed.join("\n"), /signup token was set by an earlier run/);
    assert.ok(w.state.deployed);
  });

  it("stops, replacing nothing, when it can't tell which secrets are set", async () => {
    const w = world({ secretListFails: true });
    await assert.rejects(setup({ skipPush: true }, w.deps), /Nothing was replaced/);
    assert.ok(!w.calls.some((c) => c.args[1] === "put"));
  });

  it("stops when not logged in", async () => {
    const w = world({ loggedIn: false });
    await assert.rejects(setup({}, w.deps), /wrangler login/);
    assert.equal(w.calls.length, 1);
  });

  it("rotates only after the name is typed back", async () => {
    const set = ["SECRETS_KEY", "HASH_PEPPER", "RELAY_SIGNING_KEY", "SIGNUP_TOKEN"];
    const no = world({ secrets: set, tty: true, answers: ["yes"] });
    await assert.rejects(setup({ rotate: ["RELAY_SIGNING_KEY"], skipPush: true }, no.deps), /kept; nothing was replaced/);
    assert.ok(!no.calls.some((c) => c.args[1] === "put"));
    assert.match(no.printed.join("\n"), /log in again/);

    const yes = world({ secrets: set, tty: true, answers: ["SIGNUP_TOKEN"] });
    await setup({ rotate: ["SIGNUP_TOKEN"], skipPush: true }, yes.deps);
    assert.deepEqual(stdinValues(yes.calls).map((v) => v.name), ["SIGNUP_TOKEN"]);
    assertNoLeaks(yes);

    const notty = world({ secrets: set });
    await assert.rejects(setup({ rotate: ["SIGNUP_TOKEN"], skipPush: true }, notty.deps), /terminal/);
  });

  it("asks for push in a terminal: file paths, hidden ids, and a skip", async () => {
    const key = p8();
    const sa = serviceAccount();
    const w = world({
      secrets: ["SECRETS_KEY", "HASH_PEPPER", "RELAY_SIGNING_KEY", "SIGNUP_TOKEN"],
      tty: true,
      files: { "/keys/AuthKey.p8": key, "/keys/bad.p8": "nope", "/keys/sa.json": sa },
      answers: ["y", "/keys/bad.p8", "/keys/AuthKey.p8", "sandbox", "y", "/keys/sa.json"],
      hidden: ["abc123defg", "TEAM12345", "TEAM123456", "com.example.phone"],
    });
    await setup({}, w.deps);
    const v = Object.fromEntries(stdinValues(w.calls).map((x) => [x.name, x.value]));
    assert.equal(v.APNS_KEY, key);
    assert.equal(v.APNS_KEY_ID, "ABC123DEFG");
    assert.equal(v.APNS_TEAM_ID, "TEAM123456");
    assert.equal(v.APNS_TOPIC, "com.example.phone");
    assert.equal(v.APNS_ENVIRONMENT, "sandbox");
    assert.equal(v.FCM_SERVICE_ACCOUNT, sa);
    assert.match(w.printed.join("\n"), /isn't a \.p8 key/);
    assert.match(w.printed.join("\n"), /Push to iPhones: available/);
    assertNoLeaks(w);

    const skip = world({ secrets: ["SECRETS_KEY", "HASH_PEPPER", "RELAY_SIGNING_KEY", "SIGNUP_TOKEN"], tty: true, answers: ["s", "s"] });
    await setup({}, skip.deps);
    assert.match(skip.printed.join("\n"), /push to iPhones won't be available/);
    assert.match(skip.printed.join("\n"), /push to Android phones won't be available/);
  });

  it("takes push keys from --from-env without a terminal, and refuses half of them", async () => {
    const key = p8();
    const sa = serviceAccount();
    const env = { APNS_KEY_FILE: "/k.p8", APNS_KEY_ID: "ABC123DEFG", APNS_TEAM_ID: "TEAM123456", APNS_TOPIC: "com.example.phone", FCM_SERVICE_ACCOUNT_FILE: "/sa.json" };
    const w = world({ files: { "/k.p8": key, "/sa.json": sa }, env });
    await setup({ fromEnv: true }, w.deps);
    const names = stdinValues(w.calls).map((x) => x.name);
    assert.deepEqual(names.slice(4), ["APNS_KEY", "APNS_KEY_ID", "APNS_TEAM_ID", "APNS_TOPIC", "APNS_ENVIRONMENT", "FCM_SERVICE_ACCOUNT"]);
    assert.equal(stdinValues(w.calls).find((x) => x.name === "APNS_ENVIRONMENT").value, "production");
    assertNoLeaks(w);

    const half = world({ env: { APNS_KEY_ID: "ABC123DEFG" } });
    await assert.rejects(setup({ fromEnv: true }, half.deps), /only part of it/);
    const bad = world({ files: { "/sa.json": serviceAccount({ type: "user" }) }, env: { FCM_SERVICE_ACCOUNT_FILE: "/sa.json" } });
    await assert.rejects(setup({ fromEnv: true }, bad.deps), /service_account/);
    assert.ok(!bad.calls.some((c) => c.args[2] === "FCM_SERVICE_ACCOUNT"));
  });

  it("never shows wrangler's output when it contains the secret", async () => {
    const w = world({ putEchoesSecret: true });
    const err = await setup({ skipPush: true }, w.deps).catch((e) => e);
    assert.ok(err instanceof SetupError);
    const value = w.calls.find((c) => c.input).input.toString();
    assert.ok(!err.message.includes(value));
    assert.match(err.message, /Setting SECRETS_KEY failed/);
  });

  it("shows the signup token when it stops after setting it", async () => {
    const w = world({ secrets: [], info: { protocol: 2, protocols: [2], signupOpen: false, relayKey: null } });
    await assert.rejects(setup({ skipPush: true }, w.deps), /not ready/);
    assert.match(w.printed.join("\n"), /signup token set in this run/);
    assertNoLeaks(w);
  });

  it("checks the relay and says what's wrong", async () => {
    const w = world({ secrets: ["SECRETS_KEY", "HASH_PEPPER", "RELAY_SIGNING_KEY", "SIGNUP_TOKEN"], info: { protocol: 2, protocols: [2], signupOpen: true, relayKey: null, phone: { push: { available: false, environment: null } } } });
    await assert.rejects(setup({ skipPush: true }, w.deps), /not ready/);
    const p = w.printed.join("\n");
    assert.match(p, /no relay signing key/);
    assert.match(p, /signups are open/);
  });

  it("--check-only runs no wrangler at all", async () => {
    const w = world({ files: { [DEPLOY_CONFIG]: renderDeployConfig(TEMPLATE, { url: "https://00hooks-relay.someone.workers.dev" }) }, secrets: ["SIGNUP_TOKEN", "RELAY_SIGNING_KEY"] });
    const r = await setup({ checkOnly: true }, w.deps);
    assert.equal(r.ok, true);
    assert.equal(w.calls.length, 0);
    await assert.rejects(setup({ checkOnly: true }, world().deps), /--url/);
  });
});

describe("dry run", () => {
  it("runs, generates, asks and writes nothing, and names secrets only as placeholders", async () => {
    const w = world();
    const r = await setup({ dryRun: true }, w.deps);
    assert.equal(r.dryRun, true);
    assert.equal(w.calls.length, 0);
    assert.deepEqual(w.written, {});
    const p = w.printed.join("\n");
    for (const line of ["wrangler whoami --json", "wrangler d1 create 00hooks -c wrangler.deploy.jsonc", "wrangler d1 migrations apply DB --remote -c wrangler.deploy.jsonc", "wrangler deploy -c wrangler.deploy.jsonc"]) {
      assert.ok(p.includes(line), line);
    }
    assert.match(p, /wrangler secret put SECRETS_KEY -c wrangler\.deploy\.jsonc {2}< <generated SECRETS_KEY>/);
    assert.match(p, /< <asked APNS_KEY>/);
    assert.match(p, /< <asked FCM_SERVICE_ACCOUNT>/);
    // Nothing that looks like a key.
    assert.ok(!/[A-Za-z0-9+/_-]{40,}/.test(p), "no secret-looking value");
  });

  it("with --detect, runs only read-only wrangler commands", async () => {
    const w = world({ secrets: ["SECRETS_KEY", "HASH_PEPPER"], dbs: [{ uuid: DB_ID, name: "00hooks" }] });
    await setup({ dryRun: true, detect: true }, w.deps);
    assert.deepEqual(
      w.calls.map((c) => c.args.slice(0, 2).join(" ")),
      ["whoami --json", "d1 list", "secret list"],
    );
    assert.deepEqual(w.written, {});
    const p = w.printed.join("\n");
    assert.match(p, /SECRETS_KEY: already set, kept/);
    assert.match(p, /secret put RELAY_SIGNING_KEY/);
    assert.ok(!p.includes("d1 create"));
  });
});

describe("deploy config", () => {
  it("strips JSONC comments and trailing commas without touching strings", () => {
    const text = `// head\n{ "a": "http://x//y", /* c */ "b": "/* not */", "c": [1, 2,], "d": "q\\"//",\n}`;
    assert.deepEqual(JSON.parse(stripJsonc(text)), { a: "http://x//y", b: "/* not */", c: [1, 2], d: 'q"//' });
    assert.throws(() => parseJsonc('{"a": "x}'), SetupError);
  });

  it("parses the real wrangler.jsonc", () => {
    assert.equal(TEMPLATE.d1_databases[0].binding, "DB");
    assert.ok(TEMPLATE.ratelimits.length >= 8);
  });

  it("re-runs keep the person's ids and edits, and carry over what's new", () => {
    const first = mergeDeployConfig(TEMPLATE, null, { ratelimitBase: 42_000 });
    const mine = structuredClone(first.config);
    mine.d1_databases[0].database_id = DB_ID;
    mine.vars.RETENTION_DAYS = "3";
    mine.ratelimits[0].simple.limit = 30;
    mine.routes = [{ pattern: "relay.example.com", custom_domain: true }];
    const text = renderDeployConfig(mine, first.state);

    // The template grows: a binding, a migration, a rate limit, a setting.
    const next = structuredClone(TEMPLATE);
    next.durable_objects.bindings.push({ name: "NEWTHING", class_name: "NewObject" });
    next.migrations.push({ tag: "v3", new_sqlite_classes: ["NewObject"] });
    // A binding the template gains later takes the next template id, and its id the next from the base.
    const newNs = String(1001 + TEMPLATE.ratelimits.length);
    const newId = String(42_001 + TEMPLATE.ratelimits.length);
    next.ratelimits.push({ name: "NEW_LIMIT", namespace_id: newNs, simple: { limit: 5, period: 60 } });
    next.vars.NEW_SETTING = "1";
    next.compatibility_date = "2099-01-01";

    const again = mergeDeployConfig(next, parseJsonc(text), { state: readSetupState(text) });
    const c = again.config;
    assert.equal(c.d1_databases[0].database_id, DB_ID);
    assert.equal(c.vars.RETENTION_DAYS, "3");
    assert.equal(c.ratelimits[0].simple.limit, 30);
    assert.deepEqual(c.routes, mine.routes);
    assert.deepEqual(c.ratelimits.map((r) => r.namespace_id), [...mine.ratelimits.map((r) => r.namespace_id), newId]);
    assert.ok(c.durable_objects.bindings.some((b) => b.name === "NEWTHING"));
    assert.deepEqual(c.migrations.map((m) => m.tag), ["v1", "v2", "v3"]);
    assert.equal(c.vars.NEW_SETTING, "1");
    assert.equal(c.compatibility_date, "2099-01-01");
    assert.ok(again.changes.some((x) => /NEW_LIMIT/.test(x)));

    // Without the state line, the base is read back from the ids.
    const inferred = mergeDeployConfig(next, parseJsonc(text), {});
    assert.equal(inferred.config.ratelimits.at(-1).namespace_id, newId);

    // A base given explicitly re-derives them all.
    const moved = mergeDeployConfig(TEMPLATE, parseJsonc(text), { state: readSetupState(text), ratelimitBase: 9_000 });
    assert.deepEqual(moved.config.ratelimits.map((r) => r.namespace_id).slice(0, 2), ["9001", "9002"]);
  });

  it("picks a random base the template's ids don't share, and keeps it", () => {
    const a = mergeDeployConfig(TEMPLATE, null, {});
    const ids = a.config.ratelimits.map((r) => r.namespace_id);
    assert.equal(new Set(ids).size, ids.length);
    for (const id of ids) assert.ok(Number(id) > 1_000_000);
    const text = renderDeployConfig(a.config, a.state);
    assert.deepEqual(mergeDeployConfig(TEMPLATE, parseJsonc(text), { state: readSetupState(text) }).config.ratelimits.map((r) => r.namespace_id), ids);
  });
});

describe("arguments and output", () => {
  it("takes no secrets on the command line and never echoes an unknown argument", () => {
    const e = (() => {
      try {
        parseArgs(["--signup-token", "s3cret-value"]);
      } catch (err) {
        return err;
      }
    })();
    assert.ok(e instanceof SetupError);
    assert.ok(!e.message.includes("s3cret"));
    assert.throws(() => parseArgs(["--var", "SECRETS_KEY=x"]), /never set this way/);
    assert.throws(() => parseArgs(["--rotate", "NOPE"]), SetupError);
    assert.throws(() => parseArgs(["--detect"]), /--dry-run/);
    assert.deepEqual(parseArgs(["--", "--var", "RETENTION_DAYS=3", "--rotate", "SIGNUP_TOKEN"]).vars, { RETENTION_DAYS: "3" });
    assert.equal(parseArgs(["--ratelimit-base", "123000"]).ratelimitBase, 123000);
    assert.throws(() => parseArgs(["--ratelimit-base", "0"]), SetupError);
  });

  it("finds the relay's address in wrangler deploy's output", () => {
    const wd = "Deployed 00hooks-relay triggers (1.2 sec)\n  https://00hooks-relay.me.workers.dev\n  schedule: 17 4 * * *\nCurrent Version ID: abc";
    assert.equal(parseDeployUrl(wd), "https://00hooks-relay.me.workers.dev");
    const custom = "Deployed 00hooks-relay triggers (1.2 sec)\n  https://00hooks-relay.me.workers.dev\n  relay.example.com (custom domain)\n  schedule: 17 4 * * *";
    assert.equal(parseDeployUrl(custom), "https://relay.example.com");
    assert.equal(parseDeployUrl("No targets deployed for 00hooks-relay"), null);
  });
});
