// The relay installer's logic (`setup.mjs` is its command line): put the 00hooks relay on the
// person's own Cloudflare account with their own `wrangler login`. Plain JavaScript for Node 22+, no
// dependencies, so it runs before anything is built.
//
// Every wrangler call goes through one runner (`deps.run`) and every question through one `io`, so
// the tests drive the whole flow with fakes and see everything wrangler would have seen.
//
// Secrets: each random one is made here with node:crypto, kept in a Buffer, piped to
// `wrangler secret put` on stdin and zeroed. None is ever an argument, written to a file, logged or
// put in an error message, except SIGNUP_TOKEN, which is printed once at the end because the person
// needs it to pair.

import { createPrivateKey, randomBytes, randomInt } from "node:crypto";

export const DEPLOY_CONFIG = "wrangler.deploy.jsonc";
export const TEMPLATE_CONFIG = "wrangler.jsonc";
const PLACEHOLDER_DB_ID = /^0{8}-0{4}-0{4}-0{4}-0{12}$/;
/** Rate-limit namespace ids are `base + offset`; offsets come from the template's 100N ids. */
const RATELIMIT_SPAN = 1000;
const RATELIMIT_MAX = 2 ** 31 - 1;

export class SetupError extends Error {}

// ─── JSONC ────────────────────────────────────────────────────────────────────────────────────────

/**
 * JSONC to JSON text: comments become spaces (newlines kept) and trailing commas go, both only
 * outside strings, so a `//` or `/*` inside a string value is left alone.
 */
export function stripJsonc(text) {
  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < n && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      if (j >= n) throw new SetupError("The config has a string that never ends.");
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < n && text[i] !== "\n") {
        out += " ";
        i++;
      }
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      if (end < 0) throw new SetupError("The config has a comment that never ends.");
      out += text.slice(i, end + 2).replace(/[^\n]/g, " ");
      i = end + 2;
    } else {
      out += c;
      i++;
    }
  }
  // Trailing commas, again only outside strings.
  let res = "";
  for (let k = 0; k < out.length; k++) {
    const c = out[k];
    if (c === '"') {
      let j = k + 1;
      while (j < out.length && out[j] !== '"') j += out[j] === "\\" ? 2 : 1;
      res += out.slice(k, j + 1);
      k = j;
    } else if (c === ",") {
      let j = k + 1;
      while (j < out.length && /\s/.test(out[j])) j++;
      if (out[j] === "}" || out[j] === "]") continue;
      res += c;
    } else {
      res += c;
    }
  }
  return res;
}

export function parseJsonc(text, what = "the config") {
  try {
    return JSON.parse(stripJsonc(text));
  } catch (e) {
    if (e instanceof SetupError) throw e;
    throw new SetupError(`${what} isn't valid JSONC: ${e.message}`);
  }
}

/** The installer's own state, kept in a comment line of the deploy config. */
export function readSetupState(text) {
  const m = /^\/\/ setup-state: (\{.*\})\s*$/m.exec(text ?? "");
  if (!m) return {};
  try {
    const s = JSON.parse(m[1]);
    return s && typeof s === "object" ? s : {};
  } catch {
    return {};
  }
}

export function renderDeployConfig(config, state) {
  return [
    "// The 00hooks relay's deploy config for YOUR Cloudflare account, written by",
    "// `pnpm --filter ./relay setup` from wrangler.jsonc (whose comments explain every setting).",
    "// Git ignores it: never commit it. Edit it freely (vars, limits, routes): setup keeps your edits and",
    "// ids when it runs again, and carries over what's new in wrangler.jsonc. No secrets live here.",
    `// setup-state: ${JSON.stringify(state)}`,
    JSON.stringify(config, null, 2),
    "",
  ].join("\n");
}

// ─── Deploy config merge ───────────────────────────────────────────────────────────────────────────

/** A random rate-limit base: a multiple of 1000, so the ids read as base + 1…8. */
export function randomRatelimitBase() {
  return randomInt(1_000, 2_000_000) * RATELIMIT_SPAN;
}

export function parseRatelimitBase(s) {
  if (!/^[1-9][0-9]*$/.test(String(s))) throw new SetupError("--ratelimit-base takes a positive whole number.");
  const n = Number(s);
  if (n + RATELIMIT_SPAN > RATELIMIT_MAX) throw new SetupError(`--ratelimit-base must be below ${RATELIMIT_MAX - RATELIMIT_SPAN}.`);
  return n;
}

/** A template binding's offset: the dev id's last three digits (1001 → 1), else its position. */
function ratelimitOffset(rl, index) {
  const n = Number(rl.namespace_id);
  return Number.isInteger(n) && n > 0 ? n % RATELIMIT_SPAN || index + 1 : index + 1;
}

/** The base an existing deploy config's rate limits were derived from, when they fit the pattern. */
function inferRatelimitBase(template, existing) {
  for (const [i, t] of (template.ratelimits ?? []).entries()) {
    const e = (existing?.ratelimits ?? []).find((r) => r.name === t.name);
    const id = Number(e?.namespace_id);
    if (Number.isInteger(id) && id > RATELIMIT_SPAN) return id - ratelimitOffset(t, i);
  }
  return null;
}

function nextFreeId(start, used) {
  let id = start;
  while (used.has(String(id))) id++;
  used.add(String(id));
  return String(id);
}

export function hasRealDatabaseId(db) {
  return typeof db?.database_id === "string" && db.database_id.length > 0 && !PLACEHOLDER_DB_ID.test(db.database_id);
}

/**
 * The deploy config: the person's existing one with what's new in the template carried over, or a
 * fresh copy of the template. Ids and edits already there are kept; new rate limits get
 * `base + offset`. `ratelimitBase` given explicitly (the flag) re-derives every rate-limit id.
 */
export function mergeDeployConfig(template, existing, { state = {}, ratelimitBase, vars = {} } = {}) {
  const changes = [];
  const out = structuredClone(existing ?? template);
  if (!existing) changes.push("new: made from wrangler.jsonc");
  const override = ratelimitBase !== undefined;
  const base = ratelimitBase ?? state.ratelimitBase ?? inferRatelimitBase(template, existing) ?? randomRatelimitBase();

  if (existing) {
    for (const [k, v] of Object.entries(template)) {
      if (k in out) continue;
      out[k] = structuredClone(v);
      changes.push(`added "${k}" from wrangler.jsonc`);
    }
    // The code is written against the template's date: a newer one comes along with it.
    if (typeof template.compatibility_date === "string" && String(out.compatibility_date ?? "") < template.compatibility_date) {
      changes.push(`compatibility_date ${out.compatibility_date ?? "(none)"} → ${template.compatibility_date}`);
      out.compatibility_date = template.compatibility_date;
    }
    out.durable_objects ??= {};
    const addByKey = (list, from, key, label, adjust) => {
      for (const item of from ?? []) {
        if (list.some((x) => x?.[key] === item[key])) continue;
        list.push(adjust ? adjust(structuredClone(item)) : structuredClone(item));
        changes.push(`added ${label} ${item[key]}`);
      }
    };
    out.durable_objects.bindings ??= [];
    addByKey(out.durable_objects.bindings, template.durable_objects?.bindings, "name", "Durable Object binding");
    out.migrations ??= [];
    addByKey(out.migrations, template.migrations, "tag", "Durable Object migration");
    out.d1_databases ??= [];
    addByKey(out.d1_databases, template.d1_databases, "binding", "D1 binding");
    out.ratelimits ??= [];
    addByKey(out.ratelimits, template.ratelimits, "name", "rate limit", (rl) => ({ ...rl, namespace_id: null }));
    out.vars ??= {};
    for (const [k, v] of Object.entries(template.vars ?? {})) {
      if (k in out.vars) continue;
      out.vars[k] = v;
      changes.push(`added the setting ${k}`);
    }
    if (!out.triggers?.crons?.length && template.triggers?.crons?.length) {
      out.triggers = { ...(out.triggers ?? {}), crons: [...template.triggers.crons] };
      changes.push("added the daily cron trigger");
    }
  }

  // Rate-limit ids: fresh ones for a fresh config, new bindings, or everything when overridden.
  const used = new Set();
  if (!override && existing) for (const rl of out.ratelimits ?? []) if (rl.namespace_id) used.add(String(rl.namespace_id));
  for (const rl of out.ratelimits ?? []) {
    const i = (template.ratelimits ?? []).findIndex((t) => t.name === rl.name);
    const fresh = !existing || override || !rl.namespace_id;
    if (!fresh) continue;
    const offset = i >= 0 ? ratelimitOffset(template.ratelimits[i], i) : 900;
    rl.namespace_id = nextFreeId(base + offset, used);
  }
  if (override) changes.push(`rate-limit namespace ids re-derived from ${base}`);

  for (const [k, v] of Object.entries(vars)) {
    out.vars ??= {};
    if (out.vars[k] === v) continue;
    out.vars[k] = v;
    changes.push(`set the setting ${k}`);
  }
  return { config: out, changes, state: { ...state, ratelimitBase: base } };
}

/** Settings that may go in `vars` from `--var`: never a secret's name. */
export const SETTINGS = new Set([
  "OPEN_SIGNUP",
  "RETENTION_DAYS",
  "ACCOUNT_MAX_EVENTS",
  "ACCOUNT_MAX_BYTES",
  "HOOK_MAX_EVENTS",
  "HOOK_MAX_BYTES",
  "UNCHECKED_HOOK_MAX_EVENTS",
  "UNCHECKED_HOOK_MAX_BYTES",
  "HELD_MAX_EVENTS",
  "HELD_MAX_BYTES",
  "SCREEN_HELD_DAYS",
  "REPLAY_MARK_DAYS",
  "ACCOUNT_MAX_DEVICES",
  "PHONE_NODE_QUEUE_MAX",
  "PHONE_PHONE_QUEUE_MAX",
  "PHONE_QUEUE_MAX_BYTES",
  "PHONE_PUSH_PER_HOUR",
  "HOSTED_EXTRAS",
]);

// ─── Secrets: generation ───────────────────────────────────────────────────────────────────────────

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Base64 straight into a Buffer, so the encoded secret never becomes an (unzeroable) string. */
export function base64Buffer(raw, { url = false } = {}) {
  const abc = url ? B64URL : B64;
  const out = Buffer.alloc(Math.ceil(raw.length / 3) * 4);
  let o = 0;
  for (let i = 0; i < raw.length; i += 3) {
    const a = raw[i];
    const b = i + 1 < raw.length ? raw[i + 1] : 0;
    const c = i + 2 < raw.length ? raw[i + 2] : 0;
    out[o++] = abc.charCodeAt(a >> 2);
    out[o++] = abc.charCodeAt(((a & 3) << 4) | (b >> 4));
    out[o++] = i + 1 < raw.length ? abc.charCodeAt(((b & 15) << 2) | (c >> 6)) : 0x3d;
    out[o++] = i + 2 < raw.length ? abc.charCodeAt(c & 63) : 0x3d;
  }
  if (!url) return out;
  let end = out.length;
  while (end > 0 && out[end - 1] === 0x3d) end--;
  const trimmed = Buffer.from(out.subarray(0, end));
  out.fill(0);
  return trimmed;
}

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** The secrets the relay needs that are only random bytes: made here, never asked. */
export const GENERATED = ["SECRETS_KEY", "HASH_PEPPER", "RELAY_SIGNING_KEY", "SIGNUP_TOKEN"];

/** One generated secret, encoded the way the relay reads it. The caller zeroes the Buffer. */
export function generateSecret(name) {
  const raw = randomBytes(32);
  try {
    switch (name) {
      // seal.ts: 32 bytes, base64, imported as an AES-256-GCM key.
      case "SECRETS_KEY":
      // seal.ts pepperedHash: any string, used as an HMAC-SHA256 key.
      case "HASH_PEPPER":
        return base64Buffer(raw);
      // envelope.ts importRelayKey: a 32-byte Ed25519 seed, base64. Any 32 bytes are a valid seed;
      // checked anyway, the way the relay imports it (PKCS#8 prefix + seed).
      case "RELAY_SIGNING_KEY": {
        const der = Buffer.concat([PKCS8_ED25519_PREFIX, raw]);
        try {
          if (createPrivateKey({ key: der, format: "der", type: "pkcs8" }).asymmetricKeyType !== "ed25519") {
            throw new SetupError("The generated signing key didn't import as Ed25519.");
          }
        } finally {
          der.fill(0);
        }
        return base64Buffer(raw);
      }
      // accounts.ts: compared with `Authorization: Bearer <token>`; base64url so it pastes cleanly.
      case "SIGNUP_TOKEN":
        return base64Buffer(raw, { url: true });
      default:
        throw new SetupError(`${name} isn't a secret setup generates.`);
    }
  } finally {
    raw.fill(0);
  }
}

/** What replacing each secret breaks, from what the relay's code does with it. */
export const ROTATION_WARNINGS = {
  RELAY_SIGNING_KEY:
    "Every device pinned the relay's public key at login and checks every envelope against it: after this, EVERY device (CLI, 00next, phones) must log in again.",
  SECRETS_KEY:
    "Every hook signing secret the relay stores is sealed under it: after this they can't be opened, so deliveries to every verified (non-strict) hook fail until each hook gets a new secret (recreate it and update it at the provider).",
  HASH_PEPPER:
    "API keys, enrolment codes, Meta verify tokens, dedupe and replay marks, offline-notice marks and each account's screen key are keyed hashes under it: after this every API key stops working (create new ones), Meta hooks fail their endpoint check until the verify token is set again, open enrolment codes stop working, devices must fetch the new screen key and push their edge rules again, and replay marks are forgotten, so a delivery captured earlier would be accepted once more.",
  SIGNUP_TOKEN: "The old token stops working for new signups. Existing accounts and devices are not affected.",
};

// ─── Secrets: asked inputs and their checks ────────────────────────────────────────────────────────

export const APNS_REQUIRED = ["APNS_KEY", "APNS_KEY_ID", "APNS_TEAM_ID", "APNS_TOPIC"];
export const APNS_ALL = [...APNS_REQUIRED, "APNS_ENVIRONMENT"];
export const FCM = "FCM_SERVICE_ACCOUNT";
export const ASKED = [...APNS_ALL, FCM];

/** A .p8 file's bytes: a PKCS#8 PEM of a P-256 key, as Apple gives and apns.ts imports. */
export function checkApnsKey(buf) {
  const text = buf.toString("utf8").trim();
  if (!/^-----BEGIN PRIVATE KEY-----[\s\S]+-----END PRIVATE KEY-----$/.test(text)) {
    return "That isn't a .p8 key: it should start with -----BEGIN PRIVATE KEY----- (PKCS#8).";
  }
  try {
    const k = createPrivateKey({ key: text, format: "pem" });
    if (k.asymmetricKeyType !== "ec" || k.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      return "That key isn't a P-256 (ES256) key: APNs keys from Apple are.";
    }
  } catch {
    return "That file doesn't hold a readable private key.";
  }
  return null;
}

export function checkAppleId(s, what) {
  return /^[A-Z0-9]{10}$/.test(s) ? null : `${what} is 10 characters, capital letters and digits.`;
}

/** A bundle id: reverse DNS, and within what apns.ts accepts as a topic. */
export function checkTopic(s) {
  return s.length <= 255 && /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(s) ? null : "The topic is the app's bundle id, like com.example.phone.";
}

export function checkApnsEnvironment(s) {
  return s === "sandbox" || s === "production" ? null : "The APNs environment is sandbox or production.";
}

/** A Google service-account JSON file's bytes: what FCM's HTTP v1 API signs in with. */
export function checkFcmServiceAccount(buf) {
  let j;
  try {
    j = JSON.parse(buf.toString("utf8"));
  } catch {
    return "That file isn't JSON: download the service account's key file (JSON) from Google Cloud.";
  }
  if (!j || typeof j !== "object") return "That file isn't a service account's key.";
  if (j.type !== "service_account") return 'That JSON isn\'t a service account\'s key ("type" should be "service_account").';
  if (typeof j.project_id !== "string" || !j.project_id) return 'The key file has no "project_id".';
  if (typeof j.client_email !== "string" || !/^[^@\s]+@[^@\s]+$/.test(j.client_email)) return 'The key file has no valid "client_email".';
  if (typeof j.private_key !== "string" || !j.private_key.includes("-----BEGIN PRIVATE KEY-----")) {
    return 'The key file\'s "private_key" isn\'t a PKCS#8 key.';
  }
  try {
    if (createPrivateKey({ key: j.private_key, format: "pem" }).asymmetricKeyType !== "rsa") return 'The key file\'s "private_key" isn\'t an RSA key.';
  } catch {
    return 'The key file\'s "private_key" can\'t be read.';
  }
  return null;
}

// ─── Wrangler output ───────────────────────────────────────────────────────────────────────────────

/** The JSON value in wrangler's stdout, skipping any banner or warning around it. */
export function parseJsonOutput(stdout, open = "[") {
  const close = open === "[" ? "]" : "}";
  const a = stdout.indexOf(open);
  const b = stdout.lastIndexOf(close);
  if (a < 0 || b < a) return null;
  try {
    return JSON.parse(stdout.slice(a, b + 1));
  } catch {
    return null;
  }
}

/** The relay's address from `wrangler deploy`'s output: a custom domain or route first, else workers.dev. */
export function parseDeployUrl(output) {
  const lines = output.split(/\r?\n/);
  const at = lines.findIndex((l) => /Deployed .* triggers/.test(l));
  if (at < 0) return null;
  const candidates = [];
  for (const raw of lines.slice(at + 1)) {
    const l = raw.trim();
    if (!l || /^(Current Version ID|schedule:|Uploaded|Total Upload|No )/i.test(l)) {
      if (/^Current Version ID/i.test(l)) break;
      continue;
    }
    const m = /^(https:\/\/)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})(\/\*?)?(\s|$)/.exec(l);
    if (m) candidates.push(`https://${m[2]}`);
  }
  return candidates.find((u) => !u.endsWith(".workers.dev")) ?? candidates[0] ?? null;
}

// ─── The flow ──────────────────────────────────────────────────────────────────────────────────────

function wranglerLine(args, input) {
  return `wrangler ${args.join(" ")}${input ? `  < ${input}` : ""}`;
}

/** Parts of a secret long enough that seeing them in output would be a leak. */
function secretParts(buf) {
  const parts = [buf];
  for (const line of buf.toString("utf8").split(/\r?\n/)) {
    const t = line.trim();
    if (t.length >= 16 && !t.startsWith("-----")) parts.push(Buffer.from(t));
  }
  return parts;
}

/**
 * Runs the whole install, or (`--dry-run`) prints it. `deps`: `run(args, { input })` runs wrangler
 * in relay/ and resolves `{ code, stdout, stderr }`; `io` prints and asks; `fs` reads and writes
 * the two configs; `fetch` and `sleep` for the final check.
 */
export async function setup(opts, deps) {
  const { io, fs } = deps;
  const out = (s = "") => io.print(s);
  const dry = !!opts.dryRun;
  const detect = !dry || !!opts.detect;

  if (opts.checkOnly) {
    const state = readSetupState(fs.read(DEPLOY_CONFIG));
    const url = opts.url ?? state.url;
    if (!url) throw new SetupError("No relay address yet: pass --url https://<your relay>.");
    const r = await checkRelay(url, deps, {});
    return r;
  }

  // Wrangler runs through here only; in a plain dry run nothing runs at all.
  const readOnly = async (args) => {
    if (!detect) {
      out(`  ${wranglerLine(args)}`);
      return null;
    }
    return deps.run(args, {});
  };
  const change = async (args, note) => {
    if (dry) {
      out(`  ${wranglerLine(args)}${note ? `    # ${note}` : ""}`);
      return null;
    }
    return deps.run(args, {});
  };
  const must = (r, what) => {
    if (r && r.code !== 0) throw new SetupError(`${what} failed (wrangler exited with ${r.code}); its output is above. Fix that and run setup again: it continues where it stopped.`);
    return r;
  };

  if (dry) out(detect ? "Dry run (with read-only checks): nothing is changed, generated, asked or written.\n" : "Dry run: nothing is run, changed, generated, asked or written. These are the steps:\n");

  // 1. Logged in?
  out("▸ Cloudflare login");
  let accounts = [];
  const who = await readOnly(["whoami", "--json"]);
  if (who) {
    const j = parseJsonOutput(who.stdout, "{");
    if (who.code !== 0 || !j || j.loggedIn !== true) {
      throw new SetupError("You aren't logged in to Cloudflare. Run `pnpm --filter ./relay exec wrangler login` (or `npx wrangler login`), then run setup again.");
    }
    accounts = Array.isArray(j.accounts) ? j.accounts : [];
    out(`  Logged in${j.email ? ` as ${j.email}` : ""}.`);
  }

  // 2. The deploy config.
  out("▸ Deploy config (relay/wrangler.deploy.jsonc)");
  const templateText = fs.read(TEMPLATE_CONFIG);
  if (templateText === null) throw new SetupError("relay/wrangler.jsonc is missing.");
  const template = parseJsonc(templateText, "wrangler.jsonc");
  const existingText = fs.read(DEPLOY_CONFIG);
  const existing = existingText === null ? null : parseJsonc(existingText, DEPLOY_CONFIG);
  const merged = mergeDeployConfig(template, existing, {
    state: readSetupState(existingText),
    ratelimitBase: opts.ratelimitBase,
    vars: opts.vars ?? {},
  });
  const config = merged.config;
  let state = merged.state;

  // More than one Cloudflare account: wrangler can't pick one without a terminal, so it's chosen once.
  if (detect && !config.account_id && !deps.env?.CLOUDFLARE_ACCOUNT_ID && accounts.length > 1) {
    if (opts.account) config.account_id = opts.account;
    else if (dry) out("  You have several Cloudflare accounts: setup will ask which one (or pass --account <id>).");
    else config.account_id = await chooseAccount(accounts, io);
  } else if (opts.account) config.account_id = opts.account;

  const rlIds = (config.ratelimits ?? []).map((r) => `${r.name}=${r.namespace_id}`);
  const randomBase = !existing && opts.ratelimitBase === undefined;
  for (const c of merged.changes) out(`  ${c}`);
  out(`  Rate-limit namespace ids (base ${state.ratelimitBase}${randomBase ? ", random" + (dry ? "; the real run picks its own" : "") : ""}): ${rlIds.join(", ")}.`);
  out("  They must not be used by any other Worker's rate limiter in your Cloudflare account (they'd share counters).");
  out("  Choose another base with --ratelimit-base <n>.");
  const writeConfig = () => {
    const text = renderDeployConfig(config, state);
    if (dry) return;
    if (text !== fs.read(DEPLOY_CONFIG)) fs.write(DEPLOY_CONFIG, text);
  };
  if (dry) out(`  would write relay/${DEPLOY_CONFIG}`);
  writeConfig();
  const cfg = ["-c", DEPLOY_CONFIG];
  // A dry run writes no deploy config, so its read-only checks read the template (same Worker name).
  const roCfg = dry && detect && existing === null ? ["-c", TEMPLATE_CONFIG] : cfg;
  const workerName = config.name;

  // 3. The D1 database.
  out("▸ D1 database");
  const db = (config.d1_databases ?? []).find((d) => d.binding === "DB");
  if (!db) throw new SetupError(`${DEPLOY_CONFIG} has no D1 binding named DB.`);
  const dbName = db.database_name ?? "00hooks";
  if (hasRealDatabaseId(db)) {
    out(`  Using the database in the config (${dbName}).`);
  } else {
    const list = await readOnly(["d1", "list", "--json", ...roCfg]);
    let found = null;
    if (list) {
      must(list, "Listing your D1 databases");
      const dbs = parseJsonOutput(list.stdout, "[") ?? [];
      found = dbs.find((d) => d.name === dbName) ?? null;
    }
    if (found) {
      out(`  Found the database ${dbName}; using it.`);
    } else {
      must(await change(["d1", "create", dbName, ...cfg], dry && !detect ? `only if no database named ${dbName} exists` : undefined), `Creating the database ${dbName}`);
      if (!dry) {
        const again = must(await deps.run(["d1", "list", "--json", ...cfg], {}), "Listing your D1 databases");
        found = (parseJsonOutput(again.stdout, "[") ?? []).find((d) => d.name === dbName) ?? null;
        if (!found) throw new SetupError(`The database ${dbName} was created but doesn't show in the list yet. Run setup again in a minute.`);
        out(`  Created the database ${dbName}.`);
      }
    }
    if (found) {
      db.database_id = found.uuid ?? found.id;
      writeConfig();
    }
  }

  // 4. D1 migrations (wrangler applies only what's new; "No migrations to apply" when done).
  out("▸ D1 migrations");
  const mig = await change(["d1", "migrations", "apply", "DB", "--remote", ...cfg]);
  if (mig) {
    must(mig, "Applying the D1 migrations");
    out(/No migrations to apply/.test(mig.stdout + mig.stderr) ? "  Already up to date." : "  Applied.");
  }

  // 5. Secrets, before the deploy: a relay never runs without them. On a first install,
  // `wrangler secret put` makes an empty draft Worker to hold them, which answers nothing.
  out("▸ Secrets");
  let set = null;
  const listed = await readOnly(["secret", "list", ...roCfg, "--format", "json"]);
  if (listed) {
    if (listed.code === 0) {
      const arr = parseJsonOutput(listed.stdout, "[");
      if (!Array.isArray(arr)) throw new SetupError("Couldn't read the list of secrets wrangler printed. Nothing was changed; run setup again.");
      set = new Set(arr.map((s) => s.name));
    } else if (/not found/i.test(listed.stdout + listed.stderr) && new RegExp(`Worker "?${escapeRe(workerName)}"?`).test(listed.stdout + listed.stderr)) {
      set = new Set(); // no Worker yet: no secrets
    } else {
      // Anything else (auth, network): stop rather than take "unknown" for "unset" and rotate.
      throw new SetupError("Listing the Worker's secrets failed (output above). Nothing was replaced; fix that and run setup again.");
    }
  }
  const rotate = new Set(opts.rotate ?? []);
  // Questions that can't be asked fail now, before anything is set.
  if (!dry && !io.tty && !opts.skipPush && !opts.fromEnv && !opts.fromFile) {
    const pending = [APNS_REQUIRED, [FCM]].some((g) => !g.every((n) => set.has(n)) || g.some((n) => rotate.has(n)));
    if (pending) throw new SetupError("Setup asks for push keys in a terminal only. Without one, pass --from-env or --from-file <json>, or --skip-push.");
  }
  let signupToken = null;
  let finished = false;
  try {
    for (const name of GENERATED) {
      const isSet = set?.has(name);
      if (dry) {
        if (set === null) out(`  ${wranglerLine(["secret", "put", name, ...cfg], `<generated ${name}>`)}    # only if not set yet`);
        else if (!isSet || rotate.has(name)) out(`  ${wranglerLine(["secret", "put", name, ...cfg], `<generated ${name}>`)}${isSet ? "    # rotation, after you confirm" : ""}`);
        else out(`  ${name}: already set, kept`);
        continue;
      }
      if (isSet && !rotate.has(name)) {
        out(`  ${name}: already set, kept.`);
        continue;
      }
      if (isSet) await confirmRotation(name, io);
      const buf = generateSecret(name);
      if (name === "SIGNUP_TOKEN") {
        signupToken = Buffer.from(buf); // shown once at the end
      }
      await putSecret(deps, name, buf, cfg);
      out(`  ${name}: ${isSet ? "replaced" : "generated and set"}.`);
    }

    // Push: asked, optional.
    await askPush(opts, deps, set, rotate, cfg);

    // 6. Deploy.
    out("▸ Deploy");
    let url = opts.url ?? null;
    const dep = await change(["deploy", ...cfg]);
    if (dep) {
      must(dep, "Deploying");
      url ??= parseDeployUrl(dep.stdout + "\n" + dep.stderr);
      if (!url) throw new SetupError("Deployed, but couldn't find the relay's address in wrangler's output. Run `node relay/scripts/setup.mjs --check-only --url https://<your relay>`.");
      state = { ...state, url };
      writeConfig();
    }

    // 7. Check.
    out("▸ Check");
    if (dry) {
      out(`  GET ${url ?? "<relay URL>"}/v1/info    # protocol 2, relayKey set, signups need the token, push`);
      out("\nThe secrets setup would generate: SECRETS_KEY, HASH_PEPPER, RELAY_SIGNING_KEY, SIGNUP_TOKEN (those not set yet).");
      out("It would ask (each optional): APNS_KEY (.p8 file), APNS_KEY_ID, APNS_TEAM_ID, APNS_TOPIC, APNS_ENVIRONMENT; FCM_SERVICE_ACCOUNT (JSON file).");
      return { ok: true, dryRun: true };
    }
    const apnsExpected = APNS_REQUIRED.every((n) => set?.has(n) || deps.pushSet?.has(n));
    const result = await checkRelay(url, deps, { apnsExpected });
    printPairing(url, signupToken, deps, set?.has("SIGNUP_TOKEN") && !signupToken);
    finished = true;
    return result;
  } finally {
    // Stopped after the signup token was set: show it now, or it would be lost.
    if (!finished && signupToken) {
      out("");
      out("The signup token set in this run (keep it: it's shown only now, and needed to pair):");
      out(`    ${signupToken.toString("latin1")}`);
    }
    signupToken?.fill(0);
  }
}

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function chooseAccount(accounts, io) {
  if (!io.tty) throw new SetupError("You have several Cloudflare accounts. Pass --account <id>, or set CLOUDFLARE_ACCOUNT_ID.");
  io.print("  You have several Cloudflare accounts:");
  accounts.forEach((a, i) => io.print(`    ${i + 1}. ${a.name} (${a.id})`));
  for (;;) {
    const a = (await io.ask("  Which one gets the relay? Number: ")).trim();
    const n = Number(a);
    if (Number.isInteger(n) && n >= 1 && n <= accounts.length) return accounts[n - 1].id;
  }
}

async function confirmRotation(name, io) {
  if (!io.tty) throw new SetupError(`Replacing ${name} needs a confirmation typed in a terminal.`);
  io.print("");
  io.print(`  !! You asked to REPLACE ${name}.`);
  io.print(`  !! ${ROTATION_WARNINGS[name] ?? "The old value stops working."}`);
  const a = (await io.ask(`  Type ${name} to replace it, anything else to keep it: `)).trim();
  if (a !== name) throw new SetupError(`${name} was kept; nothing was replaced.`);
}

/** Pipes one secret to `wrangler secret put` on stdin, then zeroes it. */
async function putSecret(deps, name, buf, cfg) {
  try {
    const r = await deps.run(["secret", "put", name, ...cfg], { input: buf });
    if (r.code !== 0) {
      // Show wrangler's output only when it can't hold the secret.
      const outBuf = Buffer.from(`${r.stdout}\n${r.stderr}`);
      const leaks = secretParts(buf).some((p) => outBuf.includes(p));
      outBuf.fill(0);
      const detail = leaks ? "" : `\n${(r.stdout + "\n" + r.stderr).trim().split("\n").slice(-8).join("\n")}`;
      throw new SetupError(`Setting ${name} failed (wrangler exited with ${r.code}).${detail}\nRun setup again: secrets already set are kept.`);
    }
  } finally {
    buf.fill(0);
  }
}

/** The values of the asked secrets, from a terminal, the environment or a JSON file. */
async function askPush(opts, deps, set, rotate, cfg) {
  const { io } = deps;
  const out = (s) => io.print(s);
  const dry = !!opts.dryRun;
  deps.pushSet = new Set();
  const groups = [
    { label: "iPhone push (APNs)", names: APNS_ALL, required: APNS_REQUIRED, skip: "skip — push to iPhones won't be available" },
    { label: "Android push (FCM)", names: [FCM], required: [FCM], skip: "skip — push to Android phones won't be available" },
  ];
  for (const g of groups) {
    const done = set !== null && g.required.every((n) => set.has(n));
    const rot = g.names.some((n) => rotate.has(n));
    if (dry) {
      if (done && !rot) out(`  ${g.label}: already set, kept`);
      else for (const n of g.names) out(`  ${wranglerLine(["secret", "put", n, ...cfg], `<asked ${n}>`)}    # if you set up ${g.label}`);
      continue;
    }
    if (done && !rot) {
      out(`  ${g.label}: already set, kept.`);
      continue;
    }
    if (opts.skipPush) {
      out(`  ${g.label}: skipped (--skip-push); ${g.skip.replace(/^skip — /, "")}.`);
      continue;
    }
    const values = g.names === APNS_ALL ? await apnsValues(opts, deps, g) : await fcmValues(opts, deps, g);
    if (!values) continue;
    try {
      for (const [name, buf] of values) {
        await putSecret(deps, name, buf, cfg);
        deps.pushSet.add(name);
      }
      out(`  ${g.label}: set.`);
    } finally {
      for (const [, buf] of values) buf.fill(0);
    }
  }
}

function sourceValue(opts, deps, name) {
  if (opts.fromEnv) {
    const v = deps.env?.[name];
    return v === undefined || v === "" ? undefined : String(v);
  }
  if (opts.fromFile) {
    const v = deps.fromFileData?.[name];
    if (v === undefined || v === null || v === "") return undefined;
    return typeof v === "string" ? v : JSON.stringify(v);
  }
  return undefined;
}

function readSecretFile(deps, path, what) {
  const buf = deps.fs.readSecretFile(path);
  if (!buf) throw new SetupError(`Couldn't read ${what} at that path.`);
  return buf;
}

async function apnsValues(opts, deps, g) {
  const { io } = deps;
  const fail = (msg) => {
    throw new SetupError(msg);
  };
  if (opts.fromEnv || opts.fromFile) {
    const src = opts.fromEnv ? "the environment" : "the --from-file JSON";
    const keyText = sourceValue(opts, deps, "APNS_KEY");
    const keyFile = sourceValue(opts, deps, "APNS_KEY_FILE");
    const others = ["APNS_KEY_ID", "APNS_TEAM_ID", "APNS_TOPIC"].map((n) => sourceValue(opts, deps, n));
    const any = keyText || keyFile || others.some(Boolean);
    if (!any) {
      io.print(`  ${g.label}: not in ${src}; ${g.skip.replace(/^skip — /, "")}.`);
      return null;
    }
    if (!(keyText || keyFile) || others.some((v) => !v)) fail(`${g.label}: ${src} has only part of it. Give APNS_KEY_FILE (or APNS_KEY), APNS_KEY_ID, APNS_TEAM_ID and APNS_TOPIC, or none.`);
    const key = keyText ? Buffer.from(keyText) : readSecretFile(deps, keyFile, "the .p8 file");
    const values = [["APNS_KEY", key]];
    try {
      const e1 = checkApnsKey(key);
      if (e1) fail(`APNS_KEY: ${e1}`);
      const [keyId, teamId, topic] = others.map((v) => v.trim());
      const envName = (sourceValue(opts, deps, "APNS_ENVIRONMENT") ?? "production").trim();
      for (const e of [checkAppleId(keyId.toUpperCase(), "APNS_KEY_ID"), checkAppleId(teamId.toUpperCase(), "APNS_TEAM_ID"), checkTopic(topic), checkApnsEnvironment(envName)]) if (e) fail(e);
      values.push(["APNS_KEY_ID", Buffer.from(keyId.toUpperCase())], ["APNS_TEAM_ID", Buffer.from(teamId.toUpperCase())], ["APNS_TOPIC", Buffer.from(topic)], ["APNS_ENVIRONMENT", Buffer.from(envName)]);
      return values;
    } catch (e) {
      for (const [, b] of values) b.fill(0);
      throw e;
    }
  }
  if (!io.tty) throw new SetupError("Setup asks for push keys in a terminal only. Without one, pass --from-env or --from-file <json>, or --skip-push.");
  io.print(`  ${g.label}: needs the .p8 key file from your Apple developer account, its key id, your team id and the app's bundle id.`);
  const yes = await askChoice(io, `  Set up iPhone push now? [y] yes  [s] ${g.skip}: `);
  if (!yes) {
    io.print(`  ${g.label}: skipped.`);
    return null;
  }
  const values = [];
  try {
    values.push(["APNS_KEY", await askFile(io, deps, "  Path to the .p8 file: ", checkApnsKey)]);
    values.push(["APNS_KEY_ID", await askHiddenChecked(io, "  Key id (10 characters, hidden): ", (s) => checkAppleId(s, "The key id"), true)]);
    values.push(["APNS_TEAM_ID", await askHiddenChecked(io, "  Team id (10 characters, hidden): ", (s) => checkAppleId(s, "The team id"), true)]);
    values.push(["APNS_TOPIC", await askHiddenChecked(io, "  The app's bundle id (hidden): ", checkTopic, false)]);
    let envName = "";
    for (;;) {
      envName = (await io.ask("  APNs environment: sandbox (development builds) or production (TestFlight, App Store): ")).trim();
      const e = checkApnsEnvironment(envName);
      if (!e) break;
      io.print(`  ${e}`);
    }
    values.push(["APNS_ENVIRONMENT", Buffer.from(envName)]);
    return values;
  } catch (e) {
    for (const [, b] of values) b.fill(0);
    throw e;
  }
}

async function fcmValues(opts, deps, g) {
  const { io } = deps;
  if (opts.fromEnv || opts.fromFile) {
    const src = opts.fromEnv ? "the environment" : "the --from-file JSON";
    const text = sourceValue(opts, deps, FCM);
    const file = sourceValue(opts, deps, "FCM_SERVICE_ACCOUNT_FILE");
    if (!text && !file) {
      io.print(`  ${g.label}: not in ${src}; ${g.skip.replace(/^skip — /, "")}.`);
      return null;
    }
    const buf = text ? Buffer.from(text) : readSecretFile(deps, file, "the service account file");
    const e = checkFcmServiceAccount(buf);
    if (e) {
      buf.fill(0);
      throw new SetupError(`${FCM}: ${e}`);
    }
    return [[FCM, buf]];
  }
  if (!io.tty) throw new SetupError("Setup asks for push keys in a terminal only. Without one, pass --from-env or --from-file <json>, or --skip-push.");
  io.print(`  ${g.label}: needs your Firebase project's service account key file (JSON, from Google Cloud).`);
  const yes = await askChoice(io, `  Set up Android push now? [y] yes  [s] ${g.skip}: `);
  if (!yes) {
    io.print(`  ${g.label}: skipped.`);
    return null;
  }
  return [[FCM, await askFile(io, deps, "  Path to the service account JSON file: ", checkFcmServiceAccount)]];
}

async function askChoice(io, q) {
  for (;;) {
    const a = (await io.ask(q)).trim().toLowerCase();
    if (a === "y" || a === "yes") return true;
    if (a === "s" || a === "skip" || a === "n" || a === "no") return false;
  }
}

/** Asks for a file path (not a secret), reads the file and checks it; the contents are never shown. */
async function askFile(io, deps, q, check) {
  for (let tries = 0; ; tries++) {
    const path = (await io.ask(q)).trim().replace(/^['"]|['"]$/g, "");
    const buf = deps.fs.readSecretFile(path);
    const e = buf ? check(buf) : "Couldn't read a file at that path.";
    if (!e) return buf;
    buf?.fill(0);
    io.print(`  ${e}`);
    if (tries >= 4) throw new SetupError("Giving up on that file. Run setup again when you have it.");
  }
}

/** Hidden input, checked; the value is never echoed. Upper-cases Apple ids. */
async function askHiddenChecked(io, q, check, upper) {
  for (let tries = 0; ; tries++) {
    let buf = await io.askHidden(q);
    let t = buf.subarray(0, buf.length);
    // Trim ASCII whitespace in place.
    let a = 0;
    let b = t.length;
    while (a < b && t[a] <= 0x20) a++;
    while (b > a && t[b - 1] <= 0x20) b--;
    const v = Buffer.from(t.subarray(a, b));
    buf.fill(0);
    if (upper) for (let i = 0; i < v.length; i++) if (v[i] >= 0x61 && v[i] <= 0x7a) v[i] -= 0x20;
    // Ids and a bundle id: short, and checked as text.
    const e = check(v.toString("latin1"));
    if (!e) return v;
    v.fill(0);
    io.print(`  ${e}`);
    if (tries >= 4) throw new SetupError("Giving up. Run setup again.");
  }
}

// ─── Check and pairing ─────────────────────────────────────────────────────────────────────────────

/** `GET /v1/info`, retried while a fresh deployment comes up; prints what it found. */
export async function checkRelay(url, deps, { apnsExpected = false } = {}) {
  const { io } = deps;
  const base = url.replace(/\/+$/, "");
  let info = null;
  let lastErr = "";
  const tries = deps.checkTries ?? 8;
  for (let i = 0; i < tries; i++) {
    try {
      const r = await deps.fetch(`${base}/v1/info`, { headers: { accept: "application/json" } });
      if (r.ok) {
        info = await r.json();
        break;
      }
      lastErr = `it answered ${r.status}`;
    } catch (e) {
      lastErr = "it couldn't be reached";
    }
    if (i < tries - 1) await (deps.sleep ?? ((ms) => new Promise((res) => setTimeout(res, ms))))(Math.min(2000 * (i + 1), 10000));
  }
  if (!info) throw new SetupError(`The relay at ${base} didn't answer /v1/info (${lastErr}). A new workers.dev address can take a minute: try \`node relay/scripts/setup.mjs --check-only --url ${base}\`.`);
  const problems = [];
  const protocols = Array.isArray(info.protocols) ? info.protocols : [info.protocol];
  if (!protocols.includes(2)) problems.push(`it speaks protocol ${info.protocol}, not 2`);
  if (typeof info.relayKey !== "string" || !info.relayKey) problems.push("it has no relay signing key (RELAY_SIGNING_KEY isn't set or doesn't import): it takes no deliveries");
  if (info.signupOpen !== false) problems.push("signups are open to anyone (OPEN_SIGNUP=1 without SIGNUP_TOKEN)");
  const push = info.phone?.push ?? null;
  io.print(`  ${base}: version ${info.version ?? "?"}, protocol ${info.protocol}.`);
  io.print(`  Relay key: ${info.relayKey ? "set" : "MISSING"}. Signups: ${info.signupOpen === false ? "need the signup token" : "OPEN"}.`);
  if (push) {
    const extra = Object.entries(push)
      .filter(([k]) => k !== "available" && k !== "environment")
      .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`);
    io.print(`  Push to iPhones: ${push.available ? `available (${push.environment})` : "not available"}${extra.length ? `; ${extra.join(", ")}` : ""}.`);
    if (apnsExpected && !push.available) problems.push("the APNs secrets are set but push isn't available: check the key, ids and topic");
  }
  if (problems.length) {
    for (const p of problems) io.print(`  ✗ ${p}`);
    throw new SetupError("The relay is deployed but not ready. Run setup again to finish it.");
  }
  io.print("  ✓ Ready.");
  return { ok: true, url: base, info };
}

function printPairing(url, token, deps, tokenWasSetBefore) {
  const { io } = deps;
  const base = url.replace(/\/+$/, "");
  io.print("");
  io.print(`The relay is running at ${base}`);
  io.print("");
  if (token) {
    io.print("Signup token (shown only now; nothing on this computer keeps it):");
    io.print("");
    io.print(`    ${token.toString("latin1")}`);
    io.print("");
  } else if (tokenWasSetBefore) {
    io.print("The signup token was set by an earlier run and can't be read back. Lost it? Make a new one:");
    io.print("    node relay/scripts/setup.mjs --rotate SIGNUP_TOKEN");
    io.print("");
  }
  io.print("Pair this computer with the 00hooks CLI (paste the token after the first line, then Enter):");
  io.print("    read -rs HOOKS_SIGNUP_TOKEN && export HOOKS_SIGNUP_TOKEN");
  io.print(`    00hooks login --relay ${base}; unset HOOKS_SIGNUP_TOKEN`);
  io.print(`  (\`00hooks login --relay ${base} --signup-token <token>\` works too, but your shell history keeps the token.)`);
  io.print(`Pair 00next: Settings › Automations › Relay ${base}, and the signup token above.`);
  io.print("Rotate the signup token (existing accounts keep working): node relay/scripts/setup.mjs --rotate SIGNUP_TOKEN");
  io.print("Relay status any time: node relay/scripts/setup.mjs --check-only");
}

// ─── Arguments ─────────────────────────────────────────────────────────────────────────────────────

export const HELP = `Install the 00hooks relay on your own Cloudflare account.

  pnpm --filter ./relay setup            (or: node relay/scripts/setup.mjs [options])

Uses your own \`wrangler login\`. Creates the D1 database 00hooks, writes relay/wrangler.deploy.jsonc,
applies the migrations, generates and sets the secrets, deploys and checks /v1/info. Run it again any
time: it continues where it stopped, keeps secrets already set, and carries config upgrades over.

Options:
  --dry-run             print every step; run, generate, ask and write nothing
  --detect              with --dry-run: also run read-only wrangler checks (login, databases, secrets)
  --check-only          only check a deployed relay (GET /v1/info): "relay status"
  --url <url>           the relay's address, when wrangler's output doesn't say it (custom domains)
  --account <id>        the Cloudflare account, when you have several
  --ratelimit-base <n>  derive the Rate Limiting namespace ids from n (n+1, n+2, …)
  --rotate <NAME>       replace a secret that's already set (asks you to confirm); repeatable
  --skip-push           don't ask for the APNs / FCM push keys
  --from-env            read push keys from the environment instead of asking (no terminal needed):
                        APNS_KEY_FILE (or APNS_KEY), APNS_KEY_ID, APNS_TEAM_ID, APNS_TOPIC,
                        APNS_ENVIRONMENT, FCM_SERVICE_ACCOUNT_FILE (or FCM_SERVICE_ACCOUNT)
  --from-file <json>    the same names, from a JSON file
  --var NAME=VALUE      a non-secret setting for the config's vars (RETENTION_DAYS, quotas, …)
  --help
`;

export function parseArgs(argv) {
  const opts = { rotate: [], vars: {} };
  const take = (i, flag) => {
    const v = argv[i + 1];
    if (v === undefined || v.startsWith("--")) throw new SetupError(`${flag} needs a value.`);
    return v;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--":
        break;
      case "--dry-run":
        opts.dryRun = true;
        break;
      case "--detect":
        opts.detect = true;
        break;
      case "--check-only":
        opts.checkOnly = true;
        break;
      case "--skip-push":
        opts.skipPush = true;
        break;
      case "--from-env":
        opts.fromEnv = true;
        break;
      case "--help":
      case "-h":
        opts.help = true;
        break;
      case "--url": {
        const u = take(i++, a);
        if (!/^https?:\/\/[^\s/]+/.test(u)) throw new SetupError("--url takes the relay's address, like https://relay.example.com.");
        opts.url = u.replace(/\/+$/, "");
        break;
      }
      case "--account":
        opts.account = take(i++, a);
        if (!/^[0-9a-f]{32}$/i.test(opts.account)) throw new SetupError("--account takes a Cloudflare account id (32 hex characters).");
        break;
      case "--ratelimit-base":
        opts.ratelimitBase = parseRatelimitBase(take(i++, a));
        break;
      case "--rotate": {
        const n = take(i++, a);
        if (!GENERATED.includes(n) && !ASKED.includes(n)) throw new SetupError(`--rotate takes one of ${[...GENERATED, ...ASKED].join(", ")}.`);
        opts.rotate.push(n);
        break;
      }
      case "--from-file":
        opts.fromFile = take(i++, a);
        break;
      case "--var": {
        const v = take(i++, a);
        const m = /^([A-Z_]+)=(.*)$/s.exec(v);
        if (!m || !SETTINGS.has(m[1])) throw new SetupError(`--var takes NAME=VALUE for a setting (${[...SETTINGS].join(", ")}); secrets are never set this way.`);
        opts.vars[m[1]] = m[2];
        break;
      }
      default:
        // Never echo an unknown argument: it might be a secret pasted in the wrong place.
        throw new SetupError("Unknown argument (not shown). Secrets are never passed on the command line; see --help.");
    }
  }
  if (opts.detect && !opts.dryRun) throw new SetupError("--detect goes with --dry-run.");
  if (opts.fromEnv && opts.fromFile) throw new SetupError("Use --from-env or --from-file, not both.");
  return opts;
}
