-- Accounts, devices, hooks, enrolments: everything that isn't the event log. The log, cursors,
-- nonces and dedupe marks live in each account's Durable Object.

CREATE TABLE accounts (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  name TEXT NOT NULL,
  -- Raw Ed25519 public key, base64url. Unique: one key is one device.
  public_key TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER,
  revoked_at INTEGER
);
CREATE INDEX devices_account ON devices(account_id);

-- The routing from a hook id to its account, and how to verify it. Secrets are sealed
-- (AES-256-GCM under SECRETS_KEY, the hook id as associated data), never stored in plain text.
CREATE TABLE hooks (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  verify TEXT NOT NULL,
  secret_sealed TEXT,
  previous_secret_sealed TEXT,
  previous_secret_until INTEGER,
  max_body_bytes INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_event_at INTEGER
);
CREATE INDEX hooks_account ON hooks(account_id);

-- One-time codes for adding a device. Only an HMAC of the code (under HASH_PEPPER) is stored.
CREATE TABLE enrolments (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  code_hash TEXT NOT NULL UNIQUE,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);

-- Failed redemptions per client IP (an HMAC of the IP, not the IP).
CREATE TABLE enrolment_failures (
  ip_hash TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  failures INTEGER NOT NULL,
  blocked_until INTEGER
);
