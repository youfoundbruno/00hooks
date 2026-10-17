-- Phase 1: devices publish an X25519 sealing key (PROTOCOL §2), and API keys (PROTOCOL §9).

-- The device's sealing public key (raw X25519, base64url) and its id. Events are sealed to it.
ALTER TABLE devices ADD COLUMN seal_key TEXT;
ALTER TABLE devices ADD COLUMN seal_kid TEXT;

-- API keys for management and CI. Only a salted hash of the secret is kept (HMAC-SHA256 under
-- HASH_PEPPER over the salt and the secret); the token is shown once, when the key is created.
CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  name TEXT NOT NULL,
  scopes TEXT NOT NULL,
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);
CREATE INDEX api_keys_account ON api_keys(account_id);
