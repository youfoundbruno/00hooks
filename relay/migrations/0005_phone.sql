-- Phone links (PROTOCOL §10): a phone is a device of kind `phone`, paired with one node device
-- (`peer`), limited to the phone routes. It is pending (it may open its socket and unpair itself,
-- not send) until that node confirms it; `pending_until` is null once confirmed.
ALTER TABLE devices ADD COLUMN kind TEXT NOT NULL DEFAULT 'device';
ALTER TABLE devices ADD COLUMN peer TEXT;
ALTER TABLE devices ADD COLUMN pending_until INTEGER;
CREATE INDEX devices_peer ON devices(peer);

-- One-time pairings a node registers before showing its pairing code. The relay keeps only the
-- verifier (SHA-256 of the proof the phone will show); the pairing secret never reaches it.
CREATE TABLE phone_pairings (
  id TEXT PRIMARY KEY,               -- the pairingId (22 base64url characters)
  account_id TEXT NOT NULL REFERENCES accounts(id),
  device_id TEXT NOT NULL,           -- the node device that made it
  verifier TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE INDEX phone_pairings_account ON phone_pairings(account_id, expires_at);
