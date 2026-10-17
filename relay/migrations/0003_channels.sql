-- Webhook channels (PROTOCOL §3, §4a): Meta's verify token and a hook's offline notice.

-- Meta's verify token, kept only as HMAC-SHA256 under HASH_PEPPER of the hook id and the token.
-- The GET handshake (`hub.mode=subscribe`) is answered only when the token it carries hashes to it.
ALTER TABLE hooks ADD COLUMN handshake_token_hash TEXT;

-- The offline notice as JSON `{ "text", "afterMinutes" }`: what the relay answers, at most once a day
-- per sender, while no device stream has been connected for that long. Null: none.
ALTER TABLE hooks ADD COLUMN offline_notice TEXT;
