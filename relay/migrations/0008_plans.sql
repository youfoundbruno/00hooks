-- Plans and entitlements (PROTOCOL §2a, §2b). Every new column is null (or its default) for existing
-- rows, which keeps them on the `default` plan: a self-hosted relay sees no change.

-- The account's plan (null: `default`), when it ends (an entitlement's `exp`, ms; null: never), the
-- Overblast workspace it was entitled through (one account per workspace), and a per-account
-- override of the plan's limits (JSON, the keys of PLANS).
ALTER TABLE accounts ADD COLUMN plan TEXT;
ALTER TABLE accounts ADD COLUMN plan_until INTEGER;
ALTER TABLE accounts ADD COLUMN entitlement_ws TEXT;
ALTER TABLE accounts ADD COLUMN limits TEXT;
CREATE UNIQUE INDEX accounts_entitlement_ws ON accounts(entitlement_ws) WHERE entitlement_ws IS NOT NULL;

-- A hook paused after a flood of refused deliveries is answered 429 from this row until then, without
-- waking the account's object. `on_limit`: what a delivery past the daily cap gets.
ALTER TABLE hooks ADD COLUMN paused_until INTEGER;
ALTER TABLE hooks ADD COLUMN on_limit TEXT NOT NULL DEFAULT 'refuse';

-- Hooks created per account per UTC day (the plan's `hookCreatesPerDay`), counted with the insert.
CREATE TABLE hook_creates (
  account_id TEXT NOT NULL,
  day INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (account_id, day)
);
CREATE INDEX hook_creates_day ON hook_creates(day);
