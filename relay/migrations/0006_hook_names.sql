-- Hook names are unique per account (PROTOCOL §3): an automation that names a hook resolves the name
-- to one id, and no one with `hooks:write` can make a second hook answer to an existing name.
--
-- Existing duplicates keep their oldest holder's name; the others get their id appended, so the
-- index can be created and nothing is lost.
UPDATE hooks SET name = substr(name, 1, 60) || ' (' || id || ')'
WHERE rowid NOT IN (SELECT min(rowid) FROM hooks GROUP BY account_id, name);

CREATE UNIQUE INDEX hooks_account_name ON hooks(account_id, name);

-- Expiry indexes for the daily cleanup (the scheduled handler): rows past their use are deleted.
CREATE INDEX enrolments_expires ON enrolments(expires_at);
CREATE INDEX enrolment_failures_window ON enrolment_failures(window_start);
CREATE INDEX phone_pairings_expires ON phone_pairings(expires_at);
