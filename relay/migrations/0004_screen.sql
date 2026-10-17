-- The screen at the edge (PROTOCOL §4b): a hook's rules as JSON, pushed by a device. Field values
-- are keyed hashes in it; words appear only for rules the person agreed to send (`consent.words`).
ALTER TABLE hooks ADD COLUMN screen TEXT;
