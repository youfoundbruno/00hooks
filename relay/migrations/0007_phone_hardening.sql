-- Phone links, hardened (PROTOCOL §10.1): wrong proofs counted per pairing. The fifth wrong proof
-- burns the pairing (not even the right proof redeems it after), and a burned pairing no longer
-- counts as open.
ALTER TABLE phone_pairings ADD COLUMN failures INTEGER NOT NULL DEFAULT 0;
