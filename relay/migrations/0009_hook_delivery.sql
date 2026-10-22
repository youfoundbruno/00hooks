-- How a hook's deliveries are answered and to whom they go (PROTOCOL §3):
-- `deliver_to`: one device of the account that alone receives the hook's events (null: every device),
-- so an automation doesn't run on two machines. `static_response`: a fixed answer for the provider
-- (`{ "status", "contentType", "body" }` as JSON; null: the usual `{"received": …}`).
ALTER TABLE hooks ADD COLUMN deliver_to TEXT;
ALTER TABLE hooks ADD COLUMN static_response TEXT;
