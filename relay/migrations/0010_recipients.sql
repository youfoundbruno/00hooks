-- Recipients (PROTOCOL §3): a hook can go to every device (null), to a list of devices, to the
-- devices carrying a tag, or to both at once (their union).
--
-- `devices.tags`: short labels on a node device, as a JSON array (null: none).
-- `hooks.recipients`: `{ "devices": [...], "tags": [...] }` as JSON (null: every device). A hook that
-- named one device (`deliver_to`, 0009) keeps it as a one-device list; `deliver_to` stays in step
-- for that case, so a relay rolled back to the earlier code still routes it.
-- `hooks.paused_reason`: `no_recipient` while the target matches no active device with a sealing
-- key: deliveries are refused (503) from this row, without waking the account's object, until a
-- device matches again or the target changes.
ALTER TABLE devices ADD COLUMN tags TEXT;
ALTER TABLE hooks ADD COLUMN recipients TEXT;
ALTER TABLE hooks ADD COLUMN paused_reason TEXT;
UPDATE hooks SET recipients = json_object('devices', json_array(deliver_to), 'tags', json_array())
  WHERE deliver_to IS NOT NULL;
