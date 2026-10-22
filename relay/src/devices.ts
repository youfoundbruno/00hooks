// Renaming and tagging a device (PROTOCOL §2): `PATCH /v1/devices/<id>` `{ "name"?, "tags"? }`.

import { accountStub, type Principal } from "./auth.ts";
import { HttpError, invalid, json, notFound, parseJsonObject } from "./http.ts";
import { MAX_DEVICE_TAGS, parseTags, syncRecipients, tagsOf } from "./recipients.ts";

/** A device's name: 1 to 100 characters once trimmed, no control characters (it is shown in terminals). */
function newName(v: unknown): string {
  const name = typeof v === "string" ? v.trim() : "";
  if (name.length < 1 || name.length > 100 || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new HttpError(invalid("name", "name must be 1 to 100 characters, without control characters."));
  }
  return name;
}

interface DeviceRow {
  id: string;
  name: string;
  created_at: number;
  last_seen_at: number | null;
  seal_kid: string | null;
  kind: string;
  peer: string | null;
  tags: string | null;
}

/** A device as `GET /v1/devices` lists it. */
export function deviceJson(d: DeviceRow, caller: Principal) {
  return {
    id: d.id,
    name: d.name,
    createdAt: d.created_at,
    lastSeenAt: d.last_seen_at,
    current: d.id === caller.deviceId,
    sealKid: d.seal_kid,
    kind: d.kind,
    peer: d.peer,
    tags: tagsOf(d.tags),
  };
}

/**
 * Renames one of the account's devices (a node device or a phone) and/or replaces a node device's
 * tags, by a device of the account or an API key with `devices:write`. A revoked device, or a phone
 * whose pairing ran out unconfirmed, is gone: `404`, as for another account's. Tags are what hooks'
 * targets match (src/recipients.ts): the account's object gets them first (it routes by them), then
 * D1, and every targeted hook is brought in step (paused or resumed). Answers the device as
 * `GET /v1/devices` lists it.
 */
export async function patchDevice(env: Env, caller: Principal, deviceId: string, body: Uint8Array): Promise<Response> {
  const input = parseJsonObject(body);
  if (input.name === undefined && input.tags === undefined) {
    throw new HttpError(invalid("name", "Send name, tags, or both."));
  }
  const name = input.name === undefined ? null : newName(input.name);
  const tags = input.tags === undefined ? null : parseTags(input.tags, "tags", MAX_DEVICE_TAGS);
  const now = Date.now();
  const found = await env.DB.prepare(
    `SELECT id, kind, tags FROM devices WHERE id = ? AND account_id = ? AND revoked_at IS NULL AND (pending_until IS NULL OR pending_until > ?)`,
  )
    .bind(deviceId, caller.accountId, now)
    .first<{ id: string; kind: string; tags: string | null }>();
  if (!found) return notFound();
  if (tags !== null && found.kind !== "device") {
    throw new HttpError(invalid("tags", "Only a computer (a device of kind device) can carry tags; a phone receives no hook events."));
  }
  const stub = accountStub(env, caller.accountId);
  const tagsChanged = tags !== null && JSON.stringify(tags) !== JSON.stringify(tagsOf(found.tags));
  if (tagsChanged) await stub.setDeviceTags(deviceId, tags);
  const row = await env.DB.prepare(
    `UPDATE devices SET name = coalesce(?, name), tags = CASE WHEN ? THEN ? ELSE tags END WHERE id = ? AND account_id = ?
     RETURNING id, name, created_at, last_seen_at, seal_kid, kind, peer, tags`,
  )
    .bind(name, tagsChanged ? 1 : 0, tags && tags.length > 0 ? JSON.stringify(tags) : null, deviceId, caller.accountId)
    .first<DeviceRow>();
  if (!row) return notFound();
  if (name !== null) await stub.audit({ kind: "device.renamed", actor: caller.actor, subject: deviceId, name });
  if (tagsChanged) {
    await stub.audit({ kind: "device.tagged", actor: caller.actor, subject: deviceId, name: tags.length > 0 ? tags.join(",") : "-" });
    await syncRecipients(env, caller.accountId, caller.actor);
  }
  return json({ device: deviceJson(row, caller) });
}
