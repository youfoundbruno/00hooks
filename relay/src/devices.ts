// Renaming a device (PROTOCOL §2): `PATCH /v1/devices/<id>` `{ "name" }`.

import { accountStub, type Principal } from "./auth.ts";
import { HttpError, invalid, json, notFound, parseJsonObject } from "./http.ts";

/** A device's name: 1 to 100 characters once trimmed, no control characters (it is shown in terminals). */
function newName(v: unknown): string {
  const name = typeof v === "string" ? v.trim() : "";
  if (name.length < 1 || name.length > 100 || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new HttpError(invalid("name", "name must be 1 to 100 characters, without control characters."));
  }
  return name;
}

/**
 * Renames one of the account's devices (a node device or a phone), by a device of the account or an
 * API key with `devices:write`. A revoked device, or a phone whose pairing ran out unconfirmed, is
 * gone: `404`, as for another account's. Answers the device as `GET /v1/devices` lists it.
 */
export async function renameDevice(env: Env, caller: Principal, deviceId: string, body: Uint8Array): Promise<Response> {
  const name = newName(parseJsonObject(body).name);
  const now = Date.now();
  const row = await env.DB.prepare(
    `UPDATE devices SET name = ? WHERE id = ? AND account_id = ? AND revoked_at IS NULL AND (pending_until IS NULL OR pending_until > ?)
     RETURNING id, name, created_at, last_seen_at, seal_kid, kind, peer`,
  )
    .bind(name, deviceId, caller.accountId, now)
    .first<{ id: string; name: string; created_at: number; last_seen_at: number | null; seal_kid: string | null; kind: string; peer: string | null }>();
  if (!row) return notFound();
  await accountStub(env, caller.accountId).audit({ kind: "device.renamed", actor: caller.actor, subject: deviceId, name });
  return json({
    device: {
      id: row.id,
      name: row.name,
      createdAt: row.created_at,
      lastSeenAt: row.last_seen_at,
      current: row.id === caller.deviceId,
      sealKid: row.seal_kid,
      kind: row.kind,
      peer: row.peer,
    },
  });
}
