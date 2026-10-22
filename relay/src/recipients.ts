// Who receives a hook's events (PROTOCOL §3): every device (null), a list of devices, the devices
// carrying a tag, or both at once (their union). Device tags are short labels set with
// `PATCH /v1/devices/<id>` `{ "tags" }`.
//
// D1 holds the target (`hooks.recipients`) and the tags (`devices.tags`) for the API; the account's
// Durable Object keeps a copy of each device's tags and resolves the target against its own device
// rows when an event arrives, so the devices an event is sealed to are decided in the same step that
// seals it. A target that matches no active device with a sealing key pauses the hook
// (`paused_reason = 'no_recipient'`) rather than seal to nobody or fall back to every device.

import { accountStub } from "./auth.ts";
import { isId } from "./encoding.ts";
import { HttpError, error, invalid } from "./http.ts";
import { accountPlan } from "./hooks.ts";

/** A hook's target: devices by id, and tags; a device that matches either receives the events. */
export interface Recipients {
  devices: string[];
  tags: string[];
}

/** At most this many devices in a target: the default device cap. */
export const MAX_TARGET_DEVICES = 10;
export const MAX_TARGET_TAGS = 10;
export const MAX_DEVICE_TAGS = 10;
export const MAX_TAG_LENGTH = 32;
/** Lowercase letters and digits, with `.`, `_` or `-` inside: shown in terminals, typed in commands. */
export const TAG_PATTERN = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;

/** How long a sender is asked to wait while a hook has no recipient. */
export const NO_RECIPIENT_RETRY_S = 300;

function field(name: string, message: string): never {
  throw new HttpError(invalid(name, message));
}

/** A list of tags from a request: unique, each a valid label, at most `max`. */
export function parseTags(raw: unknown, name: string, max: number): string[] {
  if (!Array.isArray(raw)) field(name, `${name} must be a list of tags.`);
  const out: string[] = [];
  for (const t of raw) {
    if (typeof t !== "string" || t.length > MAX_TAG_LENGTH || !TAG_PATTERN.test(t)) {
      field(
        name,
        `A tag is 1 to ${MAX_TAG_LENGTH} lowercase letters, digits, '.', '_' or '-', starting and ending with a letter or digit.`,
      );
    }
    if (!out.includes(t)) out.push(t);
  }
  if (out.length > max) field(name, `${name} takes at most ${max} tags.`);
  return out;
}

/** Tags as stored (a JSON array, or null). Anything unreadable is no tags. */
export function tagsOf(stored: string | null | undefined): string[] {
  if (!stored) return [];
  try {
    const v = JSON.parse(stored) as unknown;
    return Array.isArray(v) ? v.filter((t): t is string => typeof t === "string") : [];
  } catch {
    return [];
  }
}

/** A hook row's target: its `recipients`, else its one `deliver_to` device (0009), else null. */
export function recipientsOf(row: { recipients?: string | null; deliver_to?: string | null }): Recipients | null {
  if (row.recipients) {
    try {
      const v = JSON.parse(row.recipients) as Partial<Recipients>;
      return {
        devices: Array.isArray(v.devices) ? v.devices.filter((d): d is string => typeof d === "string") : [],
        tags: Array.isArray(v.tags) ? v.tags.filter((t): t is string => typeof t === "string") : [],
      };
    } catch {
      // Unreadable: treated as a target that matches nobody, never as every device.
      return { devices: [], tags: [] };
    }
  }
  return row.deliver_to ? { devices: [row.deliver_to], tags: [] } : null;
}

/** `deliverTo` as clients before recipients read it: the one device of a one-device target, else null. */
export function deliverToOf(r: Recipients | null): string | null {
  return r !== null && r.devices.length === 1 && r.tags.length === 0 ? r.devices[0]! : null;
}

/** Whether a device is one of a target's recipients. */
export function matches(r: Recipients, device: { id: string; tags: string[] }): boolean {
  return r.devices.includes(device.id) || device.tags.some((t) => r.tags.includes(t));
}

/** How a target is named in the audit: `*` for every device, else its devices and `#tags`. */
export function auditName(r: Recipients | null): string {
  if (r === null) return "*";
  return [...r.devices, ...r.tags.map((t) => `#${t}`)].join(",") || "-";
}

/** The account's active node devices that can be listed in a target: those with a sealing key. */
async function targetableDevices(env: Env, accountId: string): Promise<Set<string>> {
  const { results } = await env.DB.prepare(
    "SELECT id FROM devices WHERE account_id = ? AND kind = 'device' AND revoked_at IS NULL AND seal_key IS NOT NULL",
  )
    .bind(accountId)
    .all<{ id: string }>();
  return new Set(results.map((r) => r.id));
}

/**
 * The target a PATCH sets, or undefined when it sets none. `deliverTo` (a device id, or null) is
 * the one-device form clients before recipients send; `recipients` (`{ devices?, tags? }`, or null)
 * the general one. Both at once are refused. Every listed device must be an active node device of
 * the account with a sealing key (a device without one could read nothing sealed to it); a tag need
 * not match any device yet (the hook is paused until one does).
 */
export async function parseTarget(env: Env, accountId: string, input: Record<string, unknown>): Promise<Recipients | null | undefined> {
  const hasOne = input.deliverTo !== undefined;
  const hasMany = input.recipients !== undefined;
  if (hasOne && hasMany) field("recipients", "Send deliverTo or recipients, not both.");
  if (hasOne) {
    const raw = input.deliverTo;
    if (raw === null) return null;
    if (typeof raw !== "string" || !isId("dev", raw)) field("deliverTo", "deliverTo must be a device id, or null for every device.");
    if (!(await targetableDevices(env, accountId)).has(raw)) {
      field("deliverTo", "deliverTo must be an active device of this account that has a sealing key.");
    }
    return { devices: [raw], tags: [] };
  }
  if (!hasMany) return undefined;
  const raw = input.recipients;
  if (raw === null) return null;
  if (typeof raw !== "object" || Array.isArray(raw)) field("recipients", "recipients must be { devices, tags }, or null for every device.");
  const v = raw as Record<string, unknown>;
  for (const k of Object.keys(v)) if (k !== "devices" && k !== "tags") field("recipients", "recipients takes only devices and tags.");
  const devices: string[] = [];
  if (v.devices !== undefined) {
    if (!Array.isArray(v.devices)) field("recipients.devices", "recipients.devices must be a list of device ids.");
    for (const d of v.devices) {
      if (typeof d !== "string" || !isId("dev", d)) field("recipients.devices", "recipients.devices must be a list of device ids.");
      if (!devices.includes(d)) devices.push(d);
    }
    if (devices.length > MAX_TARGET_DEVICES) field("recipients.devices", `recipients.devices takes at most ${MAX_TARGET_DEVICES} devices.`);
  }
  const tags = v.tags === undefined ? [] : parseTags(v.tags, "recipients.tags", MAX_TARGET_TAGS);
  if (devices.length === 0 && tags.length === 0) {
    field("recipients", "recipients needs at least one device or tag; send null for every device.");
  }
  if (devices.length > 0) {
    const ok = await targetableDevices(env, accountId);
    if (devices.some((d) => !ok.has(d))) {
      field("recipients.devices", "Every device in recipients must be an active device of this account that has a sealing key.");
    }
  }
  return { devices, tags };
}

/** The answer to a delivery while its hook has no recipient (PROTOCOL §4, step 2a). */
export function noRecipientAnswer(): Response {
  return error(
    503,
    "unavailable",
    "This hook has no device to deliver to; deliveries resume once one of its recipients is back.",
    { scope: "no_recipient" },
    { "Retry-After": String(NO_RECIPIENT_RETRY_S) },
  );
}

interface TargetRow {
  id: string;
  recipients: string | null;
  deliver_to: string | null;
  paused_reason: string | null;
}

/**
 * Brings the account's targeted hooks in step with its devices (all of them, or `hookId` alone):
 * devices that are gone (revoked) leave the lists; a hook whose target matches no active device
 * with a sealing key is paused (`no_recipient`), and one paused so whose target matches again
 * resumes. Run after anything that changes who matches: a target, tags, a revocation, a sealing key.
 */
export async function syncRecipients(env: Env, accountId: string, actor: string | null, hookId?: string): Promise<void> {
  const { results: hooks } = await env.DB.prepare(
    `SELECT id, recipients, deliver_to, paused_reason FROM hooks WHERE account_id = ?1
       AND (recipients IS NOT NULL OR deliver_to IS NOT NULL OR paused_reason IS NOT NULL) AND (?2 IS NULL OR id = ?2)`,
  )
    .bind(accountId, hookId ?? null)
    .all<TargetRow>();
  if (hooks.length === 0) return;
  const { results: live } = await env.DB.prepare(
    "SELECT id, tags, seal_key IS NOT NULL AS sealed FROM devices WHERE account_id = ? AND kind = 'device' AND revoked_at IS NULL",
  )
    .bind(accountId)
    .all<{ id: string; tags: string | null; sealed: number }>();
  const devices = live.map((d) => ({ id: d.id, tags: tagsOf(d.tags), sealed: d.sealed === 1 }));
  const stub = accountStub(env, accountId);
  let planName: string | null = null;
  for (const h of hooks) {
    const before = recipientsOf(h);
    const after = before === null ? null : { devices: before.devices.filter((id) => devices.some((d) => d.id === id)), tags: before.tags };
    const reachable = after === null || devices.some((d) => d.sealed && matches(after, d));
    const reason = reachable ? (h.paused_reason === "no_recipient" ? null : h.paused_reason) : "no_recipient";
    const stored = after === null ? null : JSON.stringify(after);
    if (stored === h.recipients && deliverToOf(after) === h.deliver_to && reason === h.paused_reason) continue;
    await env.DB.prepare("UPDATE hooks SET recipients = ?, deliver_to = ?, paused_reason = ? WHERE id = ?")
      .bind(stored, deliverToOf(after), reason, h.id)
      .run();
    if (reason !== h.paused_reason) {
      planName ??= (await accountPlan(env, accountId, Date.now())).name;
      await stub.recipientPause(h.id, reason === "no_recipient", actor, planName);
    }
  }
}
