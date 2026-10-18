// The push hook of the phone links (PROTOCOL §10.7). Kept out of index.ts: the main module may export
// only handlers and Durable Object classes.

/** What a push would say about an envelope: a category, never content. */
export type PushCategory = "approval" | "message" | "notice";

export const PUSH_CATEGORIES: readonly PushCategory[] = ["approval", "message", "notice"];

/**
 * Called by `PhoneObject` when it queues an envelope that carries `push` for a phone whose socket
 * isn't connected. It does nothing yet: sending through APNs needs the operator's Apple developer
 * account and key, and the phone's device token, which it will register with the relay (never with
 * its node) through a signed `PUT /v1/phone/push`. When it is built it sends a fixed alert text per
 * category, with `mutable-content` so the phone opens the sealed envelope itself; at most one push
 * per category per phone per minute, and none while the phone's socket is open. It is given the
 * device id and the category only: the envelope is never passed to it.
 */
export async function pushHook(_env: Env, _deviceId: string, _category: PushCategory): Promise<void> {
  // Not built (see above).
}
