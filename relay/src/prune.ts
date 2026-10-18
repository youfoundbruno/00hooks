// The daily cleanup of D1 (the `scheduled` handler, wrangler.jsonc `triggers.crons`): rows that are
// past their use are deleted, so the tables that grow with traffic (one failure row per guessing
// address, one row per enrolment or pairing) don't grow forever.

/** Rows are kept this long past their expiry, for anyone reading them back. */
export const KEEP_PAST_EXPIRY_MS = 24 * 3600_000;
/** Revoked or expired API keys are kept this long (they're listed nowhere; the audit names them). */
export const KEEP_DEAD_KEYS_MS = 90 * 24 * 3600_000;

export async function pruneD1(env: Env, now: number): Promise<void> {
  const old = now - KEEP_PAST_EXPIRY_MS;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM enrolments WHERE expires_at < ?").bind(old),
    env.DB.prepare("DELETE FROM enrolment_failures WHERE window_start < ? AND coalesce(blocked_until, 0) < ?").bind(old, now),
    env.DB.prepare("DELETE FROM phone_pairings WHERE expires_at < ?").bind(old),
    env.DB.prepare(
      "DELETE FROM api_keys WHERE (revoked_at IS NOT NULL AND revoked_at < ?1) OR expires_at < ?1",
    ).bind(now - KEEP_DEAD_KEYS_MS),
  ]);
}
