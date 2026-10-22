// Secrets aren't in wrangler.jsonc, so `wrangler types` can't see them. Merged into the generated
// base interface, so both `Env` and `Cloudflare.Env` carry them.
interface __BaseEnv_Env {
  /** AES-256-GCM key (32 bytes, base64) sealing hook secrets at rest. */
  SECRETS_KEY: string;
  /** HMAC key for enrolment-code and IP hashes. */
  HASH_PEPPER: string;
  /**
   * The relay's Ed25519 signing key: a 32-byte seed, base64. It signs every sealed envelope; its
   * public half is published at `/v1/info` and pinned by clients at login.
   */
  RELAY_SIGNING_KEY?: string;
  /** When set, account creation needs `Authorization: Bearer <SIGNUP_TOKEN>`. */
  SIGNUP_TOKEN?: string;
  /** "1": signups need no token. Without it and without SIGNUP_TOKEN, signups are refused (403). */
  OPEN_SIGNUP?: string;
  /** Node devices (not phones) one account may have; 10 when unset. */
  ACCOUNT_MAX_DEVICES?: string;
  /** One verified hook's share of the account's log (PROTOCOL §4); half the account's when unset. */
  HOOK_MAX_EVENTS?: string;
  HOOK_MAX_BYTES?: string;
  /** One strict or unverified hook's share; a sixteenth of the account's when unset. */
  UNCHECKED_HOOK_MAX_EVENTS?: string;
  UNCHECKED_HOOK_MAX_BYTES?: string;
  /** What the screen may hold per hook, apart from the log (PROTOCOL §4b); 200 events, 16 MiB when unset. */
  HELD_MAX_EVENTS?: string;
  HELD_MAX_BYTES?: string;
  /** Days body-hash replay marks are kept for presets that sign no timestamp; 180 when unset. */
  REPLAY_MARK_DAYS?: string;
  /** How many days the screen holds an event before dropping it (PROTOCOL §4b); 7 when unset. */
  SCREEN_HELD_DAYS?: string;
  /**
   * Optional hosted extras this relay offers, as JSON (PROTOCOL §2, `/v1/info` `extras`): a list of
   * `{ "id", "title", "description"?, "url"? }`. A self-hosted relay leaves it unset.
   */
  HOSTED_EXTRAS?: string;
  /**
   * Plans (PROTOCOL §2a): a JSON object mapping a plan's name to its limits (`hooks`, `devices`,
   * `eventsPerDay`, `hookRatePerMin`, `hookBurst`, `accountRatePerMin`, `accountBurst`,
   * `retentionHours`, `maxBodyBytes`, `backlogEvents`, `backlogBytes`, `hookCreatesPerDay`; null is
   * no limit, a key left out takes the `default` plan's value). Unset: one plan, `default`, equal to
   * the relay's behaviour before plans. Malformed: the relay refuses deliveries (503) rather than
   * guess.
   */
  PLANS?: string;
  /**
   * Overblast entitlements (PROTOCOL §2b): a JSON array of base64url raw Ed25519 public keys (32
   * bytes each; several, for rotation). Unset: the relay takes no entitlements.
   */
  ENTITLEMENT_PUBLIC_KEYS?: string;
  /** Days an entitlement's plan keeps working past its `exp`; 7 when unset. */
  ENTITLEMENT_GRACE_DAYS?: string;
  /** The plan an account falls back to once its entitlement ran out; `suspended` when unset. */
  ENTITLEMENT_FALLBACK_PLAN?: string;
  /**
   * How to get the hosted plan, as JSON `{ "plan", "title", "description"?, "url"? }`, announced as
   * data in `/v1/info` and `/v1/account`. A self-hosted relay leaves it unset.
   */
  HOSTED_PLAN?: string;
  /** Refusals (rate or daily) of one hook within `PAUSE_WINDOW_MINUTES` that pause it; 500 when unset, 0 never pauses. */
  PAUSE_AFTER_REFUSALS?: string;
  /** The window those refusals are counted in; 10 minutes when unset. */
  PAUSE_WINDOW_MINUTES?: string;
  /** Phone links (PROTOCOL §10): rows a node's queue may hold before a phone's send is refused; 1000 when unset. */
  PHONE_NODE_QUEUE_MAX?: string;
  /** Rows a phone's queue may hold before the oldest are dropped; 500 when unset. */
  PHONE_PHONE_QUEUE_MAX?: string;
  /** Bytes one device's queue may hold, either way; 16 MiB when unset. */
  PHONE_QUEUE_MAX_BYTES?: string;
  /** Pushes one phone may be sent in a rolling hour (PROTOCOL §10.7); 30 when unset. */
  PHONE_PUSH_PER_HOUR?: string;
  /**
   * The APNs signing key (PROTOCOL §10.7): the contents of the `.p8` file Apple gives, a PKCS#8 PEM of
   * a P-256 key, BEGIN and END lines included (surrounding whitespace and `\n` escapes are fine).
   * Push is available only with this, `APNS_KEY_ID`, `APNS_TEAM_ID` and `APNS_TOPIC` all set.
   */
  APNS_KEY?: string;
  /** The APNs key's 10-character key id. */
  APNS_KEY_ID?: string;
  /** The Apple developer team's 10-character id. */
  APNS_TEAM_ID?: string;
  /** The phone app's bundle id, sent as `apns-topic`. */
  APNS_TOPIC?: string;
  /** `sandbox` or `production` (the default when unset): which APNs host pushes go to. */
  APNS_ENVIRONMENT?: string;
}
