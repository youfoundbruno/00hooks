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
  /**
   * Android push (PROTOCOL §10.7): the Firebase project's service-account key, the whole JSON file
   * Google gives (`type` `service_account`, `project_id`, `client_email`, and `private_key`, a PKCS#8
   * PEM of an RSA key). Android push is available only when it parses and the key imports.
   */
  FCM_SERVICE_ACCOUNT?: string;
}
