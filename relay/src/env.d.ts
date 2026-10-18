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
}
