// Secrets aren't in wrangler.jsonc, so `wrangler types` can't see them. Merged into the generated
// base interface, so both `Env` and `Cloudflare.Env` carry them.
interface __BaseEnv_Env {
  /** AES-256-GCM key (32 bytes, base64) sealing hook secrets at rest. */
  SECRETS_KEY: string;
  /** HMAC key for enrolment-code and IP hashes. */
  HASH_PEPPER: string;
  /** When set, account creation needs `Authorization: Bearer <SIGNUP_TOKEN>`. */
  SIGNUP_TOKEN?: string;
}
