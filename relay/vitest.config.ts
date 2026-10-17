import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// Tests run inside workerd (Miniflare): the Worker, the Durable Object with its SQLite storage,
// alarms, WebSockets, D1 and the Rate Limiting binding are all real.
export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      main: "./src/index.ts",
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          // Test-only values; real ones come from `wrangler secret put` (see .dev.vars.example).
          SECRETS_KEY: "dGVzdC1vbmx5LWtleS10ZXN0LW9ubHkta2V5LTAwMDA=",
          HASH_PEPPER: "test-only-pepper",
          TEST_MIGRATIONS: await readD1Migrations("./migrations"),
        },
      },
    })),
  ],
  test: {
    setupFiles: ["./test/setup.ts"],
  },
});
