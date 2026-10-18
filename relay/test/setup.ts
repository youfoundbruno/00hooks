import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach } from "vitest";
import { resetEdgeCounts } from "../src/edge-counts.ts";

await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);

// Counts at the edge are written at once in tests (production batches them per minute); the batching
// itself is tested with the production interval.
beforeEach(() => resetEdgeCounts(0));
