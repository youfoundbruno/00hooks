// What a webhook costs the account's Durable Object in SQLite rows (relay/docs/COSTS.md), measured
// with the object's own per-query counters. Rows written are most of a self-hosted relay's bill past
// the $5 plan, so these bounds keep a change from raising them unnoticed: if one must, raise the
// bound here and the numbers in COSTS.md and the README together.

import { describe, expect, it } from "vitest";
import { duplicateScenario, heldScenario, webhookScenario, type Rows } from "./costs.ts";

/** Upper bounds, per scenario and step: rows written (setAlarm included), and rows read. */
const BOUNDS = {
  oneDevice: { append: { written: 21, read: 60 }, acks: { written: 12, read: 80 }, alarm: { written: 4, read: 60 }, total: { written: 36, read: 180 } },
  threeDevices: { append: { written: 27, read: 70 }, acks: { written: 26, read: 220 }, alarm: { written: 6, read: 60 }, total: { written: 58, read: 320 } },
  rateLimited: { append: { written: 23, read: 70 }, acks: { written: 12, read: 80 }, alarm: { written: 4, read: 60 }, total: { written: 38, read: 190 } },
  duplicate: { written: 0, read: 5 },
  held: { written: 15, read: 50 },
};

function within(name: string, got: Rows, bound: { written: number; read: number }): void {
  // Shown with `--reporter=verbose`: the numbers COSTS.md quotes.
  console.log(`${name}: ${got.written} rows written, ${got.read} read`);
  expect({ name, written: got.written <= bound.written, read: got.read <= bound.read, got: { written: got.written, read: got.read } }).toEqual({
    name,
    written: true,
    read: true,
    got: { written: got.written, read: got.read },
  });
}

describe("rows per webhook (COSTS.md)", () => {
  it("one device: a GitHub delivery, its ack, and the alarm that prunes after it", async () => {
    const s = await webhookScenario();
    for (const k of ["append", "acks", "alarm", "total"] as const) within(`1 device, ${k}`, s[k], BOUNDS.oneDevice[k]);
  });

  it("three devices", async () => {
    const s = await webhookScenario({ devices: 3 });
    for (const k of ["append", "acks", "alarm", "total"] as const) within(`3 devices, ${k}`, s[k], BOUNDS.threeDevices[k]);
  });

  it("a plan with a hook rate, an account rate and a daily cap", async () => {
    const s = await webhookScenario({ plan: { hookRatePerMin: 600, accountRatePerMin: 6000, eventsPerDay: 100_000 } });
    for (const k of ["append", "acks", "alarm", "total"] as const) within(`rate limits, ${k}`, s[k], BOUNDS.rateLimited[k]);
  });

  it("a duplicate writes nothing", async () => {
    within("duplicate", await duplicateScenario(), BOUNDS.duplicate);
  });

  it("a held delivery", async () => {
    within("held", await heldScenario(), BOUNDS.held);
  });
});
