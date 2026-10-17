// The idle-cost script's parsing and arithmetic, against recorded-shape fixtures. The real run is
// against a deployed relay (docs/IDLE-COST.md).

import { describe, expect, it } from "vitest";
import {
  PRICING,
  backoffMs,
  buildQuery,
  computeCost,
  formatReport,
  parseAnalytics,
  parseArgs,
  slices,
} from "../scripts/idle-cost-lib.ts";
import awake from "./fixtures/analytics-awake.json";
import errors from "./fixtures/analytics-errors.json";
import idle from "./fixtures/analytics-idle.json";

describe("idle-cost arguments", () => {
  it("parses the documented invocation, with pnpm's `--`", () => {
    expect(parseArgs(["--", "--relay", "https://relay.example/", "--connections", "10", "--hours", "24"])).toEqual({
      relay: "https://relay.example",
      connections: 10,
      hours: 24,
    });
    expect(parseArgs(["--relay=http://localhost:8787", "--hours=0.5"])).toMatchObject({ connections: 1, hours: 0.5 });
    const a = parseArgs(["--relay", "https://r.example", "--start", "2026-10-01T00:00:00Z", "--end", "2026-10-02T00:00:00Z"]);
    expect(a.analyzeOnly?.end.toISOString()).toBe("2026-10-02T00:00:00.000Z");
  });

  it("refuses bad input", () => {
    expect(() => parseArgs([])).toThrow(/--relay/);
    expect(() => parseArgs(["--relay", "http://relay.example"])).toThrow(/https/);
    expect(() => parseArgs(["--relay", "https://r.example", "--connections", "0"])).toThrow(/connections/);
    expect(() => parseArgs(["--relay", "https://r.example", "--hours", "-1"])).toThrow(/hours/);
    expect(() => parseArgs(["--relay", "https://r.example", "--bogus", "1"])).toThrow(/unknown/);
    expect(() => parseArgs(["--relay", "https://r.example", "--namespace-id", "xyz"])).toThrow(/namespace/);
    expect(() => parseArgs(["--relay", "https://r.example", "--start", "2026-10-02T00:00:00Z", "--end", "2026-10-01T00:00:00Z"])).toThrow(
      /end after start/,
    );
  });
});

describe("idle-cost analytics", () => {
  it("builds a query for the window, filtered by namespace when given", () => {
    const q = buildQuery("0123456789abcdef0123456789abcdef", new Date("2026-10-01T00:00:00Z"), new Date("2026-10-02T00:00:00Z"), "f".repeat(32));
    expect(q).toContain('accountTag: "0123456789abcdef0123456789abcdef"');
    expect(q).toContain('datetimeMinute_geq: "2026-10-01T00:00:00.000Z", datetimeMinute_lt: "2026-10-02T00:00:00.000Z"');
    expect(q).toContain(`namespaceId: "${"f".repeat(32)}"`);
    expect(q).toContain("activeTime");
    expect(() => buildQuery("not-an-account", new Date(), new Date())).toThrow();
  });

  it("splits long windows into day-sized slices", () => {
    const s = slices(new Date("2026-10-01T00:00:00Z"), new Date("2026-10-03T06:00:00Z"));
    expect(s.map((x) => [x.start.toISOString(), x.end.toISOString()])).toEqual([
      ["2026-10-01T00:00:00.000Z", "2026-10-02T00:00:00.000Z"],
      ["2026-10-02T00:00:00.000Z", "2026-10-03T00:00:00.000Z"],
      ["2026-10-03T00:00:00.000Z", "2026-10-03T06:00:00.000Z"],
    ]);
  });

  it("sums the groups of an answer", () => {
    expect(parseAnalytics(idle)).toEqual({
      activeTimeUs: 2_000_000,
      cpuTimeUs: 40_000,
      inboundWebsocketMsgs: 28_800,
      outboundWebsocketMsgs: 0,
      requests: 30,
    });
  });

  it("surfaces the API's errors", () => {
    expect(() => parseAnalytics(errors)).toThrow(/unknown field "activeTime"/);
    expect(() => parseAnalytics({ data: {} })).toThrow(/unexpected/);
  });
});

describe("idle-cost arithmetic", () => {
  it("prices an idle bridge near zero and calls it hibernating", () => {
    // 10 connections for 24 h, 2 s awake in all.
    const r = computeCost(parseAnalytics(idle), 10, 24);
    const scale = 730 / 24 / 10;
    expect(r.perConnectionMonth.activeSeconds).toBeCloseTo(2 * scale, 9);
    expect(r.perConnectionMonth.durationGbS).toBeCloseTo(2 * scale * 0.128, 9);
    expect(r.perConnectionMonth.durationUsd).toBeCloseTo((2 * scale * 0.128 * 12.5) / 1e6, 12);
    expect(r.perConnectionMonth.requests).toBeCloseTo(30 * scale, 9);
    expect(r.perConnectionMonth.requestsUsd).toBeCloseTo((30 * scale * 0.15) / 1e6, 12);
    expect(r.verdict).toBe("hibernates");
    expect(formatReport(r)).toContain("The bridge works");
  });

  it("prices an object that never slept at the always-awake baseline (~$4.20 a month)", () => {
    const r = computeCost(parseAnalytics(awake), 1, 1);
    expect(r.awakeBaseline.durationGbS).toBeCloseTo(730 * 3600 * 0.128, 6);
    expect(r.awakeBaseline.durationUsd).toBeCloseTo(4.2048, 4);
    expect(r.perConnectionMonth.durationUsd).toBeCloseTo(4.2048, 4);
    expect(r.awakeFraction).toBeCloseTo(1, 9);
    expect(r.verdict).toBe("always-awake");
    expect(formatReport(r)).toContain("does NOT hibernate");
  });

  it("calls a partly awake object inconclusive", () => {
    const r = computeCost({ activeTimeUs: 0.1 * 3_600_000_000, cpuTimeUs: 0, inboundWebsocketMsgs: 0, outboundWebsocketMsgs: 0, requests: 0 }, 1, 1);
    expect(r.verdict).toBe("partly-awake");
  });

  it("uses the published prices", () => {
    expect(PRICING).toEqual({ requestUsdPerMillion: 0.15, durationUsdPerMillionGbS: 12.5, gbPerObject: 0.128, incomingWebSocketMessagesPerRequest: 20 });
  });

  it("backs off between half and all of min(30 s, retry × 2^attempt), never under 1 s", () => {
    expect(backoffMs(0, () => 0)).toBe(2500);
    expect(backoffMs(0, () => 1)).toBe(5000);
    expect(backoffMs(1, () => 0)).toBe(5000);
    expect(backoffMs(2, () => 0.5)).toBe(15_000);
    expect(backoffMs(10, () => 0)).toBe(15_000);
    expect(backoffMs(10, () => 1)).toBe(30_000);
    expect(backoffMs(0, () => 0, 1000)).toBe(1000);
  });
});
