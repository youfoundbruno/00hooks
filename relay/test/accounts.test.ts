// Accounts, devices and enrolments (PROTOCOL §2).

import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { newCode, normalizeCode, redeemEnrolment } from "../src/accounts.ts";
import { generateDeviceKey } from "../src/canonical.ts";
import { utf8 } from "../src/encoding.ts";
import { expandIpv6, ipKey } from "../src/ip.ts";
import { BASE, enrolDevice, fetchRelay, newAccount, openStream, randomTestIp, signed } from "./helpers.ts";

async function redeem(code: string, ip = "198.51.100.7") {
  const { publicKey } = await generateDeviceKey();
  return fetchRelay("/v1/enrolments/redeem", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip },
    body: JSON.stringify({ code, deviceName: "new", publicKey }),
  });
}

describe("accounts", () => {
  it("creates an account with its first device", async () => {
    const dev = await newAccount();
    expect(dev.accountId).toMatch(/^acc_[0-9a-z]{26}$/);
    expect(dev.deviceId).toMatch(/^dev_[0-9a-z]{26}$/);
  });

  it("validates the input and refuses a public key that's already a device", async () => {
    const post = (body: unknown) =>
      fetchRelay("/v1/accounts", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const { publicKey } = await generateDeviceKey();
    const missingName = await post({ publicKey });
    expect(missingName.status).toBe(400);
    expect(await missingName.json()).toMatchObject({ error: "invalid", field: "deviceName" });
    const badKey = await post({ deviceName: "x", publicKey: "AAAA" });
    expect(await badKey.json()).toMatchObject({ error: "invalid", field: "publicKey" });
    expect((await post({ deviceName: "x", publicKey })).status).toBe(201);
    const again = await post({ deviceName: "y", publicKey });
    expect(again.status).toBe(409);
    expect(await again.json()).toMatchObject({ error: "conflict" });
    const notJson = await fetchRelay("/v1/accounts", { method: "POST", body: "{" });
    expect(await notJson.json()).toMatchObject({ error: "invalid", field: "body" });
  });
});

describe("enrolments", () => {
  it("adds a device to the same account with a one-time code", async () => {
    const dev = await newAccount();
    const res = await signed(dev, "POST", "/v1/enrolments");
    expect(res.status).toBe(200);
    const { code, expiresAt } = (await res.json()) as { code: string; expiresAt: number };
    // 12 Crockford base32 characters: 60 bits.
    expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
    expect(expiresAt - Date.now()).toBeGreaterThan(9 * 60_000);
    expect(expiresAt - Date.now()).toBeLessThanOrEqual(10 * 60_000);

    const ok = await redeem(code.toLowerCase());
    expect(ok.status).toBe(200);
    const added = (await ok.json()) as { accountId: string; deviceId: string };
    expect(added.accountId).toBe(dev.accountId);
    expect(added.deviceId).not.toBe(dev.deviceId);

    // One time only.
    const again = await redeem(code);
    expect(again.status).toBe(401);
  });

  it("refuses an expired code", async () => {
    const dev = await newAccount();
    const { code } = (await (await signed(dev, "POST", "/v1/enrolments")).json()) as { code: string };
    await env.DB.prepare("UPDATE enrolments SET expires_at = ? WHERE account_id = ?").bind(Date.now() - 1, dev.accountId).run();
    expect((await redeem(code, "198.51.100.8")).status).toBe(401);
  });

  it("blocks an IP for 10 minutes after five wrong codes, even for a right one", async () => {
    const dev = await newAccount();
    const { code } = (await (await signed(dev, "POST", "/v1/enrolments")).json()) as { code: string };
    const ip = "203.0.113.50";
    for (let i = 0; i < 5; i++) {
      const res = await redeem("ZZZZ-ZZZZ-ZZZZ", ip);
      expect(res.status).toBe(401);
    }
    const blocked = await redeem(code, ip);
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("Retry-After"))).toBeGreaterThan(500);
    expect(await blocked.json()).toMatchObject({ error: "rate_limited" });
    // Another address is unaffected, and the code is still unused.
    expect((await redeem(code, "203.0.113.51")).status).toBe(200);
    // Only a hash of the IP is stored.
    const rows = await env.DB.prepare("SELECT ip_hash FROM enrolment_failures").all<{ ip_hash: string }>();
    expect(JSON.stringify(rows.results)).not.toContain(ip);
  });

  it("stores only a hash of the code", async () => {
    const dev = await newAccount();
    const { code } = (await (await signed(dev, "POST", "/v1/enrolments")).json()) as { code: string };
    const row = await env.DB.prepare("SELECT * FROM enrolments WHERE account_id = ?").bind(dev.accountId).first();
    expect(JSON.stringify(row)).not.toContain(code);
    expect(JSON.stringify(row)).not.toContain(code.replaceAll("-", ""));
  });

  it("normalizes codes the Crockford way", () => {
    expect(normalizeCode("abcd-efgh-jkmn")).toBe("ABCDEFGHJKMN");
    expect(normalizeCode("o1il 0000 1111")).toBe("011100001111");
    expect(normalizeCode("ABCD-EFGH-JKMU")).toBeNull();
    // The old 8-character form is too short now.
    expect(normalizeCode("ABCD-EFGH")).toBeNull();
    expect(normalizeCode("ABC")).toBeNull();
  });

  it("makes codes of 60 random bits", () => {
    const codes = new Set(Array.from({ length: 200 }, () => newCode()));
    expect(codes.size).toBe(200);
    for (const c of codes) expect(normalizeCode(c)).toHaveLength(12);
  });

  it("counts parallel wrong guesses one by one (the count is atomic, before the code is checked)", async () => {
    const dev = await newAccount();
    const { code } = (await (await signed(dev, "POST", "/v1/enrolments")).json()) as { code: string };
    const ip = randomTestIp();
    const statuses = (await Promise.all(Array.from({ length: 8 }, () => redeem("ZZZZ-ZZZZ-ZZZZ", ip)))).map((r) => r.status);
    expect(statuses.filter((s) => s === 401)).toHaveLength(5);
    expect(statuses.filter((s) => s === 429)).toHaveLength(3);
    expect((await redeem(code, ip)).status).toBe(429);
  });

  it("counts an IPv6 client by its /64", async () => {
    const dev = await newAccount();
    const { code } = (await (await signed(dev, "POST", "/v1/enrolments")).json()) as { code: string };
    for (let i = 1; i <= 5; i++) expect((await redeem("ZZZZ-ZZZZ-ZZZZ", `2001:db8:7:9::${i}`)).status).toBe(401);
    expect((await redeem(code, "2001:db8:7:9:ffff:1:2:3")).status).toBe(429);
    expect((await redeem(code, "2001:db8:7:a::1")).status).toBe(200);
  });

  it("a right code doesn't count against the address", async () => {
    const dev = await newAccount();
    const ip = randomTestIp();
    for (let i = 0; i < 4; i++) expect((await redeem("ZZZZ-ZZZZ-ZZZZ", ip)).status).toBe(401);
    for (let i = 0; i < 3; i++) {
      const { code } = (await (await signed(dev, "POST", "/v1/enrolments")).json()) as { code: string };
      expect((await redeem(code, ip)).status).toBe(200);
    }
    expect((await redeem("ZZZZ-ZZZZ-ZZZZ", ip)).status).toBe(401);
    expect((await redeem("ZZZZ-ZZZZ-ZZZZ", ip)).status).toBe(429);
  });

  it("rate limits redemptions per address with the Rate Limiting binding", async () => {
    // The binding counts in wall-clock-aligned 60 s windows: start early in one.
    const intoWindow = Date.now() % 60_000;
    if (intoWindow > 50_000) await new Promise((r) => setTimeout(r, 60_000 - intoWindow + 50));
    const ip = randomTestIp();
    const post = () =>
      fetchRelay("/v1/enrolments/redeem", { method: "POST", headers: { "CF-Connecting-IP": ip }, body: "not json" });
    // Bodies that don't parse never reach the code check, but they do spend the address's budget.
    for (let i = 0; i < 10; i++) expect((await post()).status).toBe(400);
    const limited = await post();
    expect(limited.status).toBe(429);
    expect(await limited.json()).toMatchObject({ error: "rate_limited" });
  }, 20_000);

  it("rate limits redemptions globally, and fails closed without the bindings", async () => {
    const body = utf8(JSON.stringify({ code: "ZZZZ-ZZZZ-ZZZZ", deviceName: "x", publicKey: (await generateDeviceKey()).publicKey }));
    const req = () => new Request(`${BASE}/v1/enrolments/redeem`, { method: "POST", headers: { "CF-Connecting-IP": randomTestIp() } });
    const no = { limit: async () => ({ success: false }) } as unknown as RateLimit;
    const global = await redeemEnrolment(req(), { ...env, REDEEM_GLOBAL_LIMIT: no } as Env, body);
    expect(global.status).toBe(429);
    for (const missing of ["REDEEM_IP_LIMIT", "REDEEM_GLOBAL_LIMIT"] as const) {
      const res = await redeemEnrolment(req(), { ...env, [missing]: undefined } as unknown as Env, body);
      expect(res.status).toBe(503);
    }
  });
});

describe("devices", () => {
  it("lists the account's devices and marks the current one", async () => {
    const dev = await newAccount("laptop");
    const second = await enrolDevice(dev, "desktop");
    const res = await signed(second, "GET", "/v1/devices");
    const { devices } = (await res.json()) as { devices: { id: string; name: string; current: boolean; createdAt: number; lastSeenAt: number | null }[] };
    expect(devices.map((d) => [d.name, d.current])).toEqual([
      ["laptop", false],
      ["desktop", true],
    ]);
    expect(devices[0]!.createdAt).toBeTypeOf("number");
  });

  it("revokes a device, which then can't sign; other accounts' devices are not found", async () => {
    const dev = await newAccount();
    const second = await enrolDevice(dev);
    const stranger = await newAccount();
    expect((await signed(stranger, "DELETE", `/v1/devices/${second.deviceId}`)).status).toBe(404);
    expect((await signed(dev, "DELETE", `/v1/devices/${second.deviceId}`)).status).toBe(204);
    // Idempotent: revoking again finishes the job (and changes nothing more).
    expect((await signed(dev, "DELETE", `/v1/devices/${second.deviceId}`)).status).toBe(204);
    expect((await signed(second, "GET", "/v1/devices")).status).toBe(401);
    const { devices } = (await (await signed(dev, "GET", "/v1/devices")).json()) as { devices: { id: string }[] };
    expect(devices.map((d) => d.id)).toEqual([dev.deviceId]);
  });

  it("a retry finishes a revocation that failed part-way: the open stream still closes with 4401", async () => {
    const dev = await newAccount();
    const second = await enrolDevice(dev);
    const { sse } = await openStream(second);
    expect((await sse.next())?.retry).toBe(5000);
    expect((await sse.nextEvent())?.event).toBe("ready");
    // A previous attempt marked D1 revoked, then failed before the Durable Object heard of it.
    await env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE id = ?").bind(Date.now(), second.deviceId).run();
    expect((await signed(dev, "DELETE", `/v1/devices/${second.deviceId}`)).status).toBe(204);
    const closed = await sse.nextEvent();
    expect(closed?.event).toBe("closed");
    expect(JSON.parse(closed!.data!)).toEqual({ code: 4401, reason: "device revoked" });
  });
});

describe("client addresses", () => {
  it("keys IPv4 as is and IPv6 by its /64", () => {
    expect(ipKey("203.0.113.9")).toBe("203.0.113.9");
    expect(ipKey("2001:db8:1:2:3:4:5:6")).toBe("2001:db8:1:2::/64");
    expect(ipKey("2001:DB8:1:2::9")).toBe("2001:db8:1:2::/64");
    expect(ipKey("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(ipKey("::1")).toBe("0:0:0:0::/64");
    expect(ipKey("::ffff:198.51.100.7")).toBe("198.51.100.7");
    expect(ipKey(null)).toBe("unknown");
    expect(ipKey("")).toBe("unknown");
    expect(expandIpv6("1::2::3")).toBeNull();
    expect(expandIpv6("1:2:3:4:5:6:7:8:9")).toBeNull();
    expect(expandIpv6("fe80::1%en0")).toEqual([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
  });
});
