// Accounts, devices and enrolments (PROTOCOL §2).

import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { normalizeCode } from "../src/accounts.ts";
import { generateDeviceKey } from "../src/canonical.ts";
import { enrolDevice, fetchRelay, newAccount, signed } from "./helpers.ts";

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
    expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
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
      const res = await redeem("ZZZZ-ZZZZ", ip);
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
    expect(JSON.stringify(row)).not.toContain(code.replace("-", ""));
  });

  it("normalizes codes the Crockford way", () => {
    expect(normalizeCode("abcd-efgh")).toBe("ABCDEFGH");
    expect(normalizeCode("o1il 0000")).toBe("01110000");
    expect(normalizeCode("ABCD-EFGU")).toBeNull();
    expect(normalizeCode("ABC")).toBeNull();
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
    expect((await signed(dev, "DELETE", `/v1/devices/${second.deviceId}`)).status).toBe(404);
    expect((await signed(second, "GET", "/v1/devices")).status).toBe(401);
    const { devices } = (await (await signed(dev, "GET", "/v1/devices")).json()) as { devices: { id: string }[] };
    expect(devices.map((d) => d.id)).toEqual([dev.deviceId]);
  });
});
