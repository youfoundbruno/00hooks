// Overblast entitlements (PROTOCOL §2b): signed by a pinned key, for this audience and subject, one
// account per workspace; a lapsed plan falls back to `suspended`, which keeps the backlog readable.

import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { generateDeviceKey } from "../src/canonical.ts";
import { toBase64Url, utf8 } from "../src/encoding.ts";
import { createHook, newAccount, newSealPair, openStream, signed, data, type TestDevice } from "./helpers.ts";
import { call, post, signedWith, withVars } from "./plan-helpers.ts";

const PLANS = JSON.stringify({ overblast: { eventsPerDay: 1000, hooks: 3 } });

interface Issuer {
  privateKey: CryptoKey;
  publicKey: string;
}

async function newIssuer(): Promise<Issuer> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
  return { privateKey: pair.privateKey, publicKey: toBase64Url(raw) };
}

/** An entitlement as the issuing side makes it (the shared contract). */
async function issue(issuer: Issuer, payload: Record<string, unknown>): Promise<string> {
  const p = toBase64Url(utf8(JSON.stringify(payload)));
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", issuer.privateKey, utf8(`ent1.${p}`)));
  return `ent1.${p}.${toBase64Url(sig)}`;
}

const nowS = () => Math.floor(Date.now() / 1000);

function payload(sub: Record<string, string>, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    iss: "overblast",
    aud: "00hooks",
    ws: `ws_${crypto.randomUUID()}`,
    sub,
    plan: "overblast",
    iat: nowS(),
    exp: nowS() + 35 * 86400,
    jti: crypto.randomUUID(),
    ...over,
  };
}

async function signupWith(
  e: Env,
  token: string | undefined,
  given?: { privateKey: CryptoKey; publicKey: string } | string,
): Promise<{ res: Response; dev: TestDevice | null }> {
  const key = typeof given === "object" ? given : await generateDeviceKey();
  const publicKey = typeof given === "string" ? given : undefined;
  const seal = await newSealPair();
  const res = await call(e, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ deviceName: "mac", publicKey: publicKey ?? key.publicKey, sealKey: seal.text, ...(token ? { entitlement: token } : {}) }),
  });
  if (res.status !== 201) return { res, dev: null };
  const body = (await res.clone().json()) as { accountId: string; deviceId: string };
  return { res, dev: { ...body, privateKey: key.privateKey, publicKey: key.publicKey, seal } };
}

describe("entitlements", () => {
  it("create an account on the entitled plan without the signup token", async () => {
    const issuer = await newIssuer();
    // Signups otherwise closed: the token is what lets this one in.
    const e = withVars({ PLANS, ENTITLEMENT_PUBLIC_KEYS: JSON.stringify([issuer.publicKey]), OPEN_SIGNUP: undefined, SIGNUP_TOKEN: "s3cret" });
    const key = await generateDeviceKey();
    const p = payload({ dev: key.publicKey });
    const { res } = await signupWith(e, await issue(issuer, p), key.publicKey);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { accountId: string; plan: string; planUntil: number };
    expect(body.plan).toBe("overblast");
    expect(body.planUntil).toBe((p.exp as number) * 1000);
    const row = await env.DB.prepare("SELECT plan, plan_until, entitlement_ws FROM accounts WHERE id = ?").bind(body.accountId).first();
    expect(row).toEqual({ plan: "overblast", plan_until: (p.exp as number) * 1000, entitlement_ws: p.ws });
    // Without one, the signup token is still needed.
    expect((await signupWith(e, undefined)).res.status).toBe(401);
    expect(((await (await call(e, "/v1/info")).json()) as { entitlements: boolean }).entitlements).toBe(true);
  });

  it("refuses a token that is forged, for another audience or device, expired, or for an unknown plan", async () => {
    const issuer = await newIssuer();
    const other = await newIssuer();
    const e = withVars({ PLANS, ENTITLEMENT_PUBLIC_KEYS: JSON.stringify([issuer.publicKey]) });
    const key = await generateDeviceKey();
    const tryWith = async (token: string, pk = key.publicKey) => (await signupWith(e, token, pk)).res;
    const cases: [string, string][] = [
      ["another issuer's key", await issue(other, payload({ dev: key.publicKey }))],
      ["wrong audience", await issue(issuer, payload({ dev: key.publicKey }, { aud: "elsewhere" }))],
      ["wrong issuer", await issue(issuer, payload({ dev: key.publicKey }, { iss: "someone" }))],
      ["wrong version", await issue(issuer, payload({ dev: key.publicKey }, { v: 2 }))],
      ["expired", await issue(issuer, payload({ dev: key.publicKey }, { iat: nowS() - 100, exp: nowS() - 1 }))],
      ["from the future", await issue(issuer, payload({ dev: key.publicKey }, { iat: nowS() + 3600 }))],
      ["unknown plan", await issue(issuer, payload({ dev: key.publicKey }, { plan: "platinum" }))],
      ["bad limits", await issue(issuer, payload({ dev: key.publicKey }, { limits: { hooks: -5 } }))],
      ["an account subject at signup", await issue(issuer, payload({ acc: "acc_0123456789abcdefghjkmnpqrs" }))],
      ["two subjects", await issue(issuer, payload({ dev: key.publicKey, acc: "acc_0123456789abcdefghjkmnpqrs" }))],
      ["not a token", "ent1.e30"],
      ["padded", (await issue(issuer, payload({ dev: key.publicKey }))) + "="],
    ];
    for (const [what, token] of cases) {
      const res = await tryWith(token);
      expect([what, res.status]).toEqual([what, 403]);
    }
    // Another device's key.
    const someone = await generateDeviceKey();
    const res = await tryWith(await issue(issuer, payload({ dev: someone.publicKey })));
    expect(res.status).toBe(403);
    // A tampered payload.
    const good = await issue(issuer, payload({ dev: key.publicKey }));
    const [, p, s] = good.split(".");
    const tampered = `ent1.${toBase64Url(utf8(JSON.stringify({ ...payload({ dev: key.publicKey }), plan: "overblast", exp: nowS() + 999 * 86400 })))}.${s}`;
    expect(p).not.toBe(tampered.split(".")[1]);
    expect((await tryWith(tampered)).status).toBe(403);
  });

  it("a relay without ENTITLEMENT_PUBLIC_KEYS takes none", async () => {
    const issuer = await newIssuer();
    const key = await generateDeviceKey();
    const { res } = await signupWith(withVars({ PLANS }), await issue(issuer, payload({ dev: key.publicKey })), key.publicKey);
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid", field: "entitlement" });
  });

  it("accepts any pinned key, for rotation", async () => {
    const old = await newIssuer();
    const fresh = await newIssuer();
    const e = withVars({ PLANS, ENTITLEMENT_PUBLIC_KEYS: JSON.stringify([old.publicKey, fresh.publicKey]) });
    for (const issuer of [old, fresh]) {
      const key = await generateDeviceKey();
      expect((await signupWith(e, await issue(issuer, payload({ dev: key.publicKey })), key.publicKey)).res.status).toBe(201);
    }
  });

  it("binds a workspace to one account, at signup and on refresh", async () => {
    const issuer = await newIssuer();
    const e = withVars({ PLANS, ENTITLEMENT_PUBLIC_KEYS: JSON.stringify([issuer.publicKey]) });
    const k1 = await generateDeviceKey();
    const ws = "ws_shared";
    const { res, dev } = await signupWith(e, await issue(issuer, payload({ dev: k1.publicKey }, { ws })), k1);
    expect(res.status).toBe(201);
    const k2 = await generateDeviceKey();
    const second = await signupWith(e, await issue(issuer, payload({ dev: k2.publicKey }, { ws })), k2.publicKey);
    expect(second.res.status).toBe(409);
    // The account it belongs to may refresh it.
    const exp = nowS() + 40 * 86400;
    const refreshed = await signedWith(e, dev!, "PUT", "/v1/account/plan", { entitlement: await issue(issuer, payload({ acc: dev!.accountId }, { ws, exp })) });
    expect(refreshed.status).toBe(200);
    expect(await refreshed.json()).toMatchObject({ plan: "overblast", planUntil: exp * 1000, expired: false });
    // An older token can't shorten it.
    await signedWith(e, dev!, "PUT", "/v1/account/plan", { entitlement: await issue(issuer, payload({ acc: dev!.accountId }, { ws, exp: exp - 86400 })) });
    const row = await env.DB.prepare("SELECT plan_until FROM accounts WHERE id = ?").bind(dev!.accountId).first<{ plan_until: number }>();
    expect(row?.plan_until).toBe(exp * 1000);
    // Another account can't take the workspace, nor use this account's token.
    const plain = await newAccount();
    const taken = await signedWith(e, plain, "PUT", "/v1/account/plan", { entitlement: await issue(issuer, payload({ acc: plain.accountId }, { ws })) });
    expect(taken.status).toBe(409);
    const notYours = await signedWith(e, plain, "PUT", "/v1/account/plan", { entitlement: await issue(issuer, payload({ acc: dev!.accountId })) });
    expect(notYours.status).toBe(403);
    const audit = (await (await signed(dev!, "GET", "/v1/audit")).json()) as { entries: { kind: string; name: string }[] };
    expect(audit.entries.some((a) => a.kind === "account.plan" && a.name === "overblast")).toBe(true);
  });

  it("a plan past its exp and the grace period falls back to `suspended`: nothing new, the backlog readable", async () => {
    const issuer = await newIssuer();
    const e = withVars({ PLANS, ENTITLEMENT_PUBLIC_KEYS: JSON.stringify([issuer.publicKey]), ENTITLEMENT_GRACE_DAYS: "7" });
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    expect((await post(e, hook.id, { before: true })).status).toBe(200);
    // Ended eight days ago: past the seven days' grace.
    await env.DB.prepare("UPDATE accounts SET plan = 'overblast', plan_until = ? WHERE id = ?").bind(Date.now() - 8 * 86_400_000, dev.accountId).run();
    const { sse } = await openStream(dev);
    expect((await sse.nextEvent())?.event).toBe("ready");
    expect((await sse.nextEvent())?.event).toBe("hook"); // the backlog still reads
    const res = await post(e, hook.id, { after: true });
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("3600");
    expect(await res.json()).toMatchObject({ error: "quota", scope: "plan_expired" });
    let f = await sse.nextEvent();
    while (f && f.event !== "limit") f = await sse.nextEvent();
    expect(data(f)).toMatchObject({ scope: "plan_expired", plan: "suspended", until: null, refused: 1 });
    await sse.cancel();
    const account = (await (await signedWith(e, dev, "GET", "/v1/account")).json()) as Record<string, any>;
    expect(account).toMatchObject({ plan: "suspended", expired: true });
    expect(account.limits).toMatchObject({ eventsPerDay: 0, hooks: 0 });
    // No new hooks either.
    expect((await signedWith(e, dev, "POST", "/v1/hooks", { name: "new", verify: { preset: "unverified" } })).status).toBe(409);
    // Within the grace period, the plan still works.
    await env.DB.prepare("UPDATE accounts SET plan_until = ? WHERE id = ?").bind(Date.now() - 6 * 86_400_000, dev.accountId).run();
    expect((await post(e, hook.id, { grace: true })).status).toBe(200);
    // A refresh brings it back, and the expired notice goes.
    await env.DB.prepare("UPDATE accounts SET plan_until = ? WHERE id = ?").bind(Date.now() - 8 * 86_400_000, dev.accountId).run();
    expect((await post(e, hook.id)).status).toBe(429);
    const put = await signedWith(e, dev, "PUT", "/v1/account/plan", { entitlement: await issue(issuer, payload({ acc: dev.accountId })) });
    expect(put.status).toBe(200);
    expect((await post(e, hook.id, { renewed: true })).status).toBe(200);
    const again = await openStream(dev);
    expect((await again.sse.nextEvent())?.event).toBe("ready");
    const next = await again.sse.nextEvent();
    expect(next?.event).not.toBe("limit");
    await again.sse.cancel();
  });

  it("ENTITLEMENT_FALLBACK_PLAN names another plan to fall back to", async () => {
    const e = withVars({ PLANS: JSON.stringify({ overblast: {}, free: { eventsPerDay: 1 } }), ENTITLEMENT_FALLBACK_PLAN: "free" });
    const dev = await newAccount();
    const { hook } = await createHook(dev, { preset: "unverified" });
    await env.DB.prepare("UPDATE accounts SET plan = 'overblast', plan_until = ? WHERE id = ?").bind(Date.now() - 30 * 86_400_000, dev.accountId).run();
    expect((await post(e, hook.id)).status).toBe(200);
    expect(await (await post(e, hook.id)).json()).toMatchObject({ scope: "daily" });
  });
});
