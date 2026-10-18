// The Worker's main module may export only its handler and Durable Object classes: workerd refuses
// to start a Worker whose entry exports anything else (a constant once did, and only `wrangler dev`
// showed it, since tests import modules directly).

import { describe, expect, it } from "vitest";
import * as entry from "../src/index.ts";
import { AccountObject } from "../src/account-object.ts";
import { PhoneObject } from "../src/phone-object.ts";

describe("entry module", () => {
  it("exports only the handler and the Durable Object classes", () => {
    expect(Object.keys(entry).sort()).toEqual(["AccountObject", "PhoneObject", "default"]);
    expect(entry.AccountObject).toBe(AccountObject);
    expect(entry.PhoneObject).toBe(PhoneObject);
    expect(typeof entry.default.fetch).toBe("function");
  });
});
