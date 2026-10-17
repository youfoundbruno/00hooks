import { describe, expect, it } from "vitest";
import { describeError } from "../src/describe-error.ts";

describe("logging a failure", () => {
  it("keeps the cause and drops anything quoted from inputs", () => {
    expect(describeError(new Error("D1_ERROR: no such table: accounts"))).toBe("Error: D1_ERROR: no such table: accounts");
    const parse = describeError(new SyntaxError(`Unexpected token 'h', "hunter2 secret" is not valid JSON`));
    expect(parse).not.toContain("hunter2");
    expect(describeError(new Error("key whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw leaked"))).not.toContain("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
    expect(describeError(new Error("x".repeat(500))).length).toBeLessThanOrEqual(207);
    expect(describeError("nope")).toBe("unknown");
  });
});
