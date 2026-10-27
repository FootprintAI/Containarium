import { describe, expect, it } from "vitest";
import { sumUsage } from "./usage.js";

describe("sumUsage (#3107 item 2)", () => {
  it("adds numeric fields, including nested objects", () => {
    expect(
      sumUsage(
        { input_tokens: 10, output_tokens: 3, cache: { read: 4 } },
        { input_tokens: 5, output_tokens: 2, cache: { read: 1, write: 7 } },
      ),
    ).toEqual({ input_tokens: 15, output_tokens: 5, cache: { read: 5, write: 7 } });
  });
  it("keeps a field present on one turn only", () => {
    expect(sumUsage({ a: 1 }, { b: 2 })).toEqual({ a: 1, b: 2 });
  });
  it("returns the other turn's usage when one turn reported none", () => {
    expect(sumUsage(undefined, { a: 2 })).toEqual({ a: 2 });
    expect(sumUsage({ a: 1 }, undefined)).toEqual({ a: 1 });
    expect(sumUsage(undefined, undefined)).toBeUndefined();
  });
  it("takes the later turn's value for non-numeric fields", () => {
    expect(sumUsage({ tier: "standard", n: 1 }, { tier: "priority", n: 1 })).toEqual({ tier: "priority", n: 2 });
  });
  it("does not mutate its inputs", () => {
    const a = { n: 1 };
    sumUsage(a, { n: 2 });
    expect(a).toEqual({ n: 1 });
  });
  it("treats __proto__ as an ordinary key, never touching the prototype", () => {
    const a = JSON.parse('{"x":1}') as unknown;
    const b = JSON.parse('{"__proto__":{"n":2},"x":2}') as unknown;
    const sum = sumUsage(a, b) as Record<string, unknown>;
    expect(Object.getPrototypeOf(sum)).toBe(Object.prototype);
    expect(({} as { n?: number }).n).toBeUndefined();
    expect(Object.getOwnPropertyDescriptor(sum, "__proto__")?.value).toEqual({ n: 2 });
    expect(sum.x).toBe(3);
  });
  it("does not treat a key that exists only on the prototype as present", () => {
    const sum = sumUsage({ x: 1 }, { toString: null, constructor: 3 }) as Record<string, unknown>;
    expect(sum.toString).toBeNull(); // with `in`, the inherited function would win over null
    expect(sum.constructor).toBe(3);
  });
});
