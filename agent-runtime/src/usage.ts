// sumUsage adds two turns' engine-shaped usage (#3107). Usage is open by
// design (each SDK reports its own shape), so this adds what it can read:
// numbers add, nested objects add field by field, and a field on only one turn
// is kept. For a non-numeric field (a tier name, an array) the later turn's
// value wins. When one turn reported no usage the other's is returned as it
// is, so a missing report never zeroes the sum.
export function sumUsage(first: unknown, second: unknown): unknown {
  if (first === undefined || first === null) return second;
  if (second === undefined || second === null) return first;
  if (typeof first === "number" && typeof second === "number") return first + second;
  if (isRecord(first) && isRecord(second)) {
    // defineProperty, not assignment: a "__proto__" key from parsed JSON is
    // data, and `out["__proto__"] = x` would set the prototype instead.
    const out: Record<string, unknown> = {};
    const put = (k: string, v: unknown): void => {
      Object.defineProperty(out, k, { value: v, enumerable: true, writable: true, configurable: true });
    };
    for (const [k, v] of Object.entries(first)) put(k, v);
    for (const [k, v] of Object.entries(second)) put(k, Object.hasOwn(first, k) ? sumUsage(first[k], v) : v);
    return out;
  }
  return second;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
