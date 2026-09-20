import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadSeed, parsePlatformMcp } from "./seed.js";

// The SAME file internal/server/agent_platform_mcp_test.go pins: the daemon
// writes this shape, this parses it. Drift on either side fails a test on the
// other.
const fixture = readFileSync(new URL("../fixtures/platform_mcp.json", import.meta.url), "utf8");

function seedDirWith(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "seed-"));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

describe("parsePlatformMcp", () => {
  it("parses the shared fixture into camelCase fields", () => {
    expect(parsePlatformMcp(fixture)).toEqual({
      command: "mcp-server",
      args: [],
      serverUrl: "http://10.9.8.1:8080",
      tokenFile: "/etc/containarium/agent/runs/run-1/token",
      tools: "tracker_*",
    });
  });

  it("throws on malformed JSON rather than silently mounting nothing", () => {
    expect(() => parsePlatformMcp("{not json")).toThrow(/platform_mcp\.json/);
  });

  it.each(["command", "server_url", "token_file", "tools"])("throws when %s is missing", (field) => {
    const obj = JSON.parse(fixture) as Record<string, unknown>;
    delete obj[field];
    expect(() => parsePlatformMcp(JSON.stringify(obj))).toThrow(new RegExp(field));
  });

  it("throws when args is not an array of strings", () => {
    const obj = { ...(JSON.parse(fixture) as object), args: "nope" };
    expect(() => parsePlatformMcp(JSON.stringify(obj))).toThrow(/args/);
  });

  // An empty allow-list means "every registered tool" to the MCP server, so
  // accepting it would hand the agent all ~75 platform tools. Must be rejected.
  it("rejects an empty tools allow-list", () => {
    const obj = { ...(JSON.parse(fixture) as object), tools: "  " };
    expect(() => parsePlatformMcp(JSON.stringify(obj))).toThrow(/tools/);
  });
});

describe("loadSeed platformMcp", () => {
  it("is null when the seed carries no platform_mcp.json", () => {
    expect(loadSeed(seedDirWith({ "system_prompt.txt": "hi" })).platformMcp).toBeNull();
  });

  it("is parsed when present", () => {
    const seed = loadSeed(seedDirWith({ "platform_mcp.json": fixture }));
    expect(seed.platformMcp?.tools).toBe("tracker_*");
  });

  it("throws when present but malformed", () => {
    expect(() => loadSeed(seedDirWith({ "platform_mcp.json": "[]" }))).toThrow(/platform_mcp\.json/);
  });
});
