import { describe, expect, it } from "vitest";
import type { EngineConfig } from "./engine.js";
import { claudeAllowedTools, claudeMcpServers, codexConfigToml, mcpServerSpecs } from "./mcp.js";

const base: EngineConfig = {
  model: "",
  systemPrompt: "",
  agentBoxCommand: "agent-box",
  agentBoxArgs: [],
  maxTurns: 5,
};
const platformMcp = {
  command: "mcp-server",
  args: [] as string[],
  serverUrl: "http://10.9.8.1:8080",
  tokenFile: "/seed/token",
  tools: "tracker_*",
};

describe("mcpServerSpecs", () => {
  it("is agent-box alone when the seed carries no platform MCP (behavior unchanged)", () => {
    expect(mcpServerSpecs(base).map((s) => s.name)).toEqual(["agent-box"]);
  });

  it("adds containarium beside agent-box when it does", () => {
    const specs = mcpServerSpecs({ ...base, platformMcp });
    expect(specs.map((s) => s.name)).toEqual(["agent-box", "containarium"]);
  });

  it("hands the MCP server the URL, token FILE and allow-list through its env", () => {
    const c = mcpServerSpecs({ ...base, platformMcp }).find((s) => s.name === "containarium")!;
    expect(c.command).toBe("mcp-server");
    expect(c.env).toEqual({
      CONTAINARIUM_SERVER_URL: "http://10.9.8.1:8080",
      CONTAINARIUM_JWT_TOKEN_FILE: "/seed/token",
      CONTAINARIUM_MCP_TOOLS: "tracker_*",
    });
  });

  // The token is only ever referenced by path so the MCP server re-reads it per
  // request (rotation-safe) and it never lands in a process env or config file.
  it("never puts a token value anywhere in the spec", () => {
    const json = JSON.stringify(mcpServerSpecs({ ...base, platformMcp }));
    expect(json).not.toMatch(/CONTAINARIUM_JWT_TOKEN"/);
    expect(json).toContain("/seed/token");
  });
});

describe("claudeAllowedTools", () => {
  it("allows agent-box only by default", () => {
    expect(claudeAllowedTools(mcpServerSpecs(base))).toEqual(["mcp__agent-box__*"]);
  });

  it("extends allowedTools with exactly the allow-listed platform tools, not a blanket grant", () => {
    const tools = claudeAllowedTools(mcpServerSpecs({ ...base, platformMcp }));
    expect(tools).toEqual(["mcp__agent-box__*", "mcp__containarium__tracker_*"]);
    expect(tools).not.toContain("mcp__containarium__*");
  });

  it("handles a comma-separated allow-list with whitespace", () => {
    const specs = mcpServerSpecs({ ...base, platformMcp: { ...platformMcp, tools: "tracker_*, create_container" } });
    expect(claudeAllowedTools(specs)).toEqual([
      "mcp__agent-box__*",
      "mcp__containarium__tracker_*",
      "mcp__containarium__create_container",
    ]);
  });
});

describe("codexConfigToml", () => {
  it("writes agent-box and the model, as before", () => {
    const toml = codexConfigToml({ ...base, model: "gpt-x" });
    expect(toml).toContain('model = "gpt-x"');
    expect(toml).toContain("[mcp_servers.agent-box]");
    expect(toml).not.toContain("containarium");
  });

  it("adds a containarium server with its env table when mounted", () => {
    const toml = codexConfigToml({ ...base, platformMcp });
    expect(toml).toContain("[mcp_servers.containarium]");
    expect(toml).toContain("[mcp_servers.containarium.env]");
    expect(toml).toContain('CONTAINARIUM_MCP_TOOLS = "tracker_*"');
    expect(toml).toContain('CONTAINARIUM_JWT_TOKEN_FILE = "/seed/token"');
  });

  it("escapes quotes in values", () => {
    const toml = codexConfigToml({ ...base, platformMcp: { ...platformMcp, serverUrl: 'http://h"x' } });
    expect(toml).toContain('CONTAINARIUM_SERVER_URL = "http://h\\"x"');
  });
});

describe("claudeMcpServers", () => {
  it("mounts agent-box with no env, and containarium with its env", () => {
    const servers = claudeMcpServers(mcpServerSpecs({ ...base, platformMcp }));
    expect(Object.keys(servers)).toEqual(["agent-box", "containarium"]);
    expect(servers["agent-box"]).toEqual({ command: "agent-box", args: [] });
    expect(servers["containarium"].env?.CONTAINARIUM_MCP_TOOLS).toBe("tracker_*");
  });
});
