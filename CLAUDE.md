# Containarium — guidance for Claude / AI assistants

This file is a small set of durable conventions for AI assistants working
on this repository. Keep it short — only rules whose violation we'd
actually want to catch in review.

## CLI-first, MCP wraps it

When adding a new platform action (anything that mutates Containarium
state — create, expose, route, deploy, etc.):

1. Land it as a `containarium <verb>` cobra subcommand under
   `internal/cmd/<verb>.go` first.
2. The MCP tool in `internal/mcp/tools.go` is a **thin wrapper** over the
   same underlying Go function used by the CLI handler. Don't have the
   MCP tool call an HTTP endpoint that the CLI doesn't.

**Why:** The CLI is the canonical interface. Humans, shell scripts, CI,
and demo recordings all consume it; MCP is one specific consumer (AI
agents). Building CLI-first means:

- Anything an agent can do, a human can do via shell — symmetric surface
  with no agent-only escape hatches.
- Demo recordings are reproducible `bash` scripts, not "spin up an
  agent + JWT token" rituals.
- Tests focus on the CLI handler / shared client function; MCP correctness
  follows for free.
- The OSS community gets value from the CLI even without running an agent.

**Anti-pattern:** an MCP tool that talks to an HTTP endpoint with no
matching `containarium <verb>` subcommand. If you spot one, file a
follow-up to add the CLI counterpart.

## Two MCP servers, distinct surfaces

- `cmd/mcp-server/` — **platform** MCP. Outside-the-box admin
  operations: create container, list containers, expose port, etc.
  Talks to the platform's REST/gRPC API.
- `cmd/agent-box/` — **in-the-box** MCP. Linux-native operations
  (shell, files) running *inside* a single Containarium box. Reached
  over stdio, typically wrapped by SSH on the client side.

Don't mix them. Tools that operate on a single box's filesystem belong
in `agent-box`; tools that operate across boxes belong in the platform
MCP.
