// Package agentbox is the in-the-box MCP server library — the tools agents
// use when working on a single Containarium box. Tools are registered onto
// an mcp-go server.MCPServer instance by the agent-box binary.
//
// Tool taxonomy (v0):
//
//   - shell_exec      — run a shell command, capture stdout/stderr/exit code
//   - read_file       — read a file (byte range, head=N lines, or tail=N lines)
//   - write_file      — write a file atomically
//   - list_directory  — enumerate a directory's entries
//   - move_file       — rename/move a file or directory
//   - delete_file     — remove a single file (refuses directories)
//   - tail_log        — watch a file for new appends, bounded by follow_seconds
//   - process_start   — spawn a long-running process; output captured to a log file
//   - process_list    — list managed processes with PID, command, liveness
//   - process_kill    — SIGTERM (or SIGKILL with force) and reap
//
// Resource taxonomy (v0):
//
//   - containarium://ci-context — JSON metadata about the current CI run
//     (PR, commit, failing test), populated by the containarium-run GitHub
//     Action. Empty stub when the box isn't being used for CI.
//
// File-ops tools enforce a sandbox in this order:
//   1. AGENTBOX_ROOT env var (strict floor when set).
//   2. MCP Roots advertised by the client via roots/list (used as the
//      sandbox when AGENTBOX_ROOT is unset). Falls back gracefully if
//      the client doesn't support the capability.
//   3. Unconstrained (only when both are absent).
//
// More tools (provision_postgres, deploy_app, snapshot, etc.) land in
// subsequent commits.
package agentbox

import "github.com/mark3labs/mcp-go/server"

// RegisterTools wires every agentbox tool into the given MCPServer. Called
// once at startup by cmd/agent-box. Each tool is implemented in its own
// file (shell.go, files.go, …) and registers itself via a Register*
// function — keeping main.go declarative and the toolset easy to discover.
//
// The MCPServer reference is also stashed in the package so file-ops
// handlers can call s.RequestRoots() to fetch the client's filesystem
// roots when AGENTBOX_ROOT isn't set. See sandbox.go.
func RegisterTools(s *server.MCPServer) {
	mcpServer = s
	registerShellTool(s)
	registerFileTools(s)
	registerTailLogTool(s)
	registerProcessTools(s)
}

// RegisterResources wires every agentbox MCP resource onto the given
// server. Resources are read-only data the agent fetches via the MCP
// resources/read RPC — distinct from tools, which are imperative calls.
// Called once at startup by cmd/agent-box, parallel to RegisterTools.
func RegisterResources(s *server.MCPServer) {
	registerCIContextResource(s)
}
