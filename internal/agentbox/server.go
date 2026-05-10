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
//
// All file paths can be confined to a project root via the AGENTBOX_ROOT
// env var; unset means no constraint.
//
// More tools (provision_postgres, deploy_app, snapshot, etc.) land in
// subsequent commits.
package agentbox

import "github.com/mark3labs/mcp-go/server"

// RegisterTools wires every agentbox tool into the given MCPServer. Called
// once at startup by cmd/agent-box. Each tool is implemented in its own
// file (shell.go, files.go, …) and registers itself via a Register*
// function — keeping main.go declarative and the toolset easy to discover.
func RegisterTools(s *server.MCPServer) {
	registerShellTool(s)
	registerFileTools(s)
	registerTailLogTool(s)
}
