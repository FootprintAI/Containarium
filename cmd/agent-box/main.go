// agent-box is the in-the-box MCP server. It runs inside every Containarium
// box and exposes Linux-native operations (shell, files, logs, services,
// deployment) to a remote MCP client over stdio.
//
// Usage on the user's laptop, in ~/.cursor/mcp.json or ~/.claude.json:
//
//	{
//	  "mcpServers": {
//	    "containarium": {
//	      "command": "ssh",
//	      "args": ["user@my-box.containarium.app", "agent-box"]
//	    }
//	  }
//	}
//
// The MCP transport is stdio; the SSH command on the user side wraps it.
//
// Tools (imperative): shell_exec, read_file, write_file, list_directory,
// move_file, delete_file, tail_log, process_start, process_list,
// process_kill. See internal/agentbox/server.go for the canonical list.
//
// Resources (read-only data):
//   - containarium://ci-context — JSON metadata about the current CI run
//     when the box is kept alive after a failed CI run by the
//     FootprintAI/containarium-run GitHub Action. Returns a stub
//     `{"available": false}` object when the box isn't a CI box.
//   - containarium://ci-prompt  — static markdown playbook that tells an
//     agent how to behave when debugging that failing CI run. Same
//     content on every box; pair with ci-context for the per-run data.
//
// Distinct from cmd/mcp-server/, which is the *platform* MCP for outside-the-
// box admin operations (create_container, list_containers, etc.). agent-box
// is the *inside-the-box* MCP — agents working on a single project use this.
package main

import (
	"log"
	"os"

	"github.com/mark3labs/mcp-go/server"

	"github.com/footprintai/containarium/internal/agentbox"
	"github.com/footprintai/containarium/pkg/version"
)

func main() {
	// MCP requires stdout to be clean (it's the protocol stream); send our
	// own logs to stderr so they don't poison the channel.
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Subcommand dispatch — `agent-box compose <verb>` runs the CLI form
	// of the compose tools (same Go funcs the MCP handlers call, but
	// arguments via flags + result as JSON on stdout). Used by the
	// platform daemon to drive these operations from outside the LXC
	// (Containarium#317 Phase C). No subcommand → start the MCP server
	// as before.
	if len(os.Args) >= 2 && os.Args[1] == "compose" {
		os.Exit(agentbox.RunComposeCLI(os.Args[2:], os.Stdout, os.Stderr))
	}

	mcpServer := server.NewMCPServer(
		"containarium-agent-box",
		version.Version,
		server.WithToolCapabilities(true),
		// listChanged=false: our resource set is static for the lifetime
		// of the process (ci-context is always advertised; its body just
		// changes based on whether the file exists at read time).
		server.WithResourceCapabilities(false, false),
	)

	agentbox.RegisterTools(mcpServer)
	agentbox.RegisterResources(mcpServer)

	log.Printf("[agent-box] starting MCP server on stdio (version %s)", version.Version)
	if err := server.ServeStdio(mcpServer); err != nil {
		log.Fatalf("[agent-box] stdio serve error: %v", err)
	}
}
