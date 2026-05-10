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

	mcpServer := server.NewMCPServer(
		"containarium-agent-box",
		version.Version,
		server.WithToolCapabilities(true),
	)

	agentbox.RegisterTools(mcpServer)

	log.Printf("[agent-box] starting MCP server on stdio (version %s)", version.Version)
	if err := server.ServeStdio(mcpServer); err != nil {
		log.Fatalf("[agent-box] stdio serve error: %v", err)
	}
}
