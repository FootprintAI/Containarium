package main

import (
	"log"
	"os"

	"github.com/footprintai/containarium/internal/mcp"
	"github.com/footprintai/containarium/pkg/version"
)

func main() {
	// Log to stderr so stdout stays clean for the MCP protocol stream.
	// Set this BEFORE LoadConfig so any config-load logging lands on
	// stderr too (the printUsage path logs to whatever's wired up).
	log.SetOutput(os.Stderr)

	// Read configuration from environment or config file
	config := mcp.LoadConfig()

	if config.ServerURL == "" {
		printUsage()
		log.Fatal("no server URL found: set CONTAINARIUM_SERVER_URL, or run `containarium login` (writes ~/.containarium/credentials.json with a default_server)")
	}
	if config.JWTToken == "" && config.JWTTokenFile == "" {
		printUsage()
		log.Fatal("no token found: set CONTAINARIUM_JWT_TOKEN or CONTAINARIUM_JWT_TOKEN_FILE, or run `containarium login` (writes ~/.containarium/credentials.json)")
	}

	// Create MCP server with protobuf-defined contracts
	// All message types defined in proto/containarium/v1/mcp.proto
	server, err := mcp.NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create MCP server: %v", err)
	}

	log.Printf("Starting Containarium MCP Server (version %s, commit %s)",
		version.GetVersion(), version.GetCommitHash())
	log.Printf("Server URL: %s", config.ServerURL)
	log.Printf("Debug mode: %v", config.Debug)

	// Start MCP server (reads from stdin, writes to stdout)
	if err := server.Start(); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}

// printUsage prints usage information and example configuration
func printUsage() {
	log.Println("")
	log.Println("=== Containarium MCP Server Configuration ===")
	log.Println("")
	log.Println("Required configuration:")
	log.Println("  CONTAINARIUM_SERVER_URL      - URL of the Containarium REST API (e.g., http://localhost:8080).")
	log.Println("                                 Optional when ~/.containarium/credentials.json has a")
	log.Println("                                 default_server (written by `containarium login`).")
	log.Println("")
	log.Println("Token resolution (highest precedence first):")
	log.Println("  CONTAINARIUM_JWT_TOKEN       - JWT token (static, captured at MCP start)")
	log.Println("  CONTAINARIUM_JWT_TOKEN_FILE  - Path to a file with the JWT — re-read on every request,")
	log.Println("                                 so rotating the token is `mv newtoken oldpath`. Prefer this")
	log.Println("                                 for long-running MCP processes that need to survive rotation.")
	log.Println("  ~/.containarium/credentials.json — fallback when neither env var is set.")
	log.Println("                                 Written by `containarium login`; looked up by server URL.")
	log.Println("")
	log.Println("Optional environment variables:")
	log.Println("  CONTAINARIUM_DEBUG           - Enable debug logging (true/false)")
	log.Println("  CONTAINARIUM_SENTINEL_HOST   - Public SSH endpoint, shown in create_container responses")
	log.Println("")
	log.Println("Example usage:")
	log.Println("  export CONTAINARIUM_SERVER_URL='http://localhost:8080'")
	log.Println("  export CONTAINARIUM_JWT_TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'")
	log.Println("  /usr/local/bin/mcp-server")
	log.Println("")
	log.Println("Claude Desktop configuration (~/.config/claude/claude_desktop_config.json):")
	log.Println(`{`)
	log.Println(`  "mcpServers": {`)
	log.Println(`    "containarium": {`)
	log.Println(`      "command": "/usr/local/bin/mcp-server",`)
	log.Println(`      "env": {`)
	log.Println(`        "CONTAINARIUM_SERVER_URL": "http://your-server:8080",`)
	log.Println(`        "CONTAINARIUM_JWT_TOKEN": "your-jwt-token"`)
	log.Println(`      }`)
	log.Println(`    }`)
	log.Println(`  }`)
	log.Println(`}`)
	log.Println("")
}
