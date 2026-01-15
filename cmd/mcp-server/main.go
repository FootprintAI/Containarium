package main

import (
	"log"
	"os"

	"github.com/footprintai/containarium/internal/mcp"
)

func main() {
	// Read configuration from environment or config file
	config := mcp.LoadConfig()

	if config.ServerURL == "" {
		printUsage()
		log.Fatal("CONTAINARIUM_SERVER_URL environment variable is required")
	}
	if config.JWTToken == "" {
		printUsage()
		log.Fatal("CONTAINARIUM_JWT_TOKEN environment variable is required")
	}

	// Create MCP server with protobuf-defined contracts
	// All message types defined in proto/containarium/v1/mcp.proto
	server, err := mcp.NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create MCP server: %v", err)
	}

	// Log to stderr so stdout is clean for MCP protocol
	log.SetOutput(os.Stderr)
	log.Printf("Starting Containarium MCP Server")
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
	log.Println("Required environment variables:")
	log.Println("  CONTAINARIUM_SERVER_URL - URL of the Containarium REST API (e.g., http://localhost:8080)")
	log.Println("  CONTAINARIUM_JWT_TOKEN  - JWT token for authentication")
	log.Println("")
	log.Println("Optional environment variables:")
	log.Println("  CONTAINARIUM_DEBUG      - Enable debug logging (true/false)")
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
