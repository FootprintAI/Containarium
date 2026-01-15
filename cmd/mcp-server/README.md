# Containarium MCP Server

MCP (Model Context Protocol) server for Containarium - enables Claude to directly manage containers.

## Quick Start

### Build
```bash
make build-mcp
```

### Run
```bash
export CONTAINARIUM_SERVER_URL="http://localhost:8080"
export CONTAINARIUM_JWT_TOKEN="your-jwt-token"
./bin/mcp-server
```

### Configure Claude Desktop

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "containarium": {
      "command": "/path/to/mcp-server",
      "env": {
        "CONTAINARIUM_SERVER_URL": "http://localhost:8080",
        "CONTAINARIUM_JWT_TOKEN": "your-jwt-token"
      }
    }
  }
}
```

## Documentation

See [docs/MCP-INTEGRATION.md](../../docs/MCP-INTEGRATION.md) for complete documentation.

## Environment Variables

- `CONTAINARIUM_SERVER_URL` (required): REST API URL
- `CONTAINARIUM_JWT_TOKEN` (required): JWT authentication token
- `CONTAINARIUM_DEBUG` (optional): Enable debug logging

## Architecture

```
Claude Desktop
      ↓ (MCP protocol - JSON-RPC over stdio)
  MCP Server
      ↓ (HTTP + JWT Bearer Token)
Containarium REST API
      ↓
Container Manager → Incus/LXC
```

## Available Tools

- `create_container` - Create a new container
- `list_containers` - List all containers
- `get_container` - Get container details
- `delete_container` - Delete a container
- `start_container` - Start a stopped container
- `stop_container` - Stop a running container
- `get_metrics` - Get container metrics
- `get_system_info` - Get system information
