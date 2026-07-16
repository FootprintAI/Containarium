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

### Run in a container

```bash
docker build -f images/mcp-server/Dockerfile -t containarium-mcp-server .
docker run -i --rm \
  -e CONTAINARIUM_SERVER_URL="http://host.docker.internal:8080" \
  -e CONTAINARIUM_JWT_TOKEN="your-jwt-token" \
  containarium-mcp-server
```

The MCP protocol runs over stdio, so `-i` (attach stdin) is required; no
ports are exposed.

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

Full schema (required/optional, description, example placeholder) — this is
the source of truth to copy into Glama's build-spec "environment-variable
schema" step (Containarium#967):

| Variable | Required | Description | Example |
|----------|----------|--------------|---------|
| `CONTAINARIUM_SERVER_URL` | Yes* | REST API base URL | `http://localhost:8080` |
| `CONTAINARIUM_JWT_TOKEN` | Yes** | JWT authentication token, captured once at startup | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` |
| `CONTAINARIUM_JWT_TOKEN_FILE` | Yes** | Path to a file holding the JWT; re-read on every request, so rotating the token is `mv newtoken oldpath` — no restart needed. Alternative to `CONTAINARIUM_JWT_TOKEN`; set at most one. | `/etc/containarium/mcp-token` |
| `CONTAINARIUM_DEBUG` | No | Enable debug logging | `true` or `false` |
| `CONTAINARIUM_KEYS_DIR` | No | Directory the server writes ephemeral SSH private keys to (from container-creation tools). Defaults to `$HOME/.containarium/keys`. | `/home/mcp/.containarium/keys` |

\* Optional only when `~/.containarium/credentials.json` (written by
`containarium login`) has a `default_server`.
\*\* One of `CONTAINARIUM_JWT_TOKEN` / `CONTAINARIUM_JWT_TOKEN_FILE` is
required unless that same credentials file supplies a token for the
resolved server.

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
