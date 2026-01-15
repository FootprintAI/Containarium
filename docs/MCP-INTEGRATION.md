# Containarium MCP Integration

Enable Claude to directly create and manage LXC containers through natural language using the Model Context Protocol (MCP).

## What is MCP?

The **Model Context Protocol (MCP)** allows AI assistants like Claude to connect to external tools and services. With Containarium's MCP server, you can manage containers directly through Claude Desktop or the Claude API.

## Quick Start

### 1. Build the MCP Server

```bash
# Build for your platform
make build-mcp

# Or build for Linux (for deployment)
make build-mcp-linux

# Install to system (optional)
make install-mcp
```

### 2. Generate JWT Token

First, start the Containarium daemon with REST API:

```bash
# On your Containarium server
containarium daemon --rest --jwt-secret "your-secret-key"

# Generate a token for MCP
containarium token generate \
  --username mcp-client \
  --roles admin \
  --expiry 8760h \
  --secret "your-secret-key"

# Output:
# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Save this JWT token - you'll need it for MCP configuration.

### 3. Configure Claude Desktop

Add the MCP server to your Claude Desktop configuration:

**Location:** `~/.config/claude/claude_desktop_config.json` (Linux/macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "containarium": {
      "command": "/usr/local/bin/mcp-server",
      "env": {
        "CONTAINARIUM_SERVER_URL": "http://your-containarium-server:8080",
        "CONTAINARIUM_JWT_TOKEN": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
      }
    }
  }
}
```

**For local testing:**
```json
{
  "mcpServers": {
    "containarium": {
      "command": "/Users/yourusername/Workspaces/Containarium/bin/mcp-server",
      "env": {
        "CONTAINARIUM_SERVER_URL": "http://localhost:8080",
        "CONTAINARIUM_JWT_TOKEN": "your-jwt-token-here",
        "CONTAINARIUM_DEBUG": "true"
      }
    }
  }
}
```

### 4. Restart Claude Desktop

Restart Claude Desktop to load the new MCP server configuration.

### 5. Test It!

Open Claude Desktop and try:

```
Create a container for user alice with 4 CPU cores and 8GB memory
```

Claude will use the MCP server to create the container!

## Available Tools

The MCP server provides the following tools that Claude can use:

### Container Management

#### `create_container`
Create a new LXC container with specified resources.

**Parameters:**
- `username` (required): Username for the container
- `cpu`: CPU limit (e.g., "4" for 4 cores, default: "4")
- `memory`: Memory limit (e.g., "4GB", "2048MB", default: "4GB")
- `disk`: Disk limit (e.g., "50GB", "100GB", default: "50GB")
- `ssh_keys`: Array of SSH public keys (optional)
- `image`: Container image (default: "images:ubuntu/24.04")
- `enable_docker`: Enable Docker support (default: true)

**Example prompts:**
- "Create a container for alice"
- "Create a container for bob with 8 CPU cores and 16GB memory"
- "Set up a development container for charlie with 100GB disk"

#### `list_containers`
List all containers with their status and resources.

**Example prompts:**
- "List all containers"
- "Show me all running containers"
- "What containers exist?"

#### `get_container`
Get detailed information about a specific container.

**Parameters:**
- `username` (required): Username of the container

**Example prompts:**
- "Show me details for alice's container"
- "Get information about bob's container"
- "What's the status of charlie's container?"

#### `delete_container`
Delete a container permanently.

**Parameters:**
- `username` (required): Username of the container to delete
- `force`: Force delete even if running (default: false)

**Example prompts:**
- "Delete alice's container"
- "Remove bob's container and force stop it"
- "Clean up charlie's container"

#### `start_container`
Start a stopped container.

**Parameters:**
- `username` (required): Username of the container to start

**Example prompts:**
- "Start alice's container"
- "Boot up bob's container"

#### `stop_container`
Stop a running container.

**Parameters:**
- `username` (required): Username of the container to stop
- `force`: Force stop (kill) instead of graceful shutdown (default: false)

**Example prompts:**
- "Stop alice's container"
- "Shut down bob's container gracefully"
- "Force stop charlie's container"

### Monitoring

#### `get_metrics`
Get runtime metrics (CPU, memory, disk, network) for containers.

**Parameters:**
- `username`: Username of specific container (optional, empty for all)

**Example prompts:**
- "Show metrics for all containers"
- "Get resource usage for alice's container"
- "How much CPU is bob using?"

#### `get_system_info`
Get information about the Containarium host system.

**Example prompts:**
- "Show system information"
- "What's the host system status?"
- "How many containers are running?"

## Example Workflows

### Create Multiple Containers

```
Create containers for alice, bob, and charlie.
Alice needs 8GB memory, Bob needs 4 CPU cores,
and Charlie needs standard settings.
```

Claude will execute three `create_container` calls with appropriate parameters.

### Monitor Resources

```
Show me resource usage for all containers and
tell me which one is using the most memory.
```

Claude will call `get_metrics` and analyze the results.

### Container Lifecycle

```
1. Create a container for testuser
2. Wait a moment
3. Show me its status
4. Stop it
5. Delete it
```

Claude will execute the full workflow sequentially.

## Architecture

```
┌─────────────────┐
│ Claude Desktop  │
│   or Claude API │
└────────┬────────┘
         │ MCP Protocol (JSON-RPC over stdio)
         ▼
┌─────────────────┐
│  MCP Server     │
│  (mcp-server)   │
└────────┬────────┘
         │ HTTP + JWT Bearer Token
         ▼
┌─────────────────┐
│ Containarium    │
│   REST API      │
│  (port 8080)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Container Mgr   │
│  → Incus/LXC    │
└─────────────────┘
```

**Protocol Flow:**
1. **Claude → MCP Server**: JSON-RPC over stdin/stdout
2. **MCP Server → REST API**: HTTP requests with JWT authentication
3. **REST API → Container Manager**: Internal Go function calls
4. **Container Manager → Incus**: LXC API calls

## Configuration

### Environment Variables

The MCP server is configured through environment variables:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `CONTAINARIUM_SERVER_URL` | Yes | REST API base URL | `http://localhost:8080` |
| `CONTAINARIUM_JWT_TOKEN` | Yes | JWT authentication token | `eyJhbGci...` |
| `CONTAINARIUM_DEBUG` | No | Enable debug logging | `true` or `false` |

### JWT Token Requirements

The JWT token must have:
- **Role**: `admin` (for container management)
- **Expiry**: Long enough for your usage (e.g., `8760h` = 1 year)
- **Signature**: Must match the server's JWT secret

Generate tokens using:
```bash
containarium token generate \
  --username mcp-client \
  --roles admin \
  --expiry 8760h \
  --secret-file /etc/containarium/jwt.secret
```

## Security Considerations

### Token Security

- **Never commit tokens to git**: Keep JWT tokens in environment variables or secure config
- **Rotate tokens regularly**: Generate new tokens periodically
- **Use short expiry for testing**: Use longer expiry only for production
- **Restrict token scope**: Use role-based access control

### Network Security

- **Use HTTPS in production**: Don't expose REST API over HTTP in production
- **Firewall rules**: Restrict API access to authorized IPs
- **VPN/Private network**: Run API on private network if possible
- **Rate limiting**: Enable rate limiting on REST API

### Claude Desktop Security

- **Config file permissions**: Ensure config file is only readable by you
  ```bash
  chmod 600 ~/.config/claude/claude_desktop_config.json
  ```
- **Don't share config**: Never share your Claude Desktop config (contains secrets)

## Troubleshooting

### MCP Server Not Starting

**Error:** `CONTAINARIUM_SERVER_URL environment variable is required`

**Solution:** Check your Claude Desktop config:
```json
{
  "mcpServers": {
    "containarium": {
      "command": "/usr/local/bin/mcp-server",
      "env": {
        "CONTAINARIUM_SERVER_URL": "http://localhost:8080",  // ← Check this
        "CONTAINARIUM_JWT_TOKEN": "your-token"
      }
    }
  }
}
```

### Authentication Errors

**Error:** `API error (status 401): {"error": "invalid token", "code": 401}`

**Solutions:**
1. **Token expired**: Generate a new token
2. **Wrong secret**: Ensure token was generated with same secret as daemon
3. **Wrong token format**: Token should start with `eyJ`

**Verify token:**
```bash
# Check token expiry
echo "YOUR_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .exp

# Compare with current time
date +%s
```

### Connection Errors

**Error:** `request failed: dial tcp: connection refused`

**Solutions:**
1. **Daemon not running**: Start the daemon
   ```bash
   containarium daemon --rest --jwt-secret "your-secret"
   ```
2. **Wrong port**: Check URL in MCP config matches daemon port
3. **Firewall blocking**: Check firewall rules allow connections

### Debug Mode

Enable debug logging to see all MCP protocol messages:

```json
{
  "mcpServers": {
    "containarium": {
      "command": "/usr/local/bin/mcp-server",
      "env": {
        "CONTAINARIUM_SERVER_URL": "http://localhost:8080",
        "CONTAINARIUM_JWT_TOKEN": "your-token",
        "CONTAINARIUM_DEBUG": "true"  // ← Enable debug
      }
    }
  }
}
```

View logs:
- **macOS**: `~/Library/Logs/Claude/`
- **Linux**: `~/.local/state/claude/logs/`
- **Windows**: `%APPDATA%\Claude\logs\`

### Claude Not Seeing Tools

**Symptoms:** Claude says "I don't have access to container management tools"

**Solutions:**
1. **Restart Claude Desktop**: Configuration changes require restart
2. **Check config syntax**: Validate JSON with `jq`:
   ```bash
   cat ~/.config/claude/claude_desktop_config.json | jq .
   ```
3. **Check MCP server path**: Ensure binary exists and is executable
   ```bash
   ls -la /usr/local/bin/mcp-server
   # Should show: -rwxr-xr-x
   ```

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/footprintai/containarium.git
cd containarium

# Build MCP server
make build-mcp

# Binary location: bin/mcp-server
```

### Testing the MCP Server

**Test with manual input:**
```bash
export CONTAINARIUM_SERVER_URL="http://localhost:8080"
export CONTAINARIUM_JWT_TOKEN="your-token"
export CONTAINARIUM_DEBUG="true"

# Start MCP server
./bin/mcp-server

# Send JSON-RPC request (type or paste, then Ctrl+D):
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}

# Should respond with server info
```

**Test with Claude Desktop:**
1. Point config to local binary
2. Enable debug mode
3. Check logs for errors

### Adding New Tools

Edit `internal/mcp/tools.go`:

```go
func (s *Server) registerTools() {
    s.tools = []Tool{
        // ... existing tools ...
        {
            Name:        "new_tool",
            Description: "Description of what the tool does",
            InputSchema: map[string]interface{}{
                "type": "object",
                "properties": map[string]interface{}{
                    "param_name": map[string]interface{}{
                        "type": "string",
                        "description": "Parameter description",
                    },
                },
                "required": []string{"param_name"},
            },
            Handler: handleNewTool,
        },
    }
}

func handleNewTool(client *Client, args map[string]interface{}) (string, error) {
    // Implementation
    return "result", nil
}
```

## Production Deployment

### Recommended Setup

1. **Dedicated API Server**: Run REST API on dedicated server
2. **Long-lived Token**: Generate token with 1-year expiry
3. **Secure Token Storage**: Store token in environment, not in config file
4. **HTTPS**: Use HTTPS for REST API
5. **Monitoring**: Monitor API usage and errors

### Example Production Setup

**Server side:**
```bash
# Start daemon with persistent JWT secret
export CONTAINARIUM_JWT_SECRET="$(openssl rand -base64 32)"
containarium daemon --rest --address 0.0.0.0 --port 8080

# Generate long-lived token
containarium token generate \
  --username mcp-production \
  --roles admin \
  --expiry 8760h \
  --secret "$CONTAINARIUM_JWT_SECRET"
```

**Client side (Claude Desktop):**
```json
{
  "mcpServers": {
    "containarium": {
      "command": "/usr/local/bin/mcp-server",
      "env": {
        "CONTAINARIUM_SERVER_URL": "https://containarium.company.com",
        "CONTAINARIUM_JWT_TOKEN": "eyJhbGci..."
      }
    }
  }
}
```

## Roadmap

Future enhancements:

- [ ] **SSH Key Management**: Add/remove SSH keys via MCP
- [ ] **Container Resize**: Resize container resources
- [ ] **Snapshot Management**: Create/restore snapshots
- [ ] **Log Streaming**: Stream container logs to Claude
- [ ] **Terminal Access**: Interactive terminal via Claude
- [ ] **Bulk Operations**: Create/delete multiple containers at once
- [ ] **Template Support**: Use container templates
- [ ] **Resource Quotas**: Enforce user/team quotas

## Contributing

Contributions welcome! See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

Apache 2.0 - See [LICENSE](../LICENSE)

## Support

- **Documentation**: [docs/](.)
- **Issues**: [GitHub Issues](https://github.com/footprintai/containarium/issues)
- **Discussions**: [GitHub Discussions](https://github.com/footprintai/containarium/discussions)
