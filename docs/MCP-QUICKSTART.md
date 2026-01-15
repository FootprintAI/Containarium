# MCP Quick Start Guide

Get Claude Desktop controlling your Containarium containers in 5 minutes!

## Prerequisites

- Containarium installed and running
- Claude Desktop installed
- Basic terminal access

## Step 1: Start Containarium with REST API (2 min)

```bash
# Start the daemon with REST API
containarium daemon --rest --jwt-secret "my-test-secret"

# You should see:
# ═══════════════════════════════════════════════════════════════
#   🔐 JWT Secret (Auto-Generated)
# ═══════════════════════════════════════════════════════════════
#   my-test-secret
# ═══════════════════════════════════════════════════════════════
#
# Starting dual server (gRPC + REST)...
# gRPC server listening on :50051
# Starting HTTP/REST gateway on :8080
```

Keep this terminal open!

## Step 2: Generate JWT Token (1 min)

In a **new terminal**:

```bash
# Generate a JWT token for Claude
containarium token generate \
  --username claude-mcp \
  --roles admin \
  --expiry 8760h \
  --secret "my-test-secret"

# Output:
# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNsYXVkZS1tY3AiLCJyb2xlcyI6WyJhZG1pbiJdLCJleHAiOjE3NDAxMjM0NTZ9.abcd1234...
```

**Copy this token!** You'll need it in the next step.

## Step 3: Build MCP Server (1 min)

```bash
# Build the MCP server
make build-mcp

# Install it (optional - or just use bin/mcp-server)
sudo make install-mcp
```

## Step 4: Configure Claude Desktop (1 min)

### Find your config file:

- **macOS/Linux**: `~/.config/claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Edit or create the file:

```json
{
  "mcpServers": {
    "containarium": {
      "command": "/usr/local/bin/mcp-server",
      "env": {
        "CONTAINARIUM_SERVER_URL": "http://localhost:8080",
        "CONTAINARIUM_JWT_TOKEN": "PASTE_YOUR_TOKEN_HERE"
      }
    }
  }
}
```

**Replace `PASTE_YOUR_TOKEN_HERE` with the token from Step 2!**

**If using local build** (not installed):
```json
{
  "mcpServers": {
    "containarium": {
      "command": "/Users/yourname/path/to/Containarium/bin/mcp-server",
      "env": {
        "CONTAINARIUM_SERVER_URL": "http://localhost:8080",
        "CONTAINARIUM_JWT_TOKEN": "YOUR_TOKEN_HERE",
        "CONTAINARIUM_DEBUG": "true"
      }
    }
  }
}
```

## Step 5: Restart Claude Desktop

1. **Quit** Claude Desktop completely (Cmd+Q on Mac)
2. **Reopen** Claude Desktop
3. Wait for it to fully load

## Step 6: Test It! 🎉

Open Claude Desktop and try these commands:

### Test 1: Create a Container
```
Create a development container for user testuser with 4 CPU cores and 8GB of memory
```

Claude should respond with:
```
✅ Container created successfully!

Name: testuser-container
Username: testuser
State: Running
IP Address: 10.0.3.100
CPU: 4
Memory: 8GB
Disk: 50GB

Container testuser-container created successfully
```

### Test 2: List Containers
```
Show me all containers
```

Claude should list all your containers with details.

### Test 3: Get Container Details
```
Show me details about testuser's container
```

Claude will display complete container information.

### Test 4: Get Metrics
```
What are the resource metrics for all containers?
```

Claude will show CPU, memory, disk, and network usage.

### Test 5: Cleanup
```
Delete the testuser container
```

## Troubleshooting

### "I don't have tools to manage containers"

**Problem**: Claude doesn't see the MCP server

**Solutions**:
1. ✅ Did you **restart** Claude Desktop after editing config?
2. ✅ Check config file path is correct
3. ✅ Validate JSON syntax:
   ```bash
   cat ~/.config/claude/claude_desktop_config.json | jq .
   ```
4. ✅ Check MCP server binary exists:
   ```bash
   ls -la /usr/local/bin/mcp-server
   # or
   ls -la /path/to/your/bin/mcp-server
   ```

### "Connection refused"

**Problem**: Can't connect to Containarium REST API

**Solutions**:
1. ✅ Is the daemon running?
   ```bash
   ps aux | grep containarium
   ```
2. ✅ Is it listening on port 8080?
   ```bash
   curl http://localhost:8080/health
   # Should return: {"status":"healthy"}
   ```
3. ✅ Check firewall isn't blocking port 8080

### "Invalid token" / "Unauthorized"

**Problem**: JWT token authentication failed

**Solutions**:
1. ✅ Token and daemon using same secret?
   - Daemon: `--jwt-secret "my-test-secret"`
   - Token: `--secret "my-test-secret"`
   - They must match exactly!
2. ✅ Token not expired?
   ```bash
   # Check expiry (should be a future timestamp)
   echo "YOUR_TOKEN" | cut -d'.' -f2 | base64 -d | jq .exp
   ```
3. ✅ Generate a fresh token with matching secret

### View Logs

Enable debug mode and check logs:

**Config with debug:**
```json
{
  "mcpServers": {
    "containarium": {
      "command": "/usr/local/bin/mcp-server",
      "env": {
        "CONTAINARIUM_SERVER_URL": "http://localhost:8080",
        "CONTAINARIUM_JWT_TOKEN": "your-token",
        "CONTAINARIUM_DEBUG": "true"
      }
    }
  }
}
```

**Find logs:**
- macOS: `~/Library/Logs/Claude/`
- Linux: `~/.local/state/claude/logs/`
- Windows: `%APPDATA%\Claude\logs\`

## What's Next?

### Try More Commands

```
Create a container for alice with 100GB disk space

List all containers and tell me which one is using the most CPU

Show system information

Stop bob's container

Start bob's container again
```

### Production Setup

For production use:
1. Use strong JWT secret: `openssl rand -base64 32`
2. Use HTTPS for REST API
3. Generate long-lived token (8760h = 1 year)
4. Secure token storage (not in config file)
5. Enable rate limiting

See [MCP-INTEGRATION.md](MCP-INTEGRATION.md) for production deployment guide.

### Learn More

- **Full Documentation**: [MCP-INTEGRATION.md](MCP-INTEGRATION.md)
- **Available Tools**: See tool list in main docs
- **Security Best Practices**: See security section
- **Troubleshooting**: Comprehensive troubleshooting guide

## Need Help?

- **Issues**: [GitHub Issues](https://github.com/footprintai/containarium/issues)
- **Discussions**: [GitHub Discussions](https://github.com/footprintai/containarium/discussions)
- **Documentation**: [docs/](.)

---

**Enjoy managing containers with Claude! 🚀**
