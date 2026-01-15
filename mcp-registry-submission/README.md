# Containarium MCP Server

> **Manage LXC containers directly from Claude Desktop using natural language**

Control your Containarium infrastructure through conversational AI. Create, manage, monitor, and delete containers without leaving Claude.

## 🎯 What is Containarium?

[Containarium](https://github.com/footprintai/containarium) is a production-ready platform for running isolated Linux development environments using LXC containers. It enables you to:

- Run 50-250 containers on a single VM
- Save up to 92% on cloud costs vs VM-per-user
- Provide full Linux environments with Docker support
- Manage containers via CLI, REST API, or now **Claude Desktop**

## 🚀 Features

This MCP server provides 8 powerful tools:

- **create_container** - Spin up new containers with custom CPU, memory, and disk
- **list_containers** - View all containers and their states
- **get_container** - Get detailed information about specific containers
- **delete_container** - Remove containers (with force option)
- **start_container** - Boot stopped containers
- **stop_container** - Gracefully shutdown containers
- **get_metrics** - Monitor CPU, memory, disk, and network usage
- **get_system_info** - Check host system resources

## 📦 Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/footprintai/containarium/main/scripts/install-mcp.sh | bash
```

### Manual Installation

**macOS (Intel):**
```bash
curl -L https://github.com/footprintai/containarium/releases/latest/download/mcp-server-darwin-amd64 -o /usr/local/bin/mcp-server
chmod +x /usr/local/bin/mcp-server
```

**macOS (Apple Silicon):**
```bash
curl -L https://github.com/footprintai/containarium/releases/latest/download/mcp-server-darwin-arm64 -o /usr/local/bin/mcp-server
chmod +x /usr/local/bin/mcp-server
```

**Linux:**
```bash
curl -L https://github.com/footprintai/containarium/releases/latest/download/mcp-server-linux-amd64 -o /usr/local/bin/mcp-server
chmod +x /usr/local/bin/mcp-server
```

## ⚙️ Configuration

### Prerequisites

1. **Containarium Server Running:**
   ```bash
   containarium daemon --rest --jwt-secret "your-secret-key"
   ```

2. **Generate JWT Token:**
   ```bash
   containarium token generate \
     --username mcp-client \
     --roles admin \
     --expiry 8760h \
     --secret "your-secret-key"
   ```

### Claude Desktop Configuration

Add to `~/.config/claude/claude_desktop_config.json` (macOS/Linux) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "containarium": {
      "command": "/usr/local/bin/mcp-server",
      "env": {
        "CONTAINARIUM_SERVER_URL": "http://localhost:8080",
        "CONTAINARIUM_JWT_TOKEN": "your-jwt-token-here"
      }
    }
  }
}
```

**For remote servers:**
```json
{
  "mcpServers": {
    "containarium": {
      "command": "/usr/local/bin/mcp-server",
      "env": {
        "CONTAINARIUM_SERVER_URL": "https://containarium.yourcompany.com",
        "CONTAINARIUM_JWT_TOKEN": "your-production-token"
      }
    }
  }
}
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CONTAINARIUM_SERVER_URL` | Yes | URL of Containarium REST API |
| `CONTAINARIUM_JWT_TOKEN` | Yes | JWT token with admin role |
| `CONTAINARIUM_DEBUG` | No | Enable debug logging (`true`/`false`) |

## 💬 Usage Examples

Once configured, interact with your containers through Claude:

**Create containers:**
- "Create a dev container for Alice with 8GB memory and 4 CPU cores"
- "Set up a container for Bob with 100GB disk space"

**List and monitor:**
- "Show me all running containers"
- "What's the CPU usage on Alice's container?"
- "List all containers and their resource usage"

**Manage lifecycle:**
- "Stop Bob's container"
- "Start Charlie's container"
- "Delete the testuser container"

**System info:**
- "Show me system information"
- "How many containers are running?"
- "What's the host system status?"

## 🏗️ Architecture

```
Claude Desktop
      ↓ MCP Protocol (stdio)
  MCP Server
      ↓ HTTP + JWT
Containarium REST API
      ↓
Container Manager
      ↓
Incus/LXC
```

## 📚 Documentation

- **Quick Start**: [5-Minute Setup](https://github.com/footprintai/containarium/blob/main/docs/MCP-QUICKSTART.md)
- **Full Guide**: [MCP Integration](https://github.com/footprintai/containarium/blob/main/docs/MCP-INTEGRATION.md)
- **Main Docs**: [Containarium Documentation](https://github.com/footprintai/containarium)

## 🔒 Security

- **JWT Authentication**: Secure token-based authentication
- **HTTPS Support**: Works with TLS-enabled servers
- **Role-Based Access**: Requires admin role for container management
- **No Hardcoded Secrets**: All credentials via environment variables

## 🐛 Troubleshooting

**"Tools not showing in Claude":**
- Restart Claude Desktop after config changes
- Check config file path and JSON syntax
- Verify binary is executable: `ls -la /usr/local/bin/mcp-server`

**"Connection refused":**
- Ensure Containarium daemon is running
- Check server URL in config
- Test API: `curl http://localhost:8080/health`

**"Unauthorized":**
- Verify JWT token matches server secret
- Check token hasn't expired
- Ensure token has admin role

See [full troubleshooting guide](https://github.com/footprintai/containarium/blob/main/docs/MCP-INTEGRATION.md#troubleshooting).

## 🤝 Contributing

Contributions welcome! See [Contributing Guide](https://github.com/footprintai/containarium/blob/main/CONTRIBUTING.md).

## 📄 License

Apache 2.0 - See [LICENSE](https://github.com/footprintai/containarium/blob/main/LICENSE)

## 🙏 Support

- **Issues**: [GitHub Issues](https://github.com/footprintai/containarium/issues)
- **Discussions**: [GitHub Discussions](https://github.com/footprintai/containarium/discussions)
- **Documentation**: [docs/](https://github.com/footprintai/containarium/tree/main/docs)

---

**Built with ❤️ by [FootprintAI](https://github.com/footprintai)**

**Star us on GitHub!** ⭐ https://github.com/footprintai/containarium
