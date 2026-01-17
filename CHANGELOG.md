# Changelog

All notable changes to Containarium will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Auto-initialization of Incus infrastructure** on daemon startup
  - Automatically creates storage pool (`default` with `dir` driver)
  - Automatically creates network bridge (`incusbr0`)
  - Automatically configures default profile with network and storage devices
  - Safe default subnet: `10.100.0.1/24` (avoids conflicts with common networks like 10.0.0.0/8)
- **Network subnet configuration** via `--network-subnet` flag
  - Customize container network subnet (default: `10.100.0.1/24`)
  - Example: `containarium daemon --network-subnet 192.168.50.1/24`
- **Skip infrastructure initialization** via `--skip-infra-init` flag
  - Useful when infrastructure is already configured manually
  - Example: `containarium daemon --skip-infra-init`
- **New Incus client methods** for infrastructure management:
  - `EnsureNetwork()` - Create network if not exists
  - `EnsureStorage()` - Create storage pool if not exists
  - `EnsureDefaultProfile()` - Configure default profile
  - `InitializeInfrastructure()` - One-call setup for all infrastructure
  - `GetNetworkSubnet()` - Get configured subnet for a network
- **HTTP/REST client for CLI** - Alternative to gRPC for remote server communication
  - `--http` flag to use HTTP/REST API instead of gRPC
  - `--token` flag for JWT authentication token
  - Supports all CLI commands: `create`, `list`, `delete`, `info`
  - Example: `containarium list --server http://host:8080 --http --token <JWT>`
- **Web UI server management with localStorage persistence**
  - Server configurations (URL, name, token) stored in browser localStorage
  - Persists across browser sessions until explicitly removed
  - Add Server dialog with connection testing
  - Edit server via pencil icon on server tab
  - Remove server via X icon on server tab
  - Multi-server support with tab-based switching
- **SSH public key input in Web UI** - Option to provide your own SSH public key
  - Uncheck "Auto-generate SSH key pair" to reveal public key input field
  - Paste existing SSH public key instead of auto-generating

### Changed
- CLI now supports both gRPC and HTTP protocols equally (neither marked as deprecated)
- Server address flag help text updated to reflect dual-protocol support

### Fixed
- **Network subnet conflicts** - Previously manual network setup could conflict with host network
  - Auto-initialization uses safe default `10.100.0.1/24` instead of common `10.0.3.0/24`
  - Prevents loss of connectivity when running Containarium inside LXC containers

## [0.3.0] - 2026-01-15

### Added
- **Web UI Dashboard** - Modern browser-based container management interface
  - Real-time container metrics (CPU, Memory, Disk usage with progress bars)
  - Multi-server management with tab-based interface
  - Container lifecycle management (create, start, stop, delete)
  - Browser-based terminal access via WebSocket
  - Client-side SSH key generation (keys never sent to server)
  - Embedded in Go binary for single-file deployment
  - Available at `/webui/` endpoint
- **Container Metrics API** - Real-time resource monitoring
  - CPU usage percentage calculation
  - Memory and disk usage with limits
  - Network I/O statistics
  - Process count per container
- **WebSocket Terminal** - Browser-based container shell access
  - Direct terminal access without SSH client
  - Runs as container user via Incus exec
  - JWT token authentication via query parameter
- **Makefile improvements**:
  - `make webui` - Build Next.js web UI for embedding
  - `make clean-ui` - Clean swagger-ui and webui files
  - `make clean-all` - Clean all artifacts including UI
- **REST API support via grpc-gateway** - HTTP/JSON API alongside existing gRPC
  - All 10 container management endpoints exposed via REST
  - Dual-protocol support: gRPC (port 50051) + REST (port 8080)
  - Backward compatible - existing gRPC clients unaffected
- **JWT token authentication** for REST API
  - Bearer token authentication with configurable expiry
  - Token generation command: `containarium token generate`
  - Support for token secret files (`--jwt-secret-file`)
  - Roles-based authorization support
- **Interactive Swagger UI** for API exploration
  - Available at `/swagger-ui/` endpoint
  - CDN fallback for zero-setup experience
  - Embedded files support for offline use
- **OpenAPI specification generation**
  - Automatic OpenAPI/Swagger spec generation from proto files
  - Available at `/swagger.json` endpoint
  - Comprehensive API documentation with examples
- **Enhanced daemon command** with new REST flags:
  - `--rest` - Enable/disable REST API (default: true)
  - `--http-port` - Configure REST API port (default: 8080)
  - `--jwt-secret` / `--jwt-secret-file` - Configure JWT authentication
  - `--swagger-dir` - Swagger files directory
- **Complete upgrade system** for the entire Containarium stack:
  - `containarium upgrade self` - Upgrade Containarium binary from GitHub releases
  - `containarium upgrade host` - Upgrade host dependencies (Incus, system packages, kernel modules)
  - `containarium upgrade containers` - Upgrade software inside containers (Docker, base OS, tools)
  - `containarium upgrade all` - Upgrade everything in the correct order
- **Changelog display** during upgrades - shows release notes before upgrading
- **Runtime version checking** with warnings for outdated components
- **Rolling upgrades** for containers (`--rolling` flag) to minimize downtime
- **Reboot detection** - automatically detects if system reboot is required after upgrade
- **Mock server** for local testing of upgrade commands (`test/mock-server.py`)
- **Test fixtures** for upgrade testing without needing real releases

### Fixed
- Docker build support by requiring Incus 6.19+ (fixes CVE-2025-52881 AppArmor bug)
- Terraform startup scripts now install Incus from Zabbly repository
- All Terraform scripts (both Containarium repo and kafeido-infra) updated for Incus 6.19+
- Fixed typo in proto package name: `continariumv1` → `containariumv1`
- **JWT secret handling** - Fixed trailing newline issues when reading JWT secrets from files
- **Gateway mTLS connection** - Fixed HTTP gateway to properly connect to gRPC server with mTLS
- **Installation script (`hacks/install.sh`)** - Multiple critical fixes:
  - Fixed Incus package conflict by adding APT pinning to prioritize Zabbly repository over Ubuntu
  - Added `--batch --yes` flags to GPG commands for non-interactive SSH installation
  - Changed `incus-tools` to `incus-extra` (newer package name in Zabbly repository)
  - Fixed systemd service permissions (`ProtectSystem=false`, `ProtectHome=false`)
  - Added automatic TLS certificate generation step for mTLS
- **Google Guest Agent race condition** - Fixed `/etc/passwd` lock conflicts during user creation
  - Stop google-guest-agent → remove stale locks → create user → restart agent
  - Prevents "cannot lock /etc/passwd; try again later" errors
- **Container creation improvements**:
  - Fixed image format parsing to support both `ubuntu:24.04` and `images:ubuntu/24.04` formats
  - Fixed SSH directory creation (`.ssh` not created before writing `authorized_keys`)
  - Added `--force` flag to delete and recreate existing containers
- **StopContainer API** - Fixed to use proper API field (`Force: true`) instead of string action

### Changed
- Updated documentation with Incus 6.19+ system requirements
- Renamed `upgrade incus` to `upgrade host` for better clarity (includes more than just Incus)
- Upgrade commands now provide detailed progress and status information
- Proto generation now includes grpc-gateway and OpenAPI plugins

### Security
- JWT-based authentication for REST API with configurable token expiry
- Bearer token validation middleware
- CORS support with configurable origins
- Preserved mTLS authentication for gRPC (unchanged)

## [0.2.0] - 2025-01-12

### Added
- Container resize command (`containarium resize`) for dynamic resource adjustment
  - Resize CPU, memory, and disk without downtime
  - Advanced CPU options: range allocation and core pinning
- mTLS (mutual TLS) support for daemon API
  - Certificate generation command (`containarium cert generate`)
  - Client certificate authentication
  - Secure remote management
- Comprehensive documentation for resize functionality
- Remote gRPC daemon for container management
- Production deployment examples with Terraform

### Security
- Added mTLS authentication for daemon API
- SSH hardening in jump server configuration
- Fail2ban integration for brute-force protection

### Infrastructure
- Terraform modules for GCE deployment
- Support for spot instances with persistent storage
- ZFS-backed storage for disk quotas
- Hyperdisk support for C4 instance types

---

## Upgrade Instructions

### Upgrading from 0.1.x to 0.2.0

**Important:** This version requires Incus 6.19 or later for Docker build support.

1. Upgrade Incus on your host:
   ```bash
   # Add Zabbly repository
   curl -fsSL https://pkgs.zabbly.com/key.asc | sudo gpg --dearmor -o /usr/share/keyrings/zabbly-incus.gpg
   echo 'deb [signed-by=/usr/share/keyrings/zabbly-incus.gpg] https://pkgs.zabbly.com/incus/stable noble main' | sudo tee /etc/apt/sources.list.d/zabbly-incus-stable.list
   sudo apt update
   sudo apt install --only-upgrade incus incus-tools incus-client
   ```

2. Upgrade Containarium binary:
   ```bash
   curl -fsSL https://github.com/FootprintAI/Containarium/releases/download/0.2.0/containarium-linux-amd64 -o /tmp/containarium
   sudo install -m 755 /tmp/containarium /usr/local/bin/containarium
   sudo systemctl restart containarium  # if running as daemon
   ```

3. Verify versions:
   ```bash
   incus --version     # Should show 6.19 or later
   containarium version
   ```

---

## Version History

- **0.3.0** (2026-01-15) - Web UI Dashboard, Container Metrics, WebSocket Terminal
- **0.2.0** (2025-01-12) - Resize command, mTLS support, production readiness
- **0.1.0** (Initial release) - Basic container management, SSH jump server

[Unreleased]: https://github.com/FootprintAI/Containarium/compare/0.3.0...HEAD
[0.3.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.3.0
[0.2.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.2.0
