package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/pkg/core/expose"
)

// ephemeralKeyDir returns the directory the MCP server writes ephemeral
// private keys to. Defaults to $HOME/.containarium/keys. Overridable via
// CONTAINARIUM_KEYS_DIR for operators who want a non-default location.
// Returns "" if no usable directory can be determined (HOME unset and no
// override) — the caller should treat that as "skip the file write".
func ephemeralKeyDir() string {
	if d := os.Getenv("CONTAINARIUM_KEYS_DIR"); d != "" {
		return d
	}
	home := os.Getenv("HOME")
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".containarium", "keys")
}

// saveEphemeralPrivateKey writes the freshly-minted private key to disk so
// the operator doesn't have to lift it out of the tool response. Returns
// the path it wrote to on success, or an error describing why it didn't.
// On any error the caller should keep showing the key text in the response
// so the agent at least has the option to save it itself.
func saveEphemeralPrivateKey(username string, key []byte) (string, error) {
	dir := ephemeralKeyDir()
	if dir == "" {
		return "", fmt.Errorf("no key directory available (HOME and CONTAINARIUM_KEYS_DIR both unset)")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, username)
	// Write atomically: create at a temp name in the same dir, chmod, then
	// rename. Avoids leaving a half-written 0600 file under the username
	// path if the write is interrupted, and avoids ever leaving the key
	// readable to other users on the filesystem.
	f, err := os.CreateTemp(dir, "."+username+".tmp.*")
	if err != nil {
		return "", fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpPath := f.Name()
	// Best-effort cleanup if anything below fails before the rename.
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("chmod 0600 on %s: %w", tmpPath, err)
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write key bytes: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return "", fmt.Errorf("rename %s -> %s: %w", tmpPath, path, err)
	}
	tmpPath = "" // rename consumed it
	return path, nil
}

// Tool represents an MCP tool (function).
//
// Phase 1.7 — RequiredScope names the least-privilege scope
// (`<resource>:<action>`) a JWT must carry to invoke this
// tool. Empty string means "no scope needed" (introspection
// helpers only). The MCP server filters tools/list and
// rejects tools/call when the JWT's scope set doesn't cover
// the requirement; see internal/auth/scopes.go for the
// taxonomy and semantics.
//
// Backwards compat: tokens minted before Phase 1.7 have no
// scopes claim. HasScope treats nil as "no restriction", so
// existing tokens continue to see every tool.
type Tool struct {
	Name          string
	Description   string
	InputSchema   map[string]interface{}
	Handler       ToolHandler
	RequiredScope string
}

// ToolHandler is a function that handles a tool call
type ToolHandler func(client API, args map[string]interface{}) (string, error)

// registerTools registers all available MCP tools
func (s *Server) registerTools() {
	s.tools = []Tool{
		{
			Name: "create_container",
			Description: "Create a new LXC container under a username. Returns the container's " +
				"name, IP address, and resources.\n\n" +
				"SSH key handling: if you OMIT `ssh_keys`, an ephemeral ed25519 keypair is " +
				"generated client-side. The public half is installed on the container; the " +
				"private half is auto-saved to `~/.containarium/keys/<username>` with mode " +
				"0600 by this MCP server itself (no agent action required) and ALSO echoed " +
				"into the tool response as a fallback. If you pass `ssh_keys`, those are " +
				"used as-is and no ephemeral key is generated (useful when reusing an " +
				"operator's existing key for SSH alias convenience).\n\n" +
				"AFTER creation, to operate inside the container (simplest path):\n" +
				"  1. The private key is already on disk at ~/.containarium/keys/<name>.\n" +
				"     (Only act on the key text in the response if the response says auto-\n" +
				"     save failed.)\n" +
				"  2. The tool response includes a ready-to-paste ssh command:\n" +
				"       ssh -i ~/.containarium/keys/<name> \\\n" +
				"           -o IdentitiesOnly=yes -o PreferredAuthentications=publickey \\\n" +
				"           <name>@<sentinel-host>\n" +
				"     Use Bash to run it. No edits to ~/.ssh/config required.\n" +
				"     IdentitiesOnly=yes is REQUIRED — without it, ssh offers every\n" +
				"     identity in ~/.ssh/, each of which sshpiper's failtoban counts\n" +
				"     as a failed attempt. One careless ssh can burn the IP's ban quota.\n" +
				"  3. Inside the container, apt install / write files / start services.\n" +
				"  4. Call `expose_port` to make a container port reachable on a public hostname.\n\n" +
				"Shipping your own code into the container (instead of just apt-installing\n" +
				"things): use one of the dedicated transfer tools rather than scp-ing by\n" +
				"hand. They reuse the SSH path above and handle the failtoban / shell-stack\n" +
				"quirks for you.\n" +
				"  - `push`: git-style. Ships committed history; delta on subsequent calls\n" +
				"    via `git bundle`. Refuses on dirty tree unless `include_wip=true`.\n" +
				"    Use when you've committed locally and want commit-by-commit shipping.\n" +
				"  - `sync`: rsync-style. Mirrors the working directory including .git/,\n" +
				"    uncommitted modifications, untracked files. Delta on subsequent calls\n" +
				"    via content-hash diff. Use when you want the container to reflect\n" +
				"    your local state right now, WIP and all.\n\n" +
				"Diagnostic: if SSH or the workflow fails, call `debug_container` BEFORE\n" +
				"reporting the failure. It surfaces host-side state the agent can't see\n" +
				"(user account presence, shell wrapper, recent sshd journal lines) and\n" +
				"returns a likely_cause + ordered next_actions.\n\n" +
				"Optional convenience (skip if you don't want to touch ~/.ssh/config):\n" +
				"  Call the `sync_ssh_config` MCP tool to generate a self-contained\n" +
				"  ssh_config file and Include line. After that, `ssh <name>` works directly.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username for the container (required)",
					},
					"cpu": map[string]interface{}{
						"type":        "string",
						"description": "CPU limit (e.g., '4' for 4 cores, default: 4)",
					},
					"memory": map[string]interface{}{
						"type":        "string",
						"description": "Memory limit (e.g., '4GB', '2048MB', default: 4GB)",
					},
					"disk": map[string]interface{}{
						"type":        "string",
						"description": "Disk limit (e.g., '50GB', '100GB', default: 50GB)",
					},
					"ssh_keys": map[string]interface{}{
						"type":        "array",
						"items":       map[string]string{"type": "string"},
						"description": "SSH public keys to authorize (optional)",
					},
					"image": map[string]interface{}{
						"type":        "string",
						"description": "Container image (default: images:ubuntu/24.04)",
					},
					"enable_podman": map[string]interface{}{
						"type":        "boolean",
						"description": "Enable Podman support (default: true)",
					},
					"gpu": map[string]interface{}{
						"type":        "string",
						"description": "Deprecated single-GPU field; prefer 'gpus'. GPU device ID for passthrough (e.g., '0' for first GPU, PCI address, or empty for none)",
					},
					"gpus": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "GPU devices for passthrough — one entry per GPU (index like '0'/'1' or PCI address). Use for multi-GPU boxes. Supersedes 'gpu' when set.",
					},
					"os_type": map[string]interface{}{
						"type":        "string",
						"description": "Container OS type: 'ubuntu' (default), 'rocky9' (dev/test), 'rhel9' (production). Overrides image when set.",
						"enum":        []string{"", "ubuntu", "rocky9", "rhel9"},
					},
					"monitoring": map[string]interface{}{
						"type":        "boolean",
						"description": "Opt the container into application-emitted OpenTelemetry. When true, the daemon stamps the LXC with OTEL_EXPORTER_OTLP_ENDPOINT (and related env vars) pointing at the platform's core OTel collector, so any OTel SDK inside the container ships telemetry without app-side configuration. Default false. The daemon's own cgroup-level metrics for the container (CPU/mem/disk/net) are independent of this flag and continue for every container regardless.",
					},
					"pool": map[string]interface{}{
						"type":        "string",
						"description": "Place the container on any healthy backend tagged with this pool (e.g., 'demo', 'lab', 'prod'). When omitted, the request lands on the primary/local backend. Use list_backends to see available pools. Mutually exclusive with backend_id unless the chosen backend is already in this pool (the daemon validates consistency).",
					},
					"backend_id": map[string]interface{}{
						"type":        "string",
						"description": "Place the container on a specific backend by ID (e.g., 'tunnel-node-a-gpu'). Look up valid IDs via list_backends. Use pool instead when any backend in a pool will do.",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleCreateContainer,
		},
		{
			Name: "list_containers",
			Description: "List all containers with name, username, state, IP, and resources. " +
				"Useful as a first step (\"what's already running?\") and after create_container " +
				"to confirm the new container's IP. Read-only — no side effects.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleListContainers,
		},
		{
			Name:        "get_container",
			Description: "Get detailed information about a specific container including metrics",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container to get",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleGetContainer,
		},
		{
			Name: "debug_container",
			Description: "Diagnose why SSH to a container is failing. Call this BEFORE " +
				"reporting an SSH failure to the user — it surfaces host-side state " +
				"the agent can't see (whether the Linux user account exists on the " +
				"backend, whether the user's shell file resolves, recent sshd journal " +
				"lines mentioning the user) and returns a likely_cause plus an ordered " +
				"next_actions list.\n\n" +
				"Typical failure modes this catches:\n" +
				"  - Container missing or stopped (start it or recreate)\n" +
				"  - Host user account missing (daemon never created or it was wiped)\n" +
				"  - Host user's shell points at a file that doesn't exist on the\n" +
				"    backend — sshd rejects every login\n" +
				"  - sshd journal lines with a concrete \"User X not allowed because\n" +
				"    …\" reason\n\n" +
				"Returns a JSON object with: containerState, hostUserExists, hostUserShell, " +
				"hostUserShellExists, recentSshdRejections, likelyCause, nextActions, " +
				"sourceRepo, daemonVersion, and sshIngressHost — the advertised public " +
				"SSH entrypoint (sentinel host); EMPTY means NO external SSH entrypoint " +
				"(direct/in-network mode), so next_actions drop the sentinel hints and " +
				"there is no jump host to chase (reach the container by IP or its " +
				"in-network deploy pipeline). When the structured fields are inconclusive, " +
				"use sourceRepo + daemonVersion to fetch the daemon's source and dig " +
				"deeper (grep internal/sentinel/, pkg/core/, etc.). Read-only — no side effects.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container to debug",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleDebugContainer,
		},
		{
			Name: "move_container",
			Description: "Migrate a container from this daemon to a peer daemon using " +
				"pre-copy snapshot + delta refresh. The container's hostname, ACME cert, " +
				"persistent disk state, and user accounts all transfer. Process memory " +
				"state is NOT preserved (use stateful=true if CRIU is configured on " +
				"both ends, which is rare in practice).\n\n" +
				"Downtime is sub-second on ZFS/btrfs storage with low write rate; " +
				"potentially minutes on dir-pool or highly active workloads. The route " +
				"store target_ip swap propagates to Caddy within ~5 seconds.\n\n" +
				"Prereqs: the target backend must be visible in /v1/backends, and the " +
				"source's incusd must have the target configured as an `incus remote` " +
				"(remote name == target_backend_id by convention).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container to migrate",
					},
					"target_backend_id": map[string]interface{}{
						"type":        "string",
						"description": "Backend ID of the destination daemon (look it up in list_backends)",
					},
					"max_iterations": map[string]interface{}{
						"type":        "integer",
						"description": "Max delta-refresh iterations [0..10], default 3. Each iteration shrinks the dirty set; lower = faster migration but bigger final delta.",
					},
					"delta_threshold_seconds": map[string]interface{}{
						"type":        "integer",
						"description": "If a delta iteration completes in less than this many seconds, skip remaining iterations and cut over. Default 5.",
					},
					"stateful": map[string]interface{}{
						"type":        "boolean",
						"description": "Attempt CRIU-based live migration (preserves process state). Requires CRIU on both ends, doesn't work with podman/docker-in-LXC. Default false.",
					},
				},
				"required": []string{"username", "target_backend_id"},
			},
			Handler: handleMoveContainer,
		},
		{
			Name:        "resize_container",
			Description: "Change a container's CPU / memory / disk allocation in place. At least one of cpu, memory, or disk must be provided; the others default to no change. Disk can only grow — the server rejects shrinks. The container stays running (no restart needed for CPU/memory; disk resize is online via ZFS).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container to resize",
					},
					"cpu": map[string]interface{}{
						"type":        "string",
						"description": "New CPU limit (e.g. \"4\" for 4 cores, \"2-4\" for a range). Empty/omitted = no change.",
					},
					"memory": map[string]interface{}{
						"type":        "string",
						"description": "New memory limit (e.g. \"8GB\", \"4096MB\"). Empty/omitted = no change.",
					},
					"disk": map[string]interface{}{
						"type":        "string",
						"description": "New disk size (e.g. \"100GB\"). Can only grow — shrinks are rejected. Empty/omitted = no change.",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleResizeContainer,
		},
		{
			Name:        "set_secret",
			Description: "Create or update a tenant secret stored encrypted (AES-256-GCM) on the daemon. The value will be stamped as environment.<NAME> on the LXC on next CreateContainer / StartContainer / refresh_secrets. Idempotent — repeated calls bump the version and replace the value. Names must be uppercase env-var-style (^[A-Z_][A-Z0-9_]*$, max 128 chars); values capped at 64 KiB.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{"type": "string", "description": "Tenant username owning the secret"},
					"name":     map[string]interface{}{"type": "string", "description": "Env-var-style name (uppercase + digits + underscore, e.g. OPENAI_API_KEY)"},
					"value":    map[string]interface{}{"type": "string", "description": "Plaintext value; the daemon encrypts before persisting"},
				},
				"required": []string{"username", "name", "value"},
			},
			Handler: handleSetSecret,
		},
		{
			Name:        "get_secret",
			Description: "Read a single tenant secret's plaintext value. Always audit-logged. Use this to verify what you just wrote or to hand a value to a script via stdout — be mindful where the output goes.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{"type": "string", "description": "Tenant username"},
					"name":     map[string]interface{}{"type": "string", "description": "Secret name"},
				},
				"required": []string{"username", "name"},
			},
			Handler: handleGetSecret,
		},
		{
			Name:        "list_secrets",
			Description: "List a tenant's secret names + versions + timestamps. Never returns the plaintext values — use get_secret per-name for that (audit-logged separately).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{"type": "string", "description": "Tenant username"},
				},
				"required": []string{"username"},
			},
			Handler: handleListSecrets,
		},
		{
			Name:        "delete_secret",
			Description: "Remove a tenant secret from the store. Does NOT cascade to env-var stamps on running containers — call refresh_secrets separately if the deletion should reach the next exec without a container restart.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{"type": "string", "description": "Tenant username"},
					"name":     map[string]interface{}{"type": "string", "description": "Secret name"},
				},
				"required": []string{"username", "name"},
			},
			Handler: handleDeleteSecret,
		},
		{
			Name:        "refresh_secrets",
			Description: "Re-stamp env vars on the LXC from the current secret-store state. Useful after rotation when the next exec'd process should see the new value without a full container restart. Running processes keep their old env (POSIX inherit-at-fork); new execs see the refresh.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{"type": "string", "description": "Tenant username"},
				},
				"required": []string{"username"},
			},
			Handler: handleRefreshSecrets,
		},
		{
			Name:        "toggle_monitoring",
			Description: "Enable or disable application-emitted OpenTelemetry on an existing container without recreating it. When enabling, the daemon stamps OTEL_EXPORTER_OTLP_ENDPOINT + related env vars and restarts the container so the app picks them up. Use this to retrofit monitoring onto containers created before --monitoring was wired in. Requires the daemon to have an OTel collector endpoint configured.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container",
					},
					"enabled": map[string]interface{}{
						"type":        "boolean",
						"description": "true to enable monitoring (stamp OTEL_* env + restart), false to disable (unset OTEL_* env + restart)",
					},
				},
				"required": []string{"username", "enabled"},
			},
			Handler: handleToggleMonitoring,
		},
		{
			Name:        "delete_container",
			Description: "Delete a container permanently",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container to delete",
					},
					"force": map[string]interface{}{
						"type":        "boolean",
						"description": "Force delete even if container is running (default: false)",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleDeleteContainer,
		},
		{
			Name:        "start_container",
			Description: "Start a stopped container. When waitForReady is true the daemon blocks until the container's primary TCP port (from its route record) accepts, or the 30s probe timeout elapses — the response then reports whether the probe timed out.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container to start",
					},
					"waitForReady": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, block until the container's primary TCP port accepts or 30s elapses (default false)",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleStartContainer,
		},
		{
			Name:        "toggle_auto_sleep",
			Description: "Opt a container into auto-sleep. Enabled containers are stopped after `idleThresholdMinutes` of network inactivity, which frees their RAM and CPU. They are restarted on the next HTTP request (Phase 3, coming). This sets a per-container metadata flag; it doesn't sleep the container itself — use `stop_container` if you want to sleep it now.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container",
					},
					"enabled": map[string]interface{}{
						"type":        "boolean",
						"description": "true to opt in, false to opt out",
					},
					"idleThresholdMinutes": map[string]interface{}{
						"type":        "integer",
						"description": "Idle minutes before Phase 2 would sleep the container. Default 15. Ignored when enabled=false.",
					},
				},
				"required": []string{"username", "enabled"},
			},
			Handler: handleToggleAutoSleep,
		},
		{
			Name:        "stop_container",
			Description: "Stop a running container",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container to stop",
					},
					"force": map[string]interface{}{
						"type":        "boolean",
						"description": "Force stop (kill) instead of graceful shutdown (default: false)",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleStopContainer,
		},
		{
			Name:        "get_metrics",
			Description: "Get runtime metrics (CPU, memory, disk, network) for containers",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of specific container (optional, empty for all containers)",
					},
				},
			},
			Handler: handleGetMetrics,
		},
		{
			Name:        "get_system_info",
			Description: "Get information about the Containarium host system",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleGetSystemInfo,
		},
		{
			Name:        "check_for_updates",
			Description: "Check whether a newer Containarium release is available. Returns the running daemon version, the latest GitHub release (cached), and whether an update is available.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleCheckForUpdates,
		},
		{
			Name:        "upgrade_backend",
			Description: "Upgrade a backend's daemon to the binary the sentinel currently serves, immediately instead of waiting for the periodic auto-update tick. The daemon SHA-verifies and smoke-tests the binary, swaps it atomically (keeping the old one as .old), and restarts. Admin-only. Omit backend_id (or pass the local id) to upgrade this daemon; pass a peer id from list_backends to upgrade that peer. Async: a successful local upgrade restarts the daemon, so confirm the new version via list_backends.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"backend_id": map[string]interface{}{
						"type":        "string",
						"description": "Backend to upgrade (from list_backends). Empty = the local/primary daemon.",
					},
					"force": map[string]interface{}{
						"type":        "boolean",
						"description": "Upgrade even if the sentinel-served binary already matches the running one. Default false.",
					},
				},
			},
			Handler: handleUpgradeBackend,
		},
		{
			Name:        "get_upgrade_status",
			Description: "Poll an upgrade started by upgrade_backend. Returns the status (in_progress, completed, failed, noop, unknown), the version at trigger time, and any error. Note: a successful LOCAL upgrade restarts the daemon and drops the job, so this returns 'unknown' afterward — compare the backend version in list_backends to confirm.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"upgrade_id": map[string]interface{}{
						"type":        "string",
						"description": "Upgrade id returned by upgrade_backend.",
					},
				},
				"required": []string{"upgrade_id"},
			},
			Handler: handleGetUpgradeStatus,
		},
		{
			Name: "list_backends",
			Description: "List the cluster's backend hosts (the local daemon plus any " +
				"tunnel-connected peers). Returns id, type (local/tunnel), health, " +
				"hostname, OS, container count, and GPU inventory per backend. Use " +
				"this when the agent needs to reason about peer topology — e.g. " +
				"\"which host has GPU capacity?\" or \"is peer X healthy?\".",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleListBackends,
		},
		{
			Name: "get_backend",
			Description: "Get a single backend's details by ID — same fields as list_backends " +
				"but for one host, plus an explicit \"not found\" error when the ID doesn't " +
				"exist. Useful when an agent has a backend ID from list_backends or from a " +
				"container's backendId field and wants to drill down (\"is this peer healthy?\", " +
				"\"how many containers does it have?\", \"does it have a GPU?\").",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "Backend ID, as returned by list_backends or as a container's backendId field.",
					},
				},
				"required": []string{"id"},
			},
			Handler: handleGetBackend,
		},
		{
			Name: "backend_validate_gpu",
			Description: "Check that GPU passthrough works inside an LXC on a backend. The " +
				"daemon launches a throwaway nvidia.runtime LXC, runs nvidia-smi inside, " +
				"tears it down, and returns status + GPU model + driver version. Use before " +
				"provisioning a GPU container, or after a VFIO/driver change. Omit backend_id " +
				"for the local/primary host; pass a peer id (from list_backends) to validate " +
				"that peer's GPU. Admin-only; creates and deletes a short-lived container (~30s).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"backend_id": map[string]interface{}{
						"type":        "string",
						"description": "Backend to validate (from list_backends). Empty = local/primary host.",
					},
					"pci": map[string]interface{}{
						"type":        "string",
						"description": "Validate a specific GPU by PCI address (e.g. '0000:01:00.0'). Empty = all GPUs.",
					},
				},
			},
			Handler: handleBackendValidateGPU,
		},
		{
			Name: "push",
			Description: "Push committed git history into a container via real `git push` over " +
				"SSH (laptop -> sentinel -> sshpiper -> container). On first call, sets up a " +
				"bare git repo at ~/work.git inside the container plus a post-receive hook " +
				"that checks out the working tree to ~/work and optionally runs the configured " +
				"deploy_cmd. On subsequent calls, just runs `git push` — the hook fires " +
				"server-side.\n\n" +
				"This is the *commit-only* + *release* mode. Working-tree changes that aren't " +
				"committed DO NOT ship by default — if the working tree has uncommitted or " +
				"untracked files, the tool refuses with a clear error. Pass `include_wip=true` " +
				"to auto-create a WIP commit, push, and rewind the local repo afterwards.\n\n" +
				"If you want to mirror the entire local state (uncommitted changes + untracked " +
				"files + stash refs) without commit ceremony, use the `sync` tool instead.\n\n" +
				"deploy_cmd: when set, the post-receive hook runs the given shell command " +
				"inside the container's work-tree directory after each successful push. Use " +
				"it for `systemctl restart`, `make build && systemctl restart`, etc. The hook " +
				"is rewritten on every push, so changing deploy_cmd between calls just " +
				"updates the hook.\n\n" +
				"After the first push, a local git remote (default 'containarium-<username>') " +
				"is configured on the local repo. From any clone with that remote, " +
				"`git push containarium-<username> <branch>` works directly without invoking " +
				"this tool — same plumbing.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Container username (same value used by create_container).",
					},
					"local_path": map[string]interface{}{
						"type":        "string",
						"description": "Local git repo path (default: current working directory).",
					},
					"branch": map[string]interface{}{
						"type":        "string",
						"description": "Branch to push (default: current HEAD branch).",
					},
					"remote_path": map[string]interface{}{
						"type":        "string",
						"description": "Working-tree directory inside the container (default: ~/work). The bare repo lives at <remote_path>.git.",
					},
					"include_wip": map[string]interface{}{
						"type":        "boolean",
						"description": "If true and the working tree is dirty, auto-create a WIP commit, push, then rewind the local repo. Default false (refuse on dirty tree).",
					},
					"deploy_cmd": map[string]interface{}{
						"type":        "string",
						"description": "Shell command to run on the container after each successful push (inside the work-tree directory). Empty = no deploy hook command, but the working tree is still checked out.",
					},
					"remote_name": map[string]interface{}{
						"type":        "string",
						"description": "Local git remote name to configure. Default 'containarium-<username>'.",
					},
					"sentinel": map[string]interface{}{
						"type":        "string",
						"description": "Sentinel SSH host override. Default: the container's ssh_host (the sentinel it belongs to, reported by the daemon).",
					},
					"key_path": map[string]interface{}{
						"type":        "string",
						"description": "SSH private key path override. Default ~/.containarium/keys/<username>.",
					},
				},
				"required": []string{"username"},
			},
			Handler: handlePush,
		},
		{
			Name: "sync",
			Description: "Mirror a local directory into a container — rsync-style, but using " +
				"a one-shot content-hash diff + tar so it works through Containarium's " +
				"shell stack without needing rsync's bidirectional protocol.\n\n" +
				"Carries everything in the working tree: committed history, uncommitted " +
				"modifications, untracked files, stash refs (because `.git/` is part of " +
				"the working directory). Subsequent calls ship only the content-hash delta.\n\n" +
				"This is the *mirror* mode. Use it when you want the container to exactly " +
				"reflect your local state including WIP. If you want commit-only semantics " +
				"(atomic per commit, refuses on dirty tree), use `push` instead.\n\n" +
				"By default, files that exist on the remote but not locally are LEFT in " +
				"place. Pass `delete=true` for true rsync --delete semantics.\n\n" +
				"Default excludes (substring match): node_modules/, .terraform/, " +
				"__pycache__/, .pytest_cache/, .venv/, venv/, .DS_Store, .idea/, .vscode/. " +
				"Pass an `exclude` array to add to (not replace) the defaults.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Container username (same value used by create_container).",
					},
					"local_path": map[string]interface{}{
						"type":        "string",
						"description": "Local directory to mirror (default: current working directory).",
					},
					"remote_path": map[string]interface{}{
						"type":        "string",
						"description": "Destination directory inside the container (default: ~/work).",
					},
					"delete": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, remove files on the remote that don't exist locally (rsync --delete semantics). Default false.",
					},
					"exclude": map[string]interface{}{
						"type":        "array",
						"items":       map[string]string{"type": "string"},
						"description": "Additional exclude patterns (substring match), added to the sensible defaults.",
					},
					"sentinel": map[string]interface{}{
						"type":        "string",
						"description": "Sentinel SSH host override. Default: the container's ssh_host (the sentinel it belongs to, reported by the daemon).",
					},
					"key_path": map[string]interface{}{
						"type":        "string",
						"description": "SSH private key path override. Default ~/.containarium/keys/<username>.",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleSync,
		},
		{
			Name: "security_scan",
			Description: "Run a security scan on a container. Triggers one or more of the daemon's " +
				"three scanner subsystems: ClamAV (malware in container files), pentest " +
				"(CVE-style vulnerabilities in installed packages), ZAP (web-app DAST against " +
				"any exposed HTTP services).\n\n" +
				"All three scanners honor the `username` argument and scope the scan to that " +
				"single container — pentest filters its target list to routes + container " +
				"records belonging to the user, ZAP filters routes by user, ClamAV scans only " +
				"that container's files. The scan-run records persist the container scope so " +
				"future per-container queries surface only the relevant runs.\n\n" +
				"This is a one-shot operator-invoked action — call it when you suspect or " +
				"need to confirm a container's security posture. The scans run asynchronously " +
				"on the daemon; this tool returns once the trigger is accepted. After waiting " +
				"(see `pollHint` in the response), call `security_findings` to read results.\n\n" +
				"Typical durations:\n" +
				"  - clamav: seconds (file walk + signature match)\n" +
				"  - pentest: tens of seconds (per-target probe)\n" +
				"  - zap: minutes (active spider + attack passes)\n\n" +
				"For continuous/scheduled scanning, the cloud product offers a hosted " +
				"security-patch agent (see the cloud roadmap). This OSS tool is the one-shot " +
				"BYOA equivalent.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Container username (same value used by create_container).",
					},
					"kind": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"clamav", "pentest", "zap", "all"},
						"description": "Which scanner(s) to run. Default 'all' triggers all three.",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleSecurityScan,
		},
		{
			Name: "security_findings",
			Description: "List security findings for a container, normalized across the three " +
				"scanner subsystems (ClamAV, pentest, ZAP). Returns a single shape per finding " +
				"so the agent doesn't have to branch on scanner internals:\n" +
				"  - kind:          'clamav' | 'pentest' | 'zap'\n" +
				"  - id:            daemon-side row ID; pass to security_remediate\n" +
				"  - severity:      'critical' | 'high' | 'medium' | 'low' | 'info'\n" +
				"  - title:         short description\n" +
				"  - description:   detail (optional)\n" +
				"  - containerName: which container the finding pertains to\n" +
				"  - target:        URL/IP:port for pentest+ZAP (optional)\n" +
				"  - fixAvailable:  true → `security_remediate` can act on this row.\n\n" +
				"Today only pentest findings have `fixAvailable=true` (the daemon's " +
				"`RemediatePentestFinding` runs a package upgrade). ClamAV findings need " +
				"a quarantine workflow; ZAP findings need web-app code fixes — neither has " +
				"an auto-fix path yet. Filter to one scanner with `kind`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Container username.",
					},
					"kind": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"clamav", "pentest", "zap", "all"},
						"description": "Restrict to one scanner. Default 'all' merges results.",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleSecurityFindings,
		},
		{
			Name: "security_remediate",
			Description: "Attempt to auto-fix a security finding. Currently only works on " +
				"pentest-kind findings where `fixAvailable=true` (the daemon's " +
				"`RemediatePentestFinding` runs a package upgrade). ClamAV and ZAP findings " +
				"return an error here — they need different fix workflows that don't exist " +
				"yet.\n\n" +
				"This is a one-shot, operator-confirmed action. Do NOT chain " +
				"`security_scan → security_findings → security_remediate` autonomously " +
				"without user confirmation — surface the findings to the user first, let " +
				"them decide which to fix.\n\n" +
				"Returns `success`, `packageName`, `oldVersion`, `newVersion` on a successful " +
				"package upgrade. A failed remediate doesn't put the finding into a wedged " +
				"state — the same finding can be remediated again after fixing the underlying " +
				"reason (locked package, missing apt index, etc.).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_id": map[string]interface{}{
						"type":        "integer",
						"description": "Finding ID from security_findings (`id` field).",
					},
				},
				"required": []string{"finding_id"},
			},
			Handler: handleSecurityRemediate,
		},
		{
			Name: "install_zap",
			Description: "Download and install OWASP ZAP into this host's security container. " +
				"Admin-only, one-time-per-host setup — `security_scan` (kind=zap) and the " +
				"scheduled ZAP scan cycle both require this to have been run at least once.\n\n" +
				"Without it, every ZAP scan job on an uninstalled host used to fail after a " +
				"generic 120-second timeout, indistinguishable from a slow daemon start, and " +
				"repeat forever on every subsequent scan (#960) — this call is what closes " +
				"that gap. Safe to call again on an already-installed host; it reports " +
				"'already installed' instead of erroring.\n\n" +
				"Takes no arguments — a daemon manages exactly one security container, so " +
				"there's no per-container or per-host identifier to pass.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleInstallZap,
		},
		{
			Name: "sync_ssh_config",
			Description: "Generate a self-contained ssh_config covering every reachable container " +
				"and write it to ~/.containarium/ssh_config. After this call, `ssh <username>` " +
				"works from any shell — no CLI install required.\n\n" +
				"Call this right after create_container so the new container's SSH alias is " +
				"available immediately. The first time you use it, you also need to add a single " +
				"line to your ~/.ssh/config to wire it in:\n" +
				"  Include ~/.containarium/ssh_config\n" +
				"That's a one-time setup; subsequent sync calls just refresh the file.\n\n" +
				"Two modes:\n" +
				"  - Direct (default): each container's IP is the SSH HostName. Works when the " +
				"    container's LAN IP is reachable from where you're running ssh.\n" +
				"  - Via sentinel (set `sentinel`): all containers route through the sentinel " +
				"    via sshpiper. Use this when containers don't have public IPs.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sentinel": map[string]interface{}{
						"type":        "string",
						"description": "Sentinel SSH endpoint (e.g. sentinel.example.com or sentinel.example.com:2222). Empty = direct mode.",
					},
					"identity_file": map[string]interface{}{
						"type":        "string",
						"description": "IdentityFile path to render in every Host block. For ephemeral-keypair containers, agents typically pass ~/.containarium/keys/<username>.",
					},
					"include_stopped": map[string]interface{}{
						"type":        "boolean",
						"description": "Include stopped containers in the config. Default false (only running containers).",
					},
					"out": map[string]interface{}{
						"type":        "string",
						"description": "Output path override. Default: ~/.containarium/ssh_config.",
					},
				},
			},
			Handler: handleSyncSSHConfig,
		},
		{
			Name: "connect",
			Description: "Get SSH access to one of your boxes using the token you're already " +
				"authenticated with — connect authorizes a managed key for you, so there's " +
				"no SSH-key setup. Two modes:\n\n" +
				"  - Config (default, omit `exec`): authorizes the key and returns the ready " +
				"    `ssh user@host` command for a human to run in their terminal. An MCP " +
				"    call has no interactive terminal, so this hands the connection off.\n" +
				"  - Exec (set `exec`): runs that one command on the box over SSH and returns " +
				"    its stdout, stderr, and exit_code. Use this to operate the box — run a " +
				"    build, tail a log, check a process — without a terminal.\n\n" +
				"By default each `exec` call is independent (stateless), so make commands " +
				"self-contained (e.g. `cd /app && make`). For state that must persist across " +
				"calls (a working dir, env vars, a background process), pass `session` with a " +
				"name: the command runs inside a named tmux session ON THE BOX, so a later call " +
				"with the same `session` sees the same shell — `cd /app` then `pwd` returns " +
				"/app. A human can `tmux attach` to that session too. The SSH target is the " +
				"box's ssh_host (or its IP if the daemon reports none) and its SSH username.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"box": map[string]interface{}{
						"type":        "string",
						"description": "Name of the box to connect to.",
					},
					"exec": map[string]interface{}{
						"type":        "string",
						"description": "A single command to run on the box; returns its stdout/stderr/exit_code. Omit for config mode (returns the ready ssh command instead).",
					},
					"session": map[string]interface{}{
						"type":        "string",
						"description": "Run inside a named tmux session on the box (stateful — cd/env/background jobs persist across calls with the same name). Requires `exec`. Needs tmux on the box.",
					},
					"user": map[string]interface{}{
						"type":        "string",
						"description": "Override the SSH login user (default: the box's SSH username).",
					},
					"host": map[string]interface{}{
						"type":        "string",
						"description": "Override the SSH host (default: the box's ssh_host, else its IP).",
					},
				},
				"required": []interface{}{"box"},
			},
			Handler: handleConnect,
		},
		{
			Name: "list_routes",
			Description: "List the proxy routes currently registered on the sentinel — the " +
				"domain → container:port mappings that `expose_port` creates. Returns each " +
				"route's domain (`fullDomain`), target container IP + port, active state, " +
				"and any associated app metadata.\n\n" +
				"Use this to:\n" +
				"  - Audit what's currently exposed (e.g. before adding a new route, check " +
				"    that the intended hostname isn't already claimed).\n" +
				"  - Recover after a session loses track of which containers have which " +
				"    public URLs.\n" +
				"  - Filter by `username` to see only one container's routes, or " +
				"    `active_only=true` to skip disabled ones.\n\n" +
				"Read-only — no side effects. For TCP passthrough routes (raw L4, not HTTPS), " +
				"those live on a different daemon endpoint and aren't included here yet — " +
				"file a request if you need them surfaced.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Restrict to routes whose target container belongs to this username. Empty = no filter.",
					},
					"active_only": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, omit disabled routes. Default false (include all).",
					},
				},
			},
			Handler: handleListRoutes,
		},
		{
			Name: "delete_route",
			Description: "Remove a proxy route by its domain — the unexpose counterpart of " +
				"`expose_port`. After this, https://<domain>/ no longer reaches any container, " +
				"and (on the cloud) the subdomain's quota slot is freed for reuse.\n\n" +
				"Use this to:\n" +
				"  - Take an app offline / retire a public hostname.\n" +
				"  - Clean up a stale route left by a deleted container.\n" +
				"  - Free a subdomain slot when you've hit your route quota and need to " +
				"    expose something else.\n\n" +
				"Idempotent: deleting an already-gone route succeeds (no error). Pass the " +
				"full domain as shown by `list_routes` (`fullDomain`).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]interface{}{
						"type":        "string",
						"description": "The route's domain to remove, e.g. 'blog-acme.containarium.dev' (the `fullDomain` from list_routes).",
					},
				},
				"required": []string{"domain"},
			},
			Handler: handleDeleteRoute,
		},
		{
			Name: "expose_port",
			Description: "Expose a container's port on a public hostname. Resolves the " +
				"container's IP, then registers a domain → container:port route in the " +
				"sentinel reverse proxy. After this completes, https://<domain>/ reaches " +
				"the container's port (the sentinel handles TLS via automatic ACME).\n\n" +
				"This is typically the LAST step of a deploy flow:\n" +
				"  create_container → ssh in via Bash → install/configure service → expose_port → curl the URL.\n\n" +
				"Make sure DNS for <domain> already points at the sentinel (a wildcard A " +
				"record for `*.<your-subdomain>.<your-zone>` covers all the apps you'll " +
				"expose during a session). The agent doesn't have to wait for DNS; that's " +
				"a one-time operator setup.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Container identifier (same value used by create_container / get_container).",
					},
					"container_port": map[string]interface{}{
						"type":        "integer",
						"description": "Port the app listens on inside the container, e.g. 8080.",
					},
					"domain": map[string]interface{}{
						"type":        "string",
						"description": "Public hostname to route from, e.g. 'blog.example.com'. The sentinel must already be DNS-pointed at this hostname or a wildcard parent.",
					},
					"description": map[string]interface{}{
						"type":        "string",
						"description": "Optional human-readable note for the route (shown in route_list).",
					},
				},
				"required": []string{"username", "container_port", "domain"},
			},
			Handler: handleExposePort,
		},
		{
			Name: "list_recipes",
			Description: "List the platform's built-in recipes. A recipe is a " +
				"one-command deployment of a GPU/app workload (e.g. ollama, " +
				"llama.cpp): it provisions a new dedicated container, runs the " +
				"recipe's image inside it, and exposes its ports. Use this to " +
				"discover deployable recipe IDs before calling deploy_recipe.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleListRecipes,
		},
		{
			Name: "deploy_recipe",
			Description: "Deploy a recipe as a new dedicated container. Provisions " +
				"the container (with optional GPU passthrough), runs the recipe's " +
				"image inside it, and exposes the configured ports. In v1 the " +
				"recipe deploys on the backend this MCP server's daemon manages; " +
				"GPU recipes require the `gpu` argument. Discover recipe IDs and " +
				"their parameters with list_recipes.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"recipe_id": map[string]interface{}{
						"type":        "string",
						"description": "Recipe to deploy, e.g. 'ollama' (see list_recipes).",
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Identity for the new container (container is named '<name>-container').",
					},
					"gpu": map[string]interface{}{
						"type":        "string",
						"description": "GPU device ID for passthrough, e.g. '0'. Required for GPU recipes.",
					},
					"parameters": map[string]interface{}{
						"type":        "object",
						"description": "Recipe parameters as key→value (e.g. {\"model\": \"llama3\"}). See the recipe's declared parameters via list_recipes / get.",
					},
				},
				"required": []string{"recipe_id", "name"},
			},
			Handler: handleDeployRecipe,
		},
		{
			Name: "list_agent_skills",
			Description: "List the platform's built-in agent skills. A skill is a " +
				"packaged, runnable agent: a box (a recipe) plus a typed manifest " +
				"(system prompt, allowed scopes, allowed peers). Use this to " +
				"discover skill IDs before calling run_agent_skill.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleListAgentSkills,
		},
		{
			Name: "run_agent_skill",
			Description: "Run an agent skill in a box. Provisions the skill's box, " +
				"mints a token scoped to exactly the skill's allowed_scopes, and " +
				"seeds the system prompt + token + task input into the box. In " +
				"Phase 0 the in-box agent loop is the box image's job, so the " +
				"returned artifact is empty. Discover skill IDs with " +
				"list_agent_skills.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"skill_id": map[string]interface{}{
						"type":        "string",
						"description": "Skill to run, e.g. 'hello-agent' (see list_agent_skills).",
					},
					"input_json": map[string]interface{}{
						"type":        "string",
						"description": "Task input as a JSON string (defaults to {}).",
					},
				},
				"required": []string{"skill_id"},
			},
			Handler: handleRunAgentSkill,
		},
		{
			Name: "call_agent",
			Description: "Delegate a task to a running peer agent over the " +
				"agent-to-agent (A2A) transport and return its artifact. The peer " +
				"must already be running (run_agent_skill). In Phase 1 the peer's " +
				"in-box A2A server receives the task; until that ships a call " +
				"returns an error. Discover peer IDs with list_agent_skills.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"to_peer_id": map[string]interface{}{
						"type":        "string",
						"description": "Peer skill/agent id to deliver the task to (see list_agent_skills).",
					},
					"from_skill_id": map[string]interface{}{
						"type":        "string",
						"description": "Calling skill id, for attribution and the future allowed_peers check.",
					},
					"input_json": map[string]interface{}{
						"type":        "string",
						"description": "Task input as a JSON string (defaults to {}).",
					},
				},
				"required": []string{"to_peer_id"},
			},
			Handler: handleCallAgent,
		},
		{
			Name: "list_crews",
			Description: "List the platform's built-in crews. A crew is a " +
				"collaborating set of agent skills wired by a topology " +
				"(pipeline/orchestrator/freeform). Use this to discover crew IDs " +
				"before calling run_crew.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleListCrews,
		},
		{
			Name: "run_crew",
			Description: "Run a crew: validate its topology against the members' " +
				"allowed_peers, provision each member's box under one trace id, and " +
				"return the run handle. Discover crew IDs with list_crews.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"crew_id": map[string]interface{}{
						"type":        "string",
						"description": "Crew to run, e.g. 'hello-crew' (see list_crews).",
					},
					"input_json": map[string]interface{}{
						"type":        "string",
						"description": "Crew input as a JSON string (defaults to {}).",
					},
				},
				"required": []string{"crew_id"},
			},
			Handler: handleRunCrew,
		},
		{
			Name: "revoke_token",
			Description: "Admin: revoke a JWT by its jti. The token is rejected " +
				"on the next request that names it. Pairs with the daemon's " +
				"revocation list (Phase 1.2). Idempotent — repeated revokes " +
				"preserve the original reason. Use when a token leaks, when " +
				"rotating an agent credential, or when terminating an active " +
				"session. The jti is in the audit-log entry of any request the " +
				"token made; you can also base64-decode the JWT payload to find " +
				"it. Requires admin role AND tokens:write scope.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"jti": map[string]interface{}{
						"type":        "string",
						"description": "The token's jti claim (required).",
					},
					"reason": map[string]interface{}{
						"type":        "string",
						"description": "Free-form reason recorded for forensics (e.g. 'leaked_to_public_gist', 'rotate'). Default: 'operator_revoke'.",
					},
					"expires_at": map[string]interface{}{
						"type":        "string",
						"description": "RFC3339 timestamp matching the token's own exp claim. Sets the cleanup horizon so the revocation row prunes when the token would have naturally expired. Default: now + daemon max lifetime.",
					},
				},
				"required": []string{"jti"},
			},
			Handler: handleRevokeToken,
		},
	}

	// Append compose-autostart tools (Phase C — daemon RPC is
	// shipped in PR #324; these MCP wrappers are the §4 piece of
	// issue #317). Defined in compose_tools.go so the giant tools
	// literal above stays readable.
	s.tools = append(s.tools, composeTools()...)

	// Runner-provision tools (CLI-mirrored). Appended here so the
	// tools.go slice literal stays focused on container/secret/
	// route lifecycle; the actual Tool definitions live in
	// runner_tools.go alongside their handlers.
	s.tools = append(s.tools, runnerTools()...)

	// Database-backup tools (CLI-mirrored). Defined in backup_tools.go
	// alongside their handlers; thin wrappers over the BackupService
	// gateway that `containarium backup` also calls.
	s.tools = append(s.tools, backupTools()...)

	// KMS admin tools (kms_tools.go) — thin wrappers over the
	// KmsService gateway that `containarium kms` also calls.
	s.tools = append(s.tools, kmsTools()...)

	// Phase 1.7 — assign required scope per tool. Done as a
	// post-pass so the slice literals above stay short and
	// the security policy lives in one auditable spot. New
	// tools added to the slice above MUST also gain an
	// entry here or they default to `""` (no-scope, allowed
	// to any token) — see TestEveryToolHasScope which
	// enforces this in CI.
	scopeByTool := toolScopeAssignments()
	for i := range s.tools {
		s.tools[i].RequiredScope = scopeByTool[s.tools[i].Name]
	}
}

// toolScopeAssignments is the canonical scope-per-tool
// table. Kept as a function so tests can assert
// completeness against the registered tool list.
func toolScopeAssignments() map[string]string {
	return map[string]string{
		// container lifecycle
		"create_container":   auth.ScopeContainersWrite,
		"delete_container":   auth.ScopeContainersWrite,
		"start_container":    auth.ScopeContainersWrite,
		"stop_container":     auth.ScopeContainersWrite,
		"resize_container":   auth.ScopeContainersWrite,
		"move_container":     auth.ScopeContainersWrite,
		"toggle_monitoring":  auth.ScopeContainersWrite,
		"toggle_auto_sleep":  auth.ScopeContainersWrite,
		"list_containers":    auth.ScopeContainersRead,
		"get_container":      auth.ScopeContainersRead,
		"debug_container":    auth.ScopeContainersRead,
		"get_metrics":        auth.ScopeContainersRead,
		"get_system_info":    auth.ScopeContainersRead,
		"check_for_updates":  auth.ScopeContainersRead,
		"upgrade_backend":    auth.ScopeContainersWrite,
		"get_upgrade_status": auth.ScopeContainersRead,
		"list_backends":      auth.ScopeContainersRead,
		"get_backend":        auth.ScopeContainersRead,
		// validate-gpu creates+deletes a throwaway container (a write op);
		// the daemon additionally enforces admin role.
		"backend_validate_gpu": auth.ScopeContainersWrite,
		// secrets
		"set_secret":      auth.ScopeSecretsWrite,
		"delete_secret":   auth.ScopeSecretsWrite,
		"refresh_secrets": auth.ScopeSecretsWrite,
		"get_secret":      auth.ScopeSecretsRead,
		"list_secrets":    auth.ScopeSecretsRead,
		// routes / network exposure
		"list_routes":  auth.ScopeRoutesRead,
		"expose_port":  auth.ScopeRoutesWrite,
		"delete_route": auth.ScopeRoutesWrite,
		// recipes — declarative GPU/app deploys
		"list_recipes":  auth.ScopeContainersRead,
		"deploy_recipe": auth.ScopeContainersWrite,

		"list_agent_skills": auth.ScopeAgentsRead,
		"run_agent_skill":   auth.ScopeAgentsRun,
		"call_agent":        auth.ScopeAgentsCall,
		"list_crews":        auth.ScopeCrewsRead,
		"run_crew":          auth.ScopeCrewsRun,
		// database backups
		"create_backup":  auth.ScopeBackupsWrite,
		"restore_backup": auth.ScopeBackupsWrite,
		"list_backups":   auth.ScopeBackupsRead,
		// KMS envelope-encryption administration (admin-only)
		"kms_status":              auth.ScopeKMSAdmin,
		"kms_envelope_coverage":   auth.ScopeKMSAdmin,
		"kms_migrate_to_envelope": auth.ScopeKMSAdmin,
		// security tools
		"security_scan":      auth.ScopeSecurityWrite,
		"security_remediate": auth.ScopeSecurityWrite,
		"security_findings":  auth.ScopeSecurityRead,
		// install_zap is admin-only (the daemon also enforces
		// RoleAdmin server-side); scope-gated the same as the other
		// security-write tools at the MCP layer.
		"install_zap": auth.ScopeSecurityWrite,
		// developer-loop tools
		"push":            auth.ScopeCodeWrite,
		"sync":            auth.ScopeCodeWrite,
		"sync_ssh_config": auth.ScopeSSHWrite,
		"connect":         auth.ScopeSSHWrite,
		// JWT lifecycle (admin)
		"revoke_token": auth.ScopeTokensWrite,
		// Runner provisioning — provision/remove create or delete
		// boxes; list is read-only. Reuses the containers:* scopes
		// since the underlying operations are box-level CRUD.
		"provision_runners": auth.ScopeContainersWrite,
		"remove_runner":     auth.ScopeContainersWrite,
		"list_runners":      auth.ScopeContainersRead,
		// Compose-autostart (platform MCP tools added in #325).
		// Discovery is read-only; enable/disable + status mutate or
		// inspect the LXC's systemd-user units. Reuses containers:*
		// scopes since the operations are box-local lifecycle.
		"compose_discover": auth.ScopeContainersRead,
		"compose_status":   auth.ScopeContainersRead,
		"compose_enable":   auth.ScopeContainersWrite,
		"compose_disable":  auth.ScopeContainersWrite,
	}
}

// Tool handlers

func handleCreateContainer(client API, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	req := CreateContainerRequest{
		Username: username,
		Resources: &ResourceLimits{
			CPU:    getStringArg(args, "cpu", "4"),
			Memory: getStringArg(args, "memory", "4GB"),
			Disk:   getStringArg(args, "disk", "50GB"),
		},
		Image:        getStringArg(args, "image", "images:ubuntu/24.04"),
		EnablePodman: getBoolArg(args, "enable_podman", true),
		GPU:          getStringArg(args, "gpu", ""),
		GPUs:         getStringSliceArg(args, "gpus"),
		Monitoring:   getBoolArg(args, "monitoring", false),
		Pool:         getStringArg(args, "pool", ""),
		BackendID:    getStringArg(args, "backend_id", ""),
	}

	// Handle SSH keys. If the caller passes ssh_keys explicitly we use
	// them as-is. If they don't, we generate an ephemeral ed25519
	// keypair CLIENT-SIDE (the private key never travels the network)
	// and return it in the response. This is the common case for
	// agent-driven workflows: the agent doesn't have to know about
	// local file paths or the operator's existing keys.
	var ephemeralPrivKey []byte
	if sshKeys, ok := args["ssh_keys"].([]interface{}); ok && len(sshKeys) > 0 {
		for _, key := range sshKeys {
			if keyStr, ok := key.(string); ok {
				req.SSHKeys = append(req.SSHKeys, keyStr)
			}
		}
	} else {
		pubKey, privKey, err := generateEphemeralSSHKey(
			fmt.Sprintf("containarium-%s ephemeral key", username),
		)
		if err != nil {
			return "", fmt.Errorf("generate ephemeral ssh key: %w", err)
		}
		req.SSHKeys = []string{pubKey}
		ephemeralPrivKey = privKey
	}

	resp, err := client.CreateContainer(req)
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	result := "✅ Container created successfully!\n\n"
	result += fmt.Sprintf("Name: %s\n", resp.Container.Name)
	result += fmt.Sprintf("Username: %s\n", resp.Container.Username)
	result += fmt.Sprintf("State: %s\n", resp.Container.State)
	// Surface the RESOLVED backend/pool the box actually landed on. If a
	// requested backend_id didn't match any host, placement silently falls back
	// to the default (cloud #686) — showing where it really landed makes that
	// immediately visible instead of discovering it later via an egress test.
	if resp.Container.BackendID != "" {
		result += fmt.Sprintf("Backend: %s\n", resp.Container.BackendID)
	}
	if resp.Container.Pool != "" {
		result += fmt.Sprintf("Pool: %s\n", resp.Container.Pool)
	}
	if reqBackend := getStringArg(args, "backend_id", ""); reqBackend != "" && resp.Container.BackendID != "" && resp.Container.BackendID != reqBackend {
		result += fmt.Sprintf("⚠️  Requested backend_id %q but the box landed on %q (the requested id matched no host; placement used the default).\n",
			reqBackend, resp.Container.BackendID)
	}
	if resp.Container.Network != nil && resp.Container.Network.IPAddress != "" {
		result += fmt.Sprintf("IP Address: %s\n", resp.Container.Network.IPAddress)
	}
	if resp.Container.Resources != nil {
		result += fmt.Sprintf("CPU: %s\n", resp.Container.Resources.CPU)
		result += fmt.Sprintf("Memory: %s\n", resp.Container.Resources.Memory)
		result += fmt.Sprintf("Disk: %s\n", resp.Container.Resources.Disk)
	}
	result += fmt.Sprintf("\n%s", resp.Message)

	// Always tell the caller how to reach the box and which tool to use —
	// independent of whether we generated a key. The daemon stamps ssh_host
	// with the reachable SSH target (the sentinel this container belongs to,
	// or empty for a direct deployment), so the caller never has to discover
	// a host or set CONTAINARIUM_SENTINEL_HOST. Without this, agents that pass
	// their own ssh_keys got no connection guidance at all and tended to go
	// hunting for the env var and give up (see issue #658).
	result += "\n\n--- CONNECTING ---\n"
	result += "⏳ PROVISIONING TAKES MINUTES: the create is async — the box installs\n"
	result += "packages and SSH keys AFTER this response returns. Poll get_container\n"
	result += "until state is RUNNING before attempting SSH; an early SSH failure is\n"
	result += "NOT an error, and deleting the box because of one aborts a create that\n"
	result += "was still in progress.\n\n"
	if resp.Container.SSHHost != "" {
		result += fmt.Sprintf("SSH target: %s@%s  (resolved from ssh_host — no env/config needed)\n",
			resp.Container.Username, resp.Container.SSHHost)
	} else {
		result += "SSH target: direct / no-sentinel deployment — the daemon reported no\n"
		result += "ssh_host. Reach the container at its IP"
		if resp.Container.Network != nil && resp.Container.Network.IPAddress != "" {
			result += fmt.Sprintf(" (%s)", resp.Container.Network.IPAddress)
		}
		result += ", or call sync_ssh_config for an alias.\n"
	}
	result += "\nTo run code on this box, prefer the MCP tools — they resolve the SSH\n"
	result += "target from ssh_host automatically (you do NOT need to know a hostname\n"
	result += "or set CONTAINARIUM_SENTINEL_HOST):\n"
	result += "  - connect (exec mode): run a command inside the box.\n"
	result += "  - push / sync: transfer code into the box.\n"

	if ephemeralPrivKey != nil {
		// Write the key to the local filesystem ourselves rather than
		// asking the agent to do it. The agent could forget the save step
		// (or its context could be compacted between create_container and
		// the next ssh call), at which point the key is gone — the daemon
		// never stores a copy. Doing the write here makes "container
		// created" and "key on disk" a single atomic-from-the-caller's-
		// perspective operation.
		savedPath, saveErr := saveEphemeralPrivateKey(resp.Container.Username, ephemeralPrivKey)

		result += "\n\n--- EPHEMERAL SSH PRIVATE KEY ---\n"
		result += "Caller did not provide ssh_keys, so an ed25519 keypair was\n"
		result += "generated locally. The public half is already on the container.\n\n"
		if saveErr == nil {
			result += fmt.Sprintf("✅ Private key saved: %s (mode 0600)\n\n", savedPath)
		} else {
			result += fmt.Sprintf("⚠️  Could not auto-save the private key: %v\n", saveErr)
			result += "    Save the key text below to a file with mode 0600 yourself.\n\n"
			result += "Suggested save path:\n"
			result += fmt.Sprintf("  ~/.containarium/keys/%s\n\n", resp.Container.Username)
		}
		result += "To SSH in:\n"
		// The daemon stamps ssh_host with the sentinel this container belongs
		// to (from its --ssh-host), so the agent gets a reachable host straight
		// from create_container — no env, no config. Empty means a direct /
		// no-sentinel deployment, where the container IP is the way in.
		sentinelHost := resp.Container.SSHHost
		if sentinelHost == "" {
			sentinelHost = "<sentinel-host>"
		}
		result += fmt.Sprintf("  ssh -i ~/.containarium/keys/%s \\\n"+
			"      -o IdentitiesOnly=yes -o PreferredAuthentications=publickey \\\n"+
			"      %s@%s\n\n",
			resp.Container.Username, resp.Container.Username, sentinelHost)
		result += "IdentitiesOnly=yes is REQUIRED — without it ssh offers every key in\n"
		result += "~/.ssh/, and sshpiper's failtoban counts each rejected offer toward\n"
		result += "the ban quota. Workstations with several keys can get banned on a\n"
		result += "single ssh attempt.\n\n"
		if resp.Container.SSHHost == "" {
			result += "(The daemon reported no ssh_host for this container — a direct /\n"
			result += "no-sentinel deployment. SSH to the container's IP directly, or call\n"
			result += "sync_ssh_config for an alias-based setup.)\n\n"
		}
		// Include the key text regardless of save outcome — even on success
		// it's useful for one-off copy to other machines (vendor laptop,
		// CI runner, etc.) without re-exporting from the auto-saved file.
		result += string(ephemeralPrivKey)
	}

	return result, nil
}

func handleListContainers(client API, args map[string]interface{}) (string, error) {
	resp, err := client.ListContainers()
	if err != nil {
		return "", fmt.Errorf("failed to list containers: %w", err)
	}

	if len(resp.Containers) == 0 {
		return "No containers found.", nil
	}

	result := fmt.Sprintf("Found %d container(s):\n\n", resp.TotalCount)
	for _, container := range resp.Containers {
		result += fmt.Sprintf("📦 %s\n", container.Name)
		result += fmt.Sprintf("   Username: %s\n", container.Username)
		result += fmt.Sprintf("   State: %s\n", container.State)
		// Show WHERE the box actually runs. A wrong/typo'd backend_id silently
		// falls back to the default pool, so surfacing the resolved backend is
		// the fastest way to catch a misplacement (see cloud #686).
		if container.BackendID != "" {
			result += fmt.Sprintf("   Backend: %s\n", container.BackendID)
		}
		if container.Pool != "" {
			result += fmt.Sprintf("   Pool: %s\n", container.Pool)
		}
		if container.Network != nil && container.Network.IPAddress != "" {
			result += fmt.Sprintf("   IP: %s\n", container.Network.IPAddress)
		}
		if container.Resources != nil {
			result += fmt.Sprintf("   Resources: CPU=%s, Memory=%s, Disk=%s\n",
				container.Resources.CPU, container.Resources.Memory, container.Resources.Disk)
		}
		result += "\n"
	}

	return result, nil
}

func handleGetContainer(client API, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	resp, err := client.GetContainer(username)
	if err != nil {
		return "", fmt.Errorf("failed to get container: %w", err)
	}

	// Pretty print as JSON
	jsonData, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal response: %w", err)
	}

	return string(jsonData), nil
}

func handleDebugContainer(client API, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	resp, err := client.DebugContainer(username)
	if err != nil {
		return "", fmt.Errorf("failed to debug container: %w", err)
	}

	jsonData, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal response: %w", err)
	}

	return string(jsonData), nil
}

func handleRevokeToken(client API, args map[string]interface{}) (string, error) {
	jti, _ := args["jti"].(string)
	if jti == "" {
		return "", fmt.Errorf("jti is required")
	}
	reason, _ := args["reason"].(string)
	expiresAt, _ := args["expires_at"].(string)
	msg, err := client.RevokeToken(jti, reason, expiresAt)
	if err != nil {
		return "", fmt.Errorf("revoke token: %w", err)
	}
	return fmt.Sprintf("✅ revoked jti=%s — %s", jti, msg), nil
}

func handleSetSecret(client API, args map[string]interface{}) (string, error) {
	username, _ := args["username"].(string)
	name, _ := args["name"].(string)
	value, _ := args["value"].(string)
	if username == "" || name == "" {
		return "", fmt.Errorf("username and name are required")
	}
	resp, err := client.SetSecret(username, name, value)
	if err != nil {
		return "", fmt.Errorf("failed to set secret: %w", err)
	}
	return fmt.Sprintf("✅ %s", resp.Message), nil
}

func handleGetSecret(client API, args map[string]interface{}) (string, error) {
	username, _ := args["username"].(string)
	name, _ := args["name"].(string)
	if username == "" || name == "" {
		return "", fmt.Errorf("username and name are required")
	}
	value, err := client.GetSecret(username, name)
	if err != nil {
		return "", fmt.Errorf("failed to get secret: %w", err)
	}
	return value, nil
}

func handleListSecrets(client API, args map[string]interface{}) (string, error) {
	username, _ := args["username"].(string)
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	list, err := client.ListSecrets(username)
	if err != nil {
		return "", fmt.Errorf("failed to list secrets: %w", err)
	}
	if len(list) == 0 {
		return fmt.Sprintf("(no secrets for %s)", username), nil
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	return string(b), nil
}

func handleDeleteSecret(client API, args map[string]interface{}) (string, error) {
	username, _ := args["username"].(string)
	name, _ := args["name"].(string)
	if username == "" || name == "" {
		return "", fmt.Errorf("username and name are required")
	}
	if err := client.DeleteSecret(username, name); err != nil {
		return "", fmt.Errorf("failed to delete secret: %w", err)
	}
	return fmt.Sprintf("✅ secret %s deleted", name), nil
}

func handleRefreshSecrets(client API, args map[string]interface{}) (string, error) {
	username, _ := args["username"].(string)
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	resp, err := client.RefreshSecrets(username)
	if err != nil {
		return "", fmt.Errorf("failed to refresh secrets: %w", err)
	}
	return fmt.Sprintf("✅ %s", resp.Message), nil
}

func handleResizeContainer(client API, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}
	cpu, _ := args["cpu"].(string)
	memory, _ := args["memory"].(string)
	disk, _ := args["disk"].(string)
	if cpu == "" && memory == "" && disk == "" {
		return "", fmt.Errorf("at least one of cpu, memory, or disk must be provided")
	}

	resp, err := client.ResizeContainer(username, cpu, memory, disk)
	if err != nil {
		return "", fmt.Errorf("failed to resize container: %w", err)
	}
	return fmt.Sprintf("✅ %s", resp.Message), nil
}

func handleToggleMonitoring(client API, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}
	enabled, ok := args["enabled"].(bool)
	if !ok {
		return "", fmt.Errorf("enabled (bool) is required")
	}

	resp, err := client.ToggleMonitoring(username, enabled)
	if err != nil {
		return "", fmt.Errorf("failed to toggle monitoring: %w", err)
	}
	return fmt.Sprintf("✅ %s (monitoring_enabled=%v)", resp.Message, resp.MonitoringEnabled), nil
}

func handleDeleteContainer(client API, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	force := getBoolArg(args, "force", false)

	// Best-effort: capture WHERE the box ran before deleting, so the
	// confirmation states which backend/pool it was removed from. The delete
	// response doesn't carry placement, and a lookup failure is non-fatal — the
	// delete still proceeds.
	var backend, pool string
	if info, gerr := client.GetContainer(username); gerr == nil && info != nil {
		backend, pool = info.Container.BackendID, info.Container.Pool
	}

	resp, err := client.DeleteContainer(username, force)
	if err != nil {
		return "", fmt.Errorf("failed to delete container: %w", err)
	}

	out := fmt.Sprintf("✅ %s", resp.Message)
	if backend != "" {
		out += fmt.Sprintf("\n   Backend: %s", backend)
	}
	if pool != "" {
		out += fmt.Sprintf("\n   Pool: %s", pool)
	}
	return out, nil
}

func handleStartContainer(client API, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}
	waitForReady := getBoolArg(args, "waitForReady", false)

	resp, err := client.StartContainer(username, waitForReady)
	if err != nil {
		return "", fmt.Errorf("failed to start container: %w", err)
	}

	if resp.ReadyTimedOut {
		return fmt.Sprintf("⚠ %s (readiness probe timed out)\nContainer state: %s", resp.Message, resp.Container.State), nil
	}
	return fmt.Sprintf("✅ %s\nContainer state: %s", resp.Message, resp.Container.State), nil
}

func handleToggleAutoSleep(client API, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}
	enabled, ok := args["enabled"].(bool)
	if !ok {
		return "", fmt.Errorf("enabled (bool) is required")
	}
	idle := int32(0)
	if n, ok := getIntArg(args, "idleThresholdMinutes"); ok {
		idle = safecast.I32(n)
	}

	resp, err := client.ToggleAutoSleep(username, enabled, idle)
	if err != nil {
		return "", fmt.Errorf("failed to toggle auto-sleep: %w", err)
	}
	return fmt.Sprintf("✅ %s (auto_sleep_enabled=%v, idle_threshold_minutes=%d)",
		resp.Message, resp.AutoSleepEnabled, resp.IdleThresholdMinutes), nil
}

func handleStopContainer(client API, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	force := getBoolArg(args, "force", false)

	resp, err := client.StopContainer(username, force)
	if err != nil {
		return "", fmt.Errorf("failed to stop container: %w", err)
	}

	return fmt.Sprintf("✅ %s\nContainer state: %s", resp.Message, resp.Container.State), nil
}

func handleGetMetrics(client API, args map[string]interface{}) (string, error) {
	username := getStringArg(args, "username", "")

	resp, err := client.GetMetrics(username)
	if err != nil {
		return "", fmt.Errorf("failed to get metrics: %w", err)
	}

	if len(resp.Metrics) == 0 {
		return "No metrics available.", nil
	}

	result := fmt.Sprintf("Container Metrics (%d container(s)):\n\n", len(resp.Metrics))
	for _, m := range resp.Metrics {
		result += fmt.Sprintf("📊 %s\n", m.Name)
		result += fmt.Sprintf("   CPU Usage: %d seconds\n", m.CPUUsageSeconds)
		result += fmt.Sprintf("   Memory: %d MB / %d MB peak\n",
			m.MemoryUsageBytes/1024/1024, m.MemoryPeakBytes/1024/1024)
		result += fmt.Sprintf("   Disk: %d MB\n", m.DiskUsageBytes/1024/1024)
		result += fmt.Sprintf("   Network: ↓%d MB ↑%d MB\n",
			m.NetworkRxBytes/1024/1024, m.NetworkTxBytes/1024/1024)
		result += fmt.Sprintf("   Processes: %d\n", m.ProcessCount)
		result += "\n"
	}

	return result, nil
}

func handleGetSystemInfo(client API, args map[string]interface{}) (string, error) {
	resp, err := client.GetSystemInfo()
	if err != nil {
		return "", fmt.Errorf("failed to get system info: %w", err)
	}

	result := "🖥️  System Information:\n\n"
	result += fmt.Sprintf("Hostname: %s\n", resp.Info.Hostname)
	result += fmt.Sprintf("OS: %s\n", resp.Info.OS)
	result += fmt.Sprintf("Kernel: %s\n", resp.Info.KernelVersion)
	result += fmt.Sprintf("Incus Version: %s\n", resp.Info.IncusVersion)
	if resp.Info.DaemonVersion != "" {
		result += fmt.Sprintf("Daemon Version: %s\n", resp.Info.DaemonVersion)
	}
	result += "\nContainers:\n"
	result += fmt.Sprintf("  Running: %d\n", resp.Info.ContainersRunning)
	result += fmt.Sprintf("  Stopped: %d\n", resp.Info.ContainersStopped)
	result += fmt.Sprintf("  Total: %d\n", resp.Info.ContainersTotal)

	// OTLP endpoint: where monitoring=true containers ship telemetry.
	// Point docker-in-LXC apps here when they can't inherit the
	// env-stamped OTEL_EXPORTER_OTLP_ENDPOINT. See #370.
	if resp.Info.OTelCollectorEndpoint != "" {
		result += fmt.Sprintf("\nOTel collector (OTLP/HTTP): %s\n", resp.Info.OTelCollectorEndpoint)
	} else {
		result += "\nOTel collector: not configured (app monitoring unavailable)\n"
	}

	return result, nil
}

func handleBackendValidateGPU(client API, args map[string]interface{}) (string, error) {
	backendID, _ := args["backend_id"].(string)
	pci, _ := args["pci"].(string)

	resp, err := client.ValidateGPU(backendID, pci)
	if err != nil {
		return "", fmt.Errorf("validate GPU: %w", err)
	}

	target := resp.BackendID
	if target == "" {
		target = "(local)"
	}
	if resp.Status == "GPU_STATUS_OK" {
		return fmt.Sprintf("✓ GPU passthrough OK on %s: %s (driver %s)", target, resp.GpuModel, resp.DriverVersion), nil
	}
	status := strings.TrimPrefix(resp.Status, "GPU_STATUS_")
	return fmt.Sprintf("✗ GPU passthrough %s on %s: %s", status, target, resp.Detail), nil
}

func handleCheckForUpdates(client API, args map[string]interface{}) (string, error) {
	resp, err := client.GetLatestRelease()
	if err != nil {
		return "", fmt.Errorf("failed to check for updates: %w", err)
	}
	result := fmt.Sprintf("Running version:  %s\n", resp.CurrentVersion)
	if resp.LatestRelease == "" {
		result += "Latest release:   unknown (GitHub lookup unavailable)\n"
		return result, nil
	}
	result += fmt.Sprintf("Latest release:   %s\n", resp.LatestRelease)
	if resp.UpdateAvailable {
		result += fmt.Sprintf("\n⚠ Update available: %s → %s\n", resp.CurrentVersion, resp.LatestRelease)
	} else {
		result += "\n✓ Up to date\n"
	}
	return result, nil
}

func handleUpgradeBackend(client API, args map[string]interface{}) (string, error) {
	backendID, _ := args["backend_id"].(string)
	force, _ := args["force"].(bool)
	resp, err := client.TriggerUpgrade(backendID, force)
	if err != nil {
		return "", fmt.Errorf("failed to trigger upgrade: %w", err)
	}
	target := resp.BackendID
	if target == "" {
		target = "(local)"
	}
	result := fmt.Sprintf("Upgrade %s on %s (job %s)\n", resp.Status, target, resp.UpgradeID)
	if resp.CurrentVersion != "" {
		result += fmt.Sprintf("  from version: %s\n", resp.CurrentVersion)
	}
	if resp.Message != "" {
		result += fmt.Sprintf("  %s\n", resp.Message)
	}
	return result, nil
}

func handleGetUpgradeStatus(client API, args map[string]interface{}) (string, error) {
	upgradeID, _ := args["upgrade_id"].(string)
	if upgradeID == "" {
		return "", fmt.Errorf("upgrade_id is required")
	}
	resp, err := client.GetUpgradeStatus(upgradeID)
	if err != nil {
		return "", fmt.Errorf("failed to get upgrade status: %w", err)
	}
	result := fmt.Sprintf("Status:   %s\n", resp.Status)
	if resp.CurrentVersion != "" {
		result += fmt.Sprintf("Version:  %s\n", resp.CurrentVersion)
	}
	if resp.CompletedAt != "" {
		result += fmt.Sprintf("Done at:  %s\n", resp.CompletedAt)
	}
	if resp.Error != "" {
		result += fmt.Sprintf("Error:    %s\n", resp.Error)
	}
	if resp.Status == "unknown" {
		result += "\n(unknown id — if you just triggered a local upgrade, the daemon restarted and dropped the job; confirm via list_backends.)\n"
	}
	return result, nil
}

func handleListBackends(client API, args map[string]interface{}) (string, error) {
	resp, err := client.ListBackends()
	if err != nil {
		return "", fmt.Errorf("failed to list backends: %w", err)
	}
	if len(resp.Backends) == 0 {
		return "No backends registered (running standalone, no peers).", nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Found %d backend(s):\n\n", len(resp.Backends))
	for i := range resp.Backends {
		writeBackendDetail(&b, &resp.Backends[i])
		b.WriteString("\n")
	}
	return b.String(), nil
}

func handleGetBackend(client API, args map[string]interface{}) (string, error) {
	id, ok := args["id"].(string)
	if !ok || id == "" {
		return "", fmt.Errorf("id is required")
	}
	bk, err := client.GetBackend(id)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	writeBackendDetail(&b, bk)
	return b.String(), nil
}

// writeBackendDetail renders one Backend in the same shape used by both
// list_backends and get_backend so the agent sees a consistent format.
func writeBackendDetail(b *strings.Builder, bk *Backend) {
	health := "✓ healthy"
	if !bk.Healthy {
		health = "✗ unhealthy"
	}
	fmt.Fprintf(b, "🖥️  %s  (%s, %s)\n", bk.ID, bk.Type, health)
	if bk.Hostname != "" {
		fmt.Fprintf(b, "   Hostname:   %s\n", bk.Hostname)
	}
	if bk.OS != "" {
		fmt.Fprintf(b, "   OS:         %s\n", bk.OS)
	}
	if bk.Version != "" {
		fmt.Fprintf(b, "   Version:    %s\n", bk.Version)
	}
	fmt.Fprintf(b, "   Containers: %d running\n", bk.ContainerCount)
	if bk.UptimeSeconds > 0 {
		fmt.Fprintf(b, "   Uptime:     %s\n", formatUptime(int64(bk.UptimeSeconds)))
	}
	if bk.LastSeenAt != "" && bk.Type != "local" {
		fmt.Fprintf(b, "   Last seen:  %s\n", bk.LastSeenAt)
	}
	if len(bk.GPUs) > 0 {
		fmt.Fprintf(b, "   GPUs:\n")
		for _, g := range bk.GPUs {
			vram := ""
			if g.VRAMBytes > 0 {
				vram = fmt.Sprintf(" — %s VRAM", humanBytes(int64(g.VRAMBytes)))
			}
			fmt.Fprintf(b, "     - %s %s%s\n", g.Vendor, g.ModelName, vram)
		}
	}
}

// formatUptime converts seconds into a human string like "3d4h" or "1h30m".
// Bias toward terse — agents render this verbatim.
func formatUptime(seconds int64) string {
	d := seconds / 86400
	h := (seconds % 86400) / 3600
	m := (seconds % 3600) / 60
	switch {
	case d > 0:
		return fmt.Sprintf("%dd%dh", d, h)
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	default:
		return fmt.Sprintf("%dm", m)
	}
}

// humanBytes formats sizes like "24 GiB" for VRAM, where the source
// is a power-of-two byte count.
func humanBytes(n int64) string {
	const k = 1024
	switch {
	case n >= k*k*k*k:
		return fmt.Sprintf("%.1f TiB", float64(n)/float64(k*k*k*k))
	case n >= k*k*k:
		return fmt.Sprintf("%.0f GiB", float64(n)/float64(k*k*k))
	case n >= k*k:
		return fmt.Sprintf("%.0f MiB", float64(n)/float64(k*k))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func handleListRoutes(client API, args map[string]interface{}) (string, error) {
	username := getStringArg(args, "username", "")
	activeOnly := getBoolArg(args, "active_only", false)

	resp, err := client.ListRoutes(username, activeOnly)
	if err != nil {
		return "", fmt.Errorf("failed to list routes: %w", err)
	}

	out, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal response: %w", err)
	}
	return string(out), nil
}

func handleDeleteRoute(client API, args map[string]interface{}) (string, error) {
	domain := getStringArg(args, "domain", "")
	if domain == "" {
		return "", fmt.Errorf("domain is required")
	}
	if err := client.DeleteRoute(domain); err != nil {
		return "", fmt.Errorf("failed to delete route %s: %w", domain, err)
	}
	return fmt.Sprintf("✅ Deleted route %s — it no longer reaches any container.", domain), nil
}

func handleExposePort(client API, args map[string]interface{}) (string, error) {
	port, _ := getIntArg(args, "container_port")
	res, err := expose.Run(context.Background(), &mcpExposeAdapter{c: client}, expose.Options{
		Username:      getStringArg(args, "username", ""),
		ContainerPort: port,
		Domain:        getStringArg(args, "domain", ""),
		Description:   getStringArg(args, "description", ""),
	})
	if err != nil {
		return "", err
	}

	out := fmt.Sprintf("✅ Exposed %s:%d → %s\n\n",
		getStringArg(args, "username", ""), port, res.Domain)
	out += fmt.Sprintf("Domain:    %s\n", res.Domain)
	out += fmt.Sprintf("Target:    %s:%d\n", res.ContainerIP, res.Port)
	if res.ContainerName != "" {
		out += fmt.Sprintf("Container: %s\n", res.ContainerName)
	}
	if res.Message != "" {
		out += fmt.Sprintf("\n%s", res.Message)
	}
	out += "\n\nNext: confirm DNS for this hostname points at the sentinel, then\n"
	out += fmt.Sprintf("`curl https://%s/` should reach the app inside %s.",
		res.Domain, getStringArg(args, "username", ""))
	return out, nil
}

func handleListRecipes(client API, _ map[string]interface{}) (string, error) {
	resp, err := client.ListRecipes()
	if err != nil {
		return "", err
	}
	if len(resp.Recipes) == 0 {
		return "No recipes available.", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-12s %-10s %-30s %s\n", "ID", "GPU", "IMAGE", "DESCRIPTION")
	for _, r := range resp.Recipes {
		gpu := "no"
		if r.RequiresGPU {
			gpu = "required"
		}
		fmt.Fprintf(&b, "%-12s %-10s %-30s %s\n", r.ID, gpu, r.Image, r.Description)
	}
	return b.String(), nil
}

func handleDeployRecipe(client API, args map[string]interface{}) (string, error) {
	params := map[string]string{}
	if raw, ok := args["parameters"].(map[string]interface{}); ok {
		for k, v := range raw {
			params[k] = fmt.Sprintf("%v", v)
		}
	}
	resp, err := client.DeployRecipe(DeployRecipeRequest{
		RecipeID:   getStringArg(args, "recipe_id", ""),
		Name:       getStringArg(args, "name", ""),
		GPU:        getStringArg(args, "gpu", ""),
		Parameters: params,
	})
	if err != nil {
		return "", err
	}
	out := fmt.Sprintf("✅ %s\n", resp.Message)
	if resp.URL != "" {
		out += fmt.Sprintf("URL:       %s\n", resp.URL)
	}
	if resp.Container != nil {
		out += fmt.Sprintf("Container: %s (%s)\n", resp.Container.Name, resp.Container.State)
	}
	return out, nil
}

func handleListAgentSkills(client API, _ map[string]interface{}) (string, error) {
	resp, err := client.ListAgentSkills()
	if err != nil {
		return "", err
	}
	if len(resp.Skills) == 0 {
		return "No agent skills available.", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-16s %-16s %-24s %s\n", "ID", "BOX", "SCOPES", "DESCRIPTION")
	for _, s := range resp.Skills {
		fmt.Fprintf(&b, "%-16s %-16s %-24s %s\n",
			s.ID, s.RecipeID, strings.Join(s.AllowedScopes, ","), s.Description)
	}
	return b.String(), nil
}

func handleRunAgentSkill(client API, args map[string]interface{}) (string, error) {
	resp, err := client.RunAgentSkill(RunAgentSkillRequest{
		SkillID:   getStringArg(args, "skill_id", ""),
		InputJSON: getStringArg(args, "input_json", ""),
	})
	if err != nil {
		return "", err
	}
	var out string
	if resp.Container != nil {
		out = fmt.Sprintf("✅ box ready: %s (%s)\n", resp.Container.Name, resp.Container.State)
	}
	if resp.ArtifactJSON != "" {
		out += fmt.Sprintf("Artifact:  %s\n", resp.ArtifactJSON)
	} else {
		out += "(no artifact — the in-box agent loop is a Phase 0 seam)\n"
	}
	return out, nil
}

func handleCallAgent(client API, args map[string]interface{}) (string, error) {
	resp, err := client.CallAgent(CallAgentRequest{
		ToPeerID:    getStringArg(args, "to_peer_id", ""),
		FromSkillID: getStringArg(args, "from_skill_id", ""),
		InputJSON:   getStringArg(args, "input_json", ""),
	})
	if err != nil {
		return "", err
	}
	if resp.Artifact == nil {
		return "Peer returned no artifact.", nil
	}
	out := fmt.Sprintf("✅ task %s — %s\n", resp.Artifact.TaskID, resp.Artifact.State)
	if resp.Artifact.Error != "" {
		out += fmt.Sprintf("error:    %s\n", resp.Artifact.Error)
	}
	if resp.Artifact.OutputJSON != "" {
		out += fmt.Sprintf("artifact: %s\n", resp.Artifact.OutputJSON)
	}
	return out, nil
}

func handleListCrews(client API, _ map[string]interface{}) (string, error) {
	resp, err := client.ListCrews()
	if err != nil {
		return "", err
	}
	if len(resp.Crews) == 0 {
		return "No crews available.", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-16s %-14s %-28s %s\n", "ID", "TOPOLOGY", "SKILLS", "DESCRIPTION")
	for _, c := range resp.Crews {
		fmt.Fprintf(&b, "%-16s %-14s %-28s %s\n", c.ID, c.Topology, strings.Join(c.SkillIDs, ","), c.Description)
	}
	return b.String(), nil
}

func handleRunCrew(client API, args map[string]interface{}) (string, error) {
	resp, err := client.RunCrew(RunCrewRequest{
		CrewID:    getStringArg(args, "crew_id", ""),
		InputJSON: getStringArg(args, "input_json", ""),
	})
	if err != nil {
		return "", err
	}
	if resp.Run == nil {
		return "Crew run returned no handle.", nil
	}
	out := fmt.Sprintf("✅ crew run %s — %s (trace %s)\n", resp.Run.ID, resp.Run.State, resp.Run.TraceID)
	if resp.Run.Error != "" {
		out += fmt.Sprintf("error: %s\n", resp.Run.Error)
	}
	return out, nil
}

// mcpExposeAdapter implements expose.APIClient against this package's
// HTTP Client. Identical responsibilities to the CLI's grpcExposeAdapter
// in internal/cmd/expose_port.go — both transports speak through the
// same expose.Run() so behavior can never drift.
type mcpExposeAdapter struct{ c API }

func (a *mcpExposeAdapter) LookupContainer(_ context.Context, username string) (string, string, string, error) {
	got, err := a.c.GetContainer(username)
	if err != nil {
		return "", "", "", err
	}
	ip := ""
	if got.Container.Network != nil {
		ip = got.Container.Network.IPAddress
	}
	return got.Container.Name, ip, got.Container.State, nil
}

func (a *mcpExposeAdapter) CreateRoute(_ context.Context, p expose.AddRouteParams) (*expose.RouteResult, error) {
	resp, err := a.c.AddRoute(AddRouteRequest{
		Domain:        p.Domain,
		TargetIP:      p.TargetIP,
		TargetPort:    p.TargetPort,
		ContainerName: p.ContainerName,
		Description:   p.Description,
	})
	if err != nil {
		return nil, err
	}
	domain := resp.Route.Domain
	if domain == "" {
		domain = p.Domain
	}
	containerName := resp.Route.ContainerName
	if containerName == "" {
		containerName = p.ContainerName
	}
	return &expose.RouteResult{
		Domain:        domain,
		ContainerName: containerName,
		ContainerIP:   resp.Route.ContainerIP,
		Port:          resp.Route.Port,
		Message:       resp.Message,
	}, nil
}

// Helper functions

func getStringArg(args map[string]interface{}, key, defaultValue string) string {
	if val, ok := args[key].(string); ok && val != "" {
		return val
	}
	return defaultValue
}

// getStringSliceArg reads a JSON array argument into a []string, dropping
// non-string and empty entries. Returns nil when the key is absent or not an
// array — JSON-RPC decodes arrays as []interface{}.
func getStringSliceArg(args map[string]interface{}, key string) []string {
	raw, ok := args[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func getBoolArg(args map[string]interface{}, key string, defaultValue bool) bool {
	if val, ok := args[key].(bool); ok {
		return val
	}
	return defaultValue
}

// getIntArg pulls an integer-shaped argument. JSON unmarshaling presents
// integers as float64 by default, so we accept both. Returns ok=false when
// the key is absent or the value is non-numeric — callers distinguish
// "missing" from "set to zero" by inspecting ok.
func getIntArg(args map[string]interface{}, key string) (int, bool) {
	switch v := args[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	default:
		return 0, false
	}
}
