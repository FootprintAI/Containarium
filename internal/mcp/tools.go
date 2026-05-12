package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/pkg/core/expose"
)

// Tool represents an MCP tool (function)
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]interface{}
	Handler     ToolHandler
}

// ToolHandler is a function that handles a tool call
type ToolHandler func(client *Client, args map[string]interface{}) (string, error)

// registerTools registers all available MCP tools
func (s *Server) registerTools() {
	s.tools = []Tool{
		{
			Name: "create_container",
			Description: "Create a new LXC container under a username. Returns the container's " +
				"name, IP address, and resources.\n\n" +
				"SSH key handling: if you OMIT `ssh_keys`, an ephemeral ed25519 keypair is " +
				"generated client-side. The public half is installed on the container; the " +
				"private half comes back in this tool's response. Save it to " +
				"`~/.containarium/keys/<username>` with mode 0600 — that's the standard " +
				"path expected by the rest of the workflow. If you pass `ssh_keys`, those " +
				"are used as-is and no ephemeral key is generated (useful when reusing an " +
				"operator's existing key for SSH alias convenience).\n\n" +
				"AFTER creation, to operate inside the container (simplest path):\n" +
				"  1. Save the ephemeral private key (if generated) via Bash to\n" +
				"     ~/.containarium/keys/<name> with mode 0600.\n" +
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
						"description": "GPU device ID for passthrough (e.g., '0' for first GPU, PCI address, or empty for none)",
					},
					"os_type": map[string]interface{}{
						"type":        "string",
						"description": "Container OS type: 'ubuntu' (default), 'rocky9' (dev/test), 'rhel9' (production). Overrides image when set.",
						"enum":        []string{"", "ubuntu", "rocky9", "rhel9"},
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
				"sourceRepo, daemonVersion. When the structured fields are inconclusive, " +
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
			Description: "Start a stopped container",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container to start",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleStartContainer,
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
			Name: "push",
			Description: "Push committed git history from a local repository into a container, " +
				"via the same SSH path you'd use to ssh in directly.\n\n" +
				"Ships only the delta since the last push to this user (tracked in " +
				"`.git/containarium-state.json` in the local repo). Uses `git bundle` as " +
				"the wire format — git's pack-protocol-level delta compression, atomic " +
				"per-call.\n\n" +
				"This is the *commit-only* mode. Working-tree changes that aren't committed " +
				"DO NOT ship by default — if the working tree has uncommitted or untracked " +
				"files, the tool refuses with a clear error. Pass `include_wip=true` to " +
				"auto-create a WIP commit, push, and rewind the local repo afterwards.\n\n" +
				"If you want to mirror the entire local state (uncommitted changes + " +
				"untracked files + stash refs) without commit ceremony, use the `sync` " +
				"tool instead.\n\n" +
				"On first push to a given `<username>`, the tool initializes a fresh git " +
				"repo at the remote path; subsequent pushes fast-forward (or force) the " +
				"branch and check it out.",
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
						"description": "Destination directory inside the container (default: ~/work).",
					},
					"include_wip": map[string]interface{}{
						"type":        "boolean",
						"description": "If true and the working tree is dirty, auto-create a WIP commit, push, then rewind the local repo. Default false (refuse on dirty tree).",
					},
					"sentinel": map[string]interface{}{
						"type":        "string",
						"description": "Sentinel SSH host override. Default uses CONTAINARIUM_SENTINEL_HOST env.",
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
						"description": "Sentinel SSH host override. Default uses CONTAINARIUM_SENTINEL_HOST env.",
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
	}
}

// Tool handlers

func handleCreateContainer(client *Client, args map[string]interface{}) (string, error) {
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

	result := fmt.Sprintf("✅ Container created successfully!\n\n")
	result += fmt.Sprintf("Name: %s\n", resp.Container.Name)
	result += fmt.Sprintf("Username: %s\n", resp.Container.Username)
	result += fmt.Sprintf("State: %s\n", resp.Container.State)
	if resp.Container.Network != nil && resp.Container.Network.IPAddress != "" {
		result += fmt.Sprintf("IP Address: %s\n", resp.Container.Network.IPAddress)
	}
	if resp.Container.Resources != nil {
		result += fmt.Sprintf("CPU: %s\n", resp.Container.Resources.CPU)
		result += fmt.Sprintf("Memory: %s\n", resp.Container.Resources.Memory)
		result += fmt.Sprintf("Disk: %s\n", resp.Container.Resources.Disk)
	}
	result += fmt.Sprintf("\n%s", resp.Message)

	if ephemeralPrivKey != nil {
		result += "\n\n--- EPHEMERAL SSH PRIVATE KEY ---\n"
		result += "Caller did not provide ssh_keys, so an ed25519 keypair was\n"
		result += "generated locally. The public half is already on the container;\n"
		result += "save the private half below to a file with mode 0600 and use it\n"
		result += "to SSH in.\n\n"
		result += "Suggested save path:\n"
		result += fmt.Sprintf("  ~/.containarium/keys/%s\n\n", resp.Container.Username)
		result += "Then to SSH in:\n"
		sentinelHost := client.SentinelHost
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
		if client.SentinelHost == "" {
			result += "(Sentinel host not configured — set CONTAINARIUM_SENTINEL_HOST in the\n"
			result += "MCP server's env, or call sync_ssh_config for an alias-based setup.)\n\n"
		}
		result += string(ephemeralPrivKey)
	}

	return result, nil
}

func handleListContainers(client *Client, args map[string]interface{}) (string, error) {
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

func handleGetContainer(client *Client, args map[string]interface{}) (string, error) {
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

func handleDebugContainer(client *Client, args map[string]interface{}) (string, error) {
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

func handleDeleteContainer(client *Client, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	force := getBoolArg(args, "force", false)

	resp, err := client.DeleteContainer(username, force)
	if err != nil {
		return "", fmt.Errorf("failed to delete container: %w", err)
	}

	return fmt.Sprintf("✅ %s", resp.Message), nil
}

func handleStartContainer(client *Client, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	resp, err := client.StartContainer(username)
	if err != nil {
		return "", fmt.Errorf("failed to start container: %w", err)
	}

	return fmt.Sprintf("✅ %s\nContainer state: %s", resp.Message, resp.Container.State), nil
}

func handleStopContainer(client *Client, args map[string]interface{}) (string, error) {
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

func handleGetMetrics(client *Client, args map[string]interface{}) (string, error) {
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

func handleGetSystemInfo(client *Client, args map[string]interface{}) (string, error) {
	resp, err := client.GetSystemInfo()
	if err != nil {
		return "", fmt.Errorf("failed to get system info: %w", err)
	}

	result := "🖥️  System Information:\n\n"
	result += fmt.Sprintf("Hostname: %s\n", resp.Info.Hostname)
	result += fmt.Sprintf("OS: %s\n", resp.Info.OS)
	result += fmt.Sprintf("Kernel: %s\n", resp.Info.KernelVersion)
	result += fmt.Sprintf("Incus Version: %s\n", resp.Info.IncusVersion)
	result += fmt.Sprintf("\nContainers:\n")
	result += fmt.Sprintf("  Running: %d\n", resp.Info.ContainersRunning)
	result += fmt.Sprintf("  Stopped: %d\n", resp.Info.ContainersStopped)
	result += fmt.Sprintf("  Total: %d\n", resp.Info.ContainersTotal)

	return result, nil
}

func handleListBackends(client *Client, args map[string]interface{}) (string, error) {
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

func handleGetBackend(client *Client, args map[string]interface{}) (string, error) {
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
		fmt.Fprintf(b, "   Uptime:     %s\n", formatUptime(bk.UptimeSeconds))
	}
	if bk.LastSeenAt != "" && bk.Type != "local" {
		fmt.Fprintf(b, "   Last seen:  %s\n", bk.LastSeenAt)
	}
	if len(bk.GPUs) > 0 {
		fmt.Fprintf(b, "   GPUs:\n")
		for _, g := range bk.GPUs {
			vram := ""
			if g.VRAMBytes > 0 {
				vram = fmt.Sprintf(" — %s VRAM", humanBytes(g.VRAMBytes))
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

func handleExposePort(client *Client, args map[string]interface{}) (string, error) {
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

// mcpExposeAdapter implements expose.APIClient against this package's
// HTTP Client. Identical responsibilities to the CLI's grpcExposeAdapter
// in internal/cmd/expose_port.go — both transports speak through the
// same expose.Run() so behavior can never drift.
type mcpExposeAdapter struct{ c *Client }

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
