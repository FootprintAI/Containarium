package mcp

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// Platform MCP tools for compose-autostart. Thin pass-throughs over
// the daemon's ComposeAutostartService gRPC, reached via grpc-gateway
// at POST /v1/tenants/{username}/compose/{verb}. Mirror of the
// agent-box MCP tools (which run INSIDE the LXC) for external agents
// that drive the platform from outside.
//
// Handlers return the daemon's JSON response verbatim — agents can
// parse it directly if they need structured data, or render the raw
// JSON for the human.
//
// Each tool requires `username` (which tenant LXC); enable/disable/
// status additionally require `dir`. Schemas mirror the proto's
// per-RPC required fields.

// ---- Client methods (typed wrappers) -------------------------------

type composeDiscoverReq struct {
	Username string   `json:"username"`
	Root     string   `json:"root,omitempty"`
	MaxDepth int32    `json:"maxDepth,omitempty"`
	Skip     []string `json:"skip,omitempty"`
	NoSkip   bool     `json:"noSkip,omitempty"`
}

type composeEnableReq struct {
	Username string `json:"username"`
	Dir      string `json:"dir"`
	Force    bool   `json:"force,omitempty"`
}

type composeDisableReq struct {
	Username string `json:"username"`
	Dir      string `json:"dir"`
}

// composeDispatch is the common shape for the POST verbs (discover /
// enable / disable). They all POST {body} to
// /v1/tenants/{username}/compose/<verb>. Returns the raw response
// body so handlers can pass it through to the agent verbatim.
func (c *Client) composeDispatch(verb, username string, body any) (json.RawMessage, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	path := "/v1/tenants/" + url.PathEscape(username) + "/compose/" + verb
	resp, err := c.doRequest("POST", path, body)
	if err != nil {
		return nil, fmt.Errorf("compose %s: %w", verb, err)
	}
	return json.RawMessage(resp), nil
}

// composeStatus is a GET (no body) — the proto exposes Status as GET
// for cheap polling.
func (c *Client) composeStatus(username, dir string) (json.RawMessage, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if dir == "" {
		return nil, fmt.Errorf("dir is required")
	}
	path := "/v1/tenants/" + url.PathEscape(username) + "/compose/status?dir=" + url.QueryEscape(dir)
	resp, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("compose status: %w", err)
	}
	return json.RawMessage(resp), nil
}

// ---- Handlers ------------------------------------------------------

func handleComposeDiscoverPlatform(client *Client, args map[string]interface{}) (string, error) {
	username, _ := args["username"].(string)
	req := composeDiscoverReq{
		Username: username,
		Root:     getStringArg(args, "root", ""),
		NoSkip:   getBoolArg(args, "no_skip", false),
	}
	if d, ok := getIntArg(args, "max_depth"); ok {
		req.MaxDepth = int32(d)
	}
	if skip, ok := args["skip"].([]interface{}); ok {
		for _, s := range skip {
			if str, ok := s.(string); ok {
				req.Skip = append(req.Skip, str)
			}
		}
	}
	body, err := client.composeDispatch("discover", username, req)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func handleComposeEnablePlatform(client *Client, args map[string]interface{}) (string, error) {
	username, _ := args["username"].(string)
	req := composeEnableReq{
		Username: username,
		Dir:      getStringArg(args, "dir", ""),
		Force:    getBoolArg(args, "force", false),
	}
	if req.Dir == "" {
		return "", fmt.Errorf("dir is required")
	}
	body, err := client.composeDispatch("enable", username, req)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func handleComposeDisablePlatform(client *Client, args map[string]interface{}) (string, error) {
	username, _ := args["username"].(string)
	req := composeDisableReq{
		Username: username,
		Dir:      getStringArg(args, "dir", ""),
	}
	if req.Dir == "" {
		return "", fmt.Errorf("dir is required")
	}
	body, err := client.composeDispatch("disable", username, req)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func handleComposeStatusPlatform(client *Client, args map[string]interface{}) (string, error) {
	username, _ := args["username"].(string)
	dir := getStringArg(args, "dir", "")
	body, err := client.composeStatus(username, dir)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// composeTools returns the four Tool defs for the registerTools()
// slice in tools.go. Split out as a function so the giant tools-array
// literal stays readable — tools.go just appends `composeTools()...`.
func composeTools() []Tool {
	return []Tool{
		{
			Name: "compose_discover",
			Description: "Discover docker-compose / podman-compose stacks under a tenant's LXC. " +
				"Walks from the tenant's $HOME (or supplied `root`) up to `max_depth`, " +
				"skipping common noise dirs (node_modules, .git, vendor, …). For each " +
				"stack returns the compose dir/file, the resolved compose runtime, " +
				"running_count + total_count (NOT a boolean — agents need to distinguish " +
				"fully-up / partial / fully-down), and whether the systemd-user autostart " +
				"unit is currently enabled.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Tenant LXC to operate in (same value used by create_container).",
					},
					"root": map[string]interface{}{
						"type":        "string",
						"description": "Walk root inside the LXC. Defaults to the tenant's $HOME when empty.",
					},
					"max_depth": map[string]interface{}{
						"type":        "integer",
						"description": "Max directory depth. 0 → agent-box default.",
					},
					"skip": map[string]interface{}{
						"type":        "array",
						"items":       map[string]string{"type": "string"},
						"description": "Extra directory names to skip on the walk (additive to the default set).",
					},
					"no_skip": map[string]interface{}{
						"type":        "boolean",
						"description": "Bypass the default skip set entirely. Useful for one-off audits; slow on deep trees.",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleComposeDiscoverPlatform,
		},
		{
			Name: "compose_enable",
			Description: "Install + enable the systemd-user autostart unit for a compose " +
				"directory inside a tenant's LXC. Idempotent — force=true refreshes the " +
				"unit after the compose file changes. Also enables loginctl linger so the " +
				"user-systemd survives logout and starts at host boot.\n\n" +
				"After this, the compose stack restarts automatically on host reboot. " +
				"To stop the running containers, use the compose CLI directly inside " +
				"the LXC; disabling here only removes the autostart protection.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{"type": "string", "description": "Tenant LXC."},
					"dir":      map[string]interface{}{"type": "string", "description": "Compose directory inside the LXC. Required."},
					"force":    map[string]interface{}{"type": "boolean", "description": "Re-install the unit even if already enabled."},
				},
				"required": []string{"username", "dir"},
			},
			Handler: handleComposeEnablePlatform,
		},
		{
			Name: "compose_disable",
			Description: "Stop + disable the systemd-user autostart unit for one compose " +
				"directory. Does NOT stop the running containers — use the compose CLI " +
				"for that. Just removes the boot-time restart protection.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{"type": "string", "description": "Tenant LXC."},
					"dir":      map[string]interface{}{"type": "string", "description": "Compose directory inside the LXC. Required."},
				},
				"required": []string{"username", "dir"},
			},
			Handler: handleComposeDisablePlatform,
		},
		{
			Name: "compose_status",
			Description: "Show one compose dir's status without a filesystem walk — " +
				"cheaper than compose_discover when the caller already knows the path. " +
				"Same ComposeStack fields: dir/file/bin, running_count + total_count, " +
				"autostart_enabled, and unit / compose file mtimes for staleness checks.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{"type": "string", "description": "Tenant LXC."},
					"dir":      map[string]interface{}{"type": "string", "description": "Compose directory inside the LXC. Required."},
				},
				"required": []string{"username", "dir"},
			},
			Handler: handleComposeStatusPlatform,
		},
	}
}
