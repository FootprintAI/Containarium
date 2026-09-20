package server

import (
	"encoding/json"
	"fmt"
	"strings"
)

// platformMCPHostPlaceholder stands in for the daemon host inside the seed
// JSON until the in-box script substitutes the real one. The host is the box's
// default-route gateway, which only the box can resolve (it depends on the
// bridge subnet) — the same in-box resolution gatewayEnvScript uses.
const platformMCPHostPlaceholder = "__CTN_HOST__"

// platformMCPSeed is the Go side of the daemon <-> in-box runtime contract for
// mounting the platform MCP (design decision D4, docs/architecture/
// agent-tracker-broker.md). Written as <seed>/platform_mcp.json; the runtime
// mounts it as a second MCP server beside agent-box. The shape is pinned by
// agent-runtime/fixtures/platform_mcp.json, which both this package's tests and
// the runtime's seed.test.ts read.
type platformMCPSeed struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	// ServerURL is the daemon REST base URL as reachable from inside the box.
	ServerURL string `json:"server_url"`
	// TokenFile is the run's seeded platform JWT. The MCP server re-reads it on
	// every request (CONTAINARIUM_JWT_TOKEN_FILE), so the seed never carries the
	// token itself.
	TokenFile string `json:"token_file"`
	// Tools is the CONTAINARIUM_MCP_TOOLS allow-list — "tracker_*", so the agent
	// sees the tracker tools and not the other ~75 platform tools. The JWT's own
	// scopes still gate every call; this narrows what is offered.
	Tools string `json:"tools"`
}

// platformMCPSeedScript returns the shell that writes <seedDir>/platform_mcp.json,
// or ok=false when this run should not get one: a run not bound to a tracker
// connection has nothing to reach through the tracker tools, and without the
// daemon's HTTP port the URL would be unusable.
//
// Fail-open, deliberately: if the box's default route can't be resolved, the
// script writes nothing and exits 0. The run proceeds without tracker tools
// rather than failing the whole seed — the same posture the model-gateway env
// script takes — and never leaves an `http://:8080` file behind that would mount
// a broken server without saying so.
func platformMCPSeedScript(seedDir string, httpPort int, trackerConnection string) (script string, ok bool) {
	if trackerConnection == "" || httpPort <= 0 {
		return "", false
	}
	raw, err := json.Marshal(platformMCPSeed{
		Command:   "mcp-server",
		Args:      []string{},
		ServerURL: fmt.Sprintf("http://%s:%d", platformMCPHostPlaceholder, httpPort),
		TokenFile: seedDir + "/token",
		Tools:     "tracker_*",
	})
	if err != nil {
		// Four strings and an empty slice cannot fail to marshal.
		return "", false
	}
	var b strings.Builder
	b.WriteString("__ctn_host=\"$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')\"\n")
	b.WriteString("if [ -z \"$__ctn_host\" ]; then\n")
	b.WriteString("  echo 'platform-mcp: could not resolve host from default route; tracker tools not mounted' >&2\n")
	b.WriteString("else\n")
	fmt.Fprintf(&b, "  mkdir -p %s\n", shellSingleQuote(seedDir))
	// The host is an IP from `ip route`; the only other input to sed is the
	// daemon-built JSON, quoted as one shell word.
	fmt.Fprintf(&b, "  printf '%%s' %s | sed \"s|%s|$__ctn_host|\" > %s/platform_mcp.json\n",
		shellSingleQuote(string(raw)), platformMCPHostPlaceholder, shellSingleQuote(seedDir))
	b.WriteString("fi\n")
	return b.String(), true
}
