package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// BridgeDNSStatusResponse mirrors the daemon's GetBridgeDNSStatusResponse
// (#2188): the reconcile state of the bridge DNS record that resolves the
// app-hosting base domain to core-caddy — NOT_MANAGED, PENDING, IN_SYNC or
// DEGRADED (BridgeDNSState enum names, unprefixed).
type BridgeDNSStatusResponse struct {
	State       string `json:"state"`
	Reason      string `json:"reason,omitempty"`
	Bridge      string `json:"bridge,omitempty"`
	CaddyIP     string `json:"caddyIp,omitempty"`
	Desired     string `json:"desired,omitempty"`
	Current     string `json:"current,omitempty"`
	LastError   string `json:"lastError,omitempty"`
	DriftCount  int32  `json:"driftCount,omitempty"`
	LastPass    string `json:"lastPass,omitempty"`
	LastApplied string `json:"lastApplied,omitempty"`
}

// handleBridgeDNSStatus reports the bridge DNS reconciler's last pass. Takes no
// arguments — a host-level read, not scoped to a container.
func handleBridgeDNSStatus(client API, args map[string]interface{}) (string, error) {
	resp, err := client.GetBridgeDNSStatus()
	if err != nil {
		return "", fmt.Errorf("bridge dns status: %w", err)
	}
	// Strip the enum's repeated prefix so the agent sees "IN_SYNC"/"DEGRADED"
	// rather than "BRIDGE_DNS_STATE_IN_SYNC" — the same normalization the CLI
	// applies.
	resp.State = strings.TrimPrefix(resp.State, "BRIDGE_DNS_STATE_")
	out, _ := json.MarshalIndent(resp, "", "  ")
	return string(out), nil
}
