package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeEgressMode(t *testing.T) {
	for in, want := range map[string]string{
		"":         "",
		"  ":       "",
		"log_only": "NETWORK_POLICY_MODE_LOG_ONLY",
		"log-only": "NETWORK_POLICY_MODE_LOG_ONLY",
		"enforce":  "NETWORK_POLICY_MODE_ENFORCE",
		"ENFORCE":  "NETWORK_POLICY_MODE_ENFORCE",
	} {
		got, err := normalizeEgressMode(in)
		if err != nil || got != want {
			t.Errorf("normalizeEgressMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := normalizeEgressMode("drop"); err == nil {
		t.Error("an unknown egress mode must be refused, not sent to the server")
	}
}

// Unset egress mode is omitted on the wire (the server reads it as "follow
// mode", and an older daemon is not sent a field it does not know).
func TestNetPolicyJSON_EgressModeWireShape(t *testing.T) {
	b, _ := json.Marshal(netPolicyJSON{Tenant: "a", Mode: "NETWORK_POLICY_MODE_ENFORCE", EgressMode: "NETWORK_POLICY_MODE_LOG_ONLY"})
	if !strings.Contains(string(b), `"egressMode":"NETWORK_POLICY_MODE_LOG_ONLY"`) {
		t.Errorf("wire = %s", b)
	}
	b, _ = json.Marshal(netPolicyJSON{Tenant: "a"})
	if strings.Contains(string(b), "egressMode") {
		t.Errorf("an unset egress mode must be omitted: %s", b)
	}
}

func TestPrintPolicy_EgressMode(t *testing.T) {
	var set, unset bytes.Buffer
	printPolicy(&set, netPolicyJSON{Tenant: "a", Mode: "NETWORK_POLICY_MODE_ENFORCE", EgressMode: "NETWORK_POLICY_MODE_LOG_ONLY"})
	printPolicy(&unset, netPolicyJSON{Tenant: "a", Mode: "NETWORK_POLICY_MODE_ENFORCE"})
	if !strings.Contains(set.String(), "egress-mode:        LOG_ONLY") {
		t.Errorf("egress mode not shown:\n%s", set.String())
	}
	if !strings.Contains(unset.String(), "egress-mode:        ENFORCE (follows mode)") {
		t.Errorf("unset egress mode must show the mode it follows:\n%s", unset.String())
	}
}
