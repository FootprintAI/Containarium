package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// The gateway's JSON for GetNetworkPolicyStatusResponse decodes into the
// local mirror.
func TestStatusEnvelope_DecodesGatewayJSON(t *testing.T) {
	raw := `{"status":{"tenant":"acme","state":"NETWORK_POLICY_APPLIED_STATE_LOADED",
		"effectiveMode":"NETWORK_POLICY_MODE_LOG_ONLY","effectiveEgressMode":"NETWORK_POLICY_MODE_LOG_ONLY",
		"lastAppliedAt":"2026-10-23T10:00:00Z","enforcementArmed":false,"boxesLoaded":2,"boxesNotLoaded":1,
		"uncoveredPaths":["NETWORK_POLICY_UNCOVERED_PATH_IPV6","NETWORK_POLICY_UNCOVERED_PATH_DOMAIN_REFRESH_LAG"]}}`
	var env statusEnvelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatal(err)
	}
	s := env.Status
	if s.Tenant != "acme" || s.BoxesLoaded != 2 || s.BoxesNotLoaded != 1 || len(s.UncoveredPaths) != 2 || s.LastAppliedAt == "" {
		t.Errorf("decoded = %+v", s)
	}
}

func TestPrintStatus_LoadedOnUnarmedHost(t *testing.T) {
	var b bytes.Buffer
	printStatus(&b, policyStatusJSON{
		Tenant:              "acme",
		State:               "NETWORK_POLICY_APPLIED_STATE_LOADED",
		EffectiveMode:       "NETWORK_POLICY_MODE_LOG_ONLY",
		EffectiveEgressMode: "NETWORK_POLICY_MODE_LOG_ONLY",
		LastAppliedAt:       "2026-10-23T10:00:00Z",
		BoxesLoaded:         2,
		BoxesNotLoaded:      1,
		UncoveredPaths:      []string{"NETWORK_POLICY_UNCOVERED_PATH_IPV6", "NETWORK_POLICY_UNCOVERED_PATH_DOMAIN_REFRESH_LAG"},
	})
	out := b.String()
	for _, want := range []string{
		"state:              loaded",
		"effective-mode:     LOG_ONLY",
		"egress-mode:        LOG_ONLY",
		"last-applied:       2026-10-23T10:00:00Z",
		"enforcement-armed:  false (a requested enforce is loaded as log_only on this host)",
		"boxes:              2 loaded, 1 NOT loaded",
		"ipv6",
		"domain refresh lag",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestPrintStatus_UnknownSaysUnknown(t *testing.T) {
	for state, want := range map[string]string{
		"NETWORK_POLICY_APPLIED_STATE_ENFORCER_NOT_RUNNING": "enforcer not running",
		"NETWORK_POLICY_APPLIED_STATE_NOT_LOADED":           "not loaded",
		"":                                                  "unknown",
		"NETWORK_POLICY_APPLIED_STATE_UNSPECIFIED":          "unknown",
	} {
		var b bytes.Buffer
		printStatus(&b, policyStatusJSON{Tenant: "acme", State: state, EnforcementArmed: true})
		out := b.String()
		if !strings.Contains(out, "state:              "+want) {
			t.Errorf("state %q: want %q in:\n%s", state, want, out)
		}
		if !strings.Contains(out, "effective-mode:     unknown") || !strings.Contains(out, "egress-mode:        unknown") {
			t.Errorf("state %q: modes must read unknown:\n%s", state, out)
		}
		if strings.Contains(out, "last-applied") {
			t.Errorf("state %q: no last-applied when nothing is loaded:\n%s", state, out)
		}
	}
}
