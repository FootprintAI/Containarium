package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The gateway's JSON for GetNetworkPolicyStatusResponse decodes into the
// generated type, so the CLI cannot drift from the contract.
func TestDecodeStatus_GatewayJSON(t *testing.T) {
	raw := []byte(`{"status":{"tenant":"acme","state":"NETWORK_POLICY_APPLIED_STATE_LOADED",
		"effectiveMode":"NETWORK_POLICY_MODE_LOG_ONLY","effectiveEgressMode":"NETWORK_POLICY_MODE_ENFORCE",
		"lastReconciledAt":"2026-10-23T10:00:00Z","enforcementArmed":false,"boxesLoaded":2,"boxesNotLoaded":1,
		"uncoveredPaths":["NETWORK_POLICY_UNCOVERED_PATH_IPV6","NETWORK_POLICY_UNCOVERED_PATH_DOMAIN_REFRESH_LAG"],
		"aFieldFromANewerDaemon":true}}`)
	s, err := decodeStatus(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.GetTenant() != "acme" || s.GetBoxesLoaded() != 2 || s.GetBoxesNotLoaded() != 1 || len(s.GetUncoveredPaths()) != 2 {
		t.Errorf("decoded = %v", s)
	}
	if s.GetEffectiveEgressMode() != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE {
		t.Errorf("effective egress mode = %v", s.GetEffectiveEgressMode())
	}
	if !s.GetLastReconciledAt().AsTime().Equal(time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("last_reconciled_at = %v", s.GetLastReconciledAt())
	}
}

// A tenant name is one path segment, whatever it contains.
func TestNetworkPolicyStatusURL_EscapesTenant(t *testing.T) {
	got := networkPolicyStatusURL("http://localhost:8080/", "a/b c")
	if want := "http://localhost:8080/v1/network-policies/a%2Fb%20c/status"; got != want {
		t.Errorf("url = %q, want %q", got, want)
	}
}

func TestPrintStatus_PartiallyLoadedOnUnarmedHost(t *testing.T) {
	var b bytes.Buffer
	printStatus(&b, &pb.NetworkPolicyStatus{
		Tenant:              "acme",
		State:               pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_PARTIALLY_LOADED,
		EffectiveMode:       pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY,
		EffectiveEgressMode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY,
		LastReconciledAt:    timestamppb.New(time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)),
		BoxesLoaded:         2,
		BoxesNotLoaded:      1,
		UncoveredPaths: []pb.NetworkPolicyUncoveredPath{
			pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_IPV6,
			pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_DOMAIN_REFRESH_LAG,
			pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_KERNEL_UNSUPPORTED,
		},
	})
	out := b.String()
	for _, want := range []string{
		"state:              PARTIALLY loaded: the tenant is NOT fully covered",
		"effective-mode:     LOG_ONLY",
		"egress-mode:        LOG_ONLY",
		"last-reconciled:    2026-10-23T10:00:00Z",
		"enforcement-armed:  false (a requested enforce is loaded as log_only on this host)",
		"boxes:              2 loaded, 1 NOT loaded",
		"ipv6",
		"domain refresh lag",
		"kernel unsupported",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestPrintStatus_UnknownSaysUnknown(t *testing.T) {
	for state, want := range map[pb.NetworkPolicyAppliedState]string{
		pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_ENFORCER_NOT_RUNNING: "enforcer not running",
		pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED:           "not loaded",
		pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_UNSPECIFIED:          "unknown",
		pb.NetworkPolicyAppliedState(99):                                               "unknown",
	} {
		var b bytes.Buffer
		printStatus(&b, &pb.NetworkPolicyStatus{Tenant: "acme", State: state, EnforcementArmed: true})
		out := b.String()
		if !strings.Contains(out, "state:              "+want) {
			t.Errorf("state %v: want %q in:\n%s", state, want, out)
		}
		if !strings.Contains(out, "effective-mode:     unknown") || !strings.Contains(out, "egress-mode:        unknown") {
			t.Errorf("state %v: modes must read unknown:\n%s", state, out)
		}
		if strings.Contains(out, "last-reconciled") {
			t.Errorf("state %v: no last-reconciled when no pass is reported:\n%s", state, out)
		}
	}
}

// Every running box loaded reads as plainly loaded.
func TestPrintStatus_FullyLoaded(t *testing.T) {
	var b bytes.Buffer
	printStatus(&b, &pb.NetworkPolicyStatus{
		Tenant:              "acme",
		State:               pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED,
		EffectiveMode:       pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
		EffectiveEgressMode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
		EnforcementArmed:    true,
		BoxesLoaded:         3,
	})
	out := b.String()
	for _, want := range []string{"state:              loaded (every running box", "effective-mode:     ENFORCE", "boxes:              3 loaded\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// A stalled reconciler: modes unknown, the last pass's time still shown.
func TestPrintStatus_Stale(t *testing.T) {
	var b bytes.Buffer
	printStatus(&b, &pb.NetworkPolicyStatus{
		Tenant:           "acme",
		State:            pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_STALE,
		LastReconciledAt: timestamppb.New(time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)),
		EnforcementArmed: true,
	})
	out := b.String()
	for _, want := range []string{
		"state:              stale",
		"effective-mode:     unknown",
		"egress-mode:        unknown",
		"last-reconciled:    2026-10-23T10:00:00Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// "loaded as log_only" describes what is loaded, so it is said only when
// something is loaded.
func TestPrintStatus_UnarmedSuffixOnlyWhenLoaded(t *testing.T) {
	const suffix = "a requested enforce is loaded as log_only"
	for state, want := range map[pb.NetworkPolicyAppliedState]bool{
		pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED:               true,
		pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_PARTIALLY_LOADED:     true,
		pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_ENFORCER_NOT_RUNNING: false,
		pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED:           false,
		pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_STALE:                false,
		pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_UNSPECIFIED:          false,
	} {
		var b bytes.Buffer
		printStatus(&b, &pb.NetworkPolicyStatus{Tenant: "acme", State: state})
		out := b.String()
		if !strings.Contains(out, "enforcement-armed:  false") {
			t.Errorf("state %v: missing enforcement-armed line:\n%s", state, out)
		}
		if got := strings.Contains(out, suffix); got != want {
			t.Errorf("state %v: suffix printed = %v, want %v:\n%s", state, got, want, out)
		}
	}
}

// Every uncovered path the API can report has a human-readable line, so the
// CLI never falls back to the bare enum name for one (#2983 added one).
func TestUncoveredPathText_CoversEveryReportedPath(t *testing.T) {
	for v, name := range pb.NetworkPolicyUncoveredPath_name {
		path := pb.NetworkPolicyUncoveredPath(v)
		if path == pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_UNSPECIFIED {
			continue
		}
		if strings.TrimSpace(uncoveredPathText[path]) == "" {
			t.Errorf("uncovered path %s has no line in uncoveredPathText", name)
		}
	}
}
