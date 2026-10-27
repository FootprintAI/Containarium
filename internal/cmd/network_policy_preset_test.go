package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeEgressPreset(t *testing.T) {
	for in, want := range map[string]string{
		"":                "",
		"  ":              "",
		"allow-list-only": "EGRESS_PRESET_ALLOW_LIST_ONLY",
		"ALLOW_LIST_ONLY": "EGRESS_PRESET_ALLOW_LIST_ONLY",
	} {
		got, err := normalizeEgressPreset(in)
		if err != nil || got != want {
			t.Errorf("normalizeEgressPreset(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := normalizeEgressPreset("deny-all"); err == nil {
		t.Error("an unknown preset must be refused, not sent to the server")
	}
}

// The preset travels as the proto enum name, and is omitted when unset so an
// older daemon that does not know the field is not sent it.
func TestNetPolicyJSON_PresetWireShape(t *testing.T) {
	b, _ := json.Marshal(netPolicyJSON{Tenant: "a", Mode: "NETWORK_POLICY_MODE_ENFORCE", EgressPreset: "EGRESS_PRESET_ALLOW_LIST_ONLY"})
	if !strings.Contains(string(b), `"egressPreset":"EGRESS_PRESET_ALLOW_LIST_ONLY"`) {
		t.Errorf("wire = %s", b)
	}
	b, _ = json.Marshal(netPolicyJSON{Tenant: "a"})
	if strings.Contains(string(b), "egressPreset") {
		t.Errorf("an unset preset must be omitted: %s", b)
	}
}

func TestPrintPolicy_ShowsPresetOnlyWhenSet(t *testing.T) {
	var on, off bytes.Buffer
	printPolicy(&on, netPolicyJSON{Tenant: "a", Mode: "NETWORK_POLICY_MODE_ENFORCE", EgressPreset: "EGRESS_PRESET_ALLOW_LIST_ONLY"})
	printPolicy(&off, netPolicyJSON{Tenant: "a", Mode: "NETWORK_POLICY_MODE_ENFORCE", EgressPreset: "EGRESS_PRESET_UNSPECIFIED"})
	if !strings.Contains(on.String(), "egress-preset:      allow-list-only") {
		t.Errorf("preset not shown:\n%s", on.String())
	}
	if strings.Contains(off.String(), "egress-preset") {
		t.Errorf("unspecified preset must not be shown:\n%s", off.String())
	}
}

func TestPrintPlan_TableAndPasteableFlags(t *testing.T) {
	var b bytes.Buffer
	printPlan(&b, planEnvelope{
		Tenant: "acme", SinceMinutes: 60, RowsScanned: 4,
		Destinations: []planDestination{
			{IP: "140.82.112.3", Port: 443, Protocol: "tcp", Count: 12, LastSeen: "2026-10-10T12:00:00Z"},
			{IP: "140.82.112.3", Port: 22, Protocol: "tcp", Count: 2, Dropped: true},
			{IP: "9.9.9.9", Port: 853, Protocol: "tcp", Count: 1},
		},
		Notes: []string{"some caveat"},
	})
	out := b.String()
	for _, want := range []string{"140.82.112.3", "dropped", "logged", "--egress-cidr 140.82.112.3/32 --egress-cidr 9.9.9.9/32", "some caveat", "network-policy set acme"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// One flag per address, however many ports it was seen on.
	if strings.Count(out, "--egress-cidr 140.82.112.3/32") != 1 {
		t.Errorf("an address seen on two ports must yield one flag:\n%s", out)
	}
}

func TestPrintPlan_EmptyAndTruncated(t *testing.T) {
	var b bytes.Buffer
	printPlan(&b, planEnvelope{Tenant: "acme", SinceMinutes: 30})
	if !strings.Contains(b.String(), "blocked nothing") || strings.Contains(b.String(), "--egress-cidr") {
		t.Errorf("empty plan:\n%s", b.String())
	}
	b.Reset()
	printPlan(&b, planEnvelope{Tenant: "acme", SinceMinutes: 30, Truncated: true, RowsScanned: 5000})
	if !strings.Contains(b.String(), "row cap was reached after 5000") {
		t.Errorf("truncation not reported:\n%s", b.String())
	}
}
