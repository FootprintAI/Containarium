package network

import (
	"strings"
	"testing"
)

// A passthrough route must be reachable from the daemon host itself,
// not only from other machines. DNAT in PREROUTING never sees
// locally-generated packets — those traverse OUTPUT — so a published
// cluster endpoint answered "connection refused" to anything running on
// the host, including the e2e lane and any operator curling it (#1459).
//
// PortForwarder has always added both chains for exactly this reason;
// the passthrough path added only PREROUTING.
func TestPassthroughRuleArgs(t *testing.T) {
	pre := passthroughPreRoutingArgs(36443, "10.166.0.9", 6443, "tcp", "10.166.0.0/24")
	joined := strings.Join(pre, " ")
	if !strings.Contains(joined, "PREROUTING") || !strings.Contains(joined, "DNAT") {
		t.Fatalf("prerouting args are not a DNAT rule: %v", pre)
	}
	// Container-network traffic stays excluded, so containers keep
	// reaching external services on the same port.
	if !strings.Contains(joined, "10.166.0.0/24") {
		t.Errorf("prerouting rule lost its container-network exclusion: %v", pre)
	}

	out := passthroughOutputArgs(36443, "10.166.0.9", 6443, "tcp")
	oj := strings.Join(out, " ")
	if !strings.Contains(oj, "OUTPUT") || !strings.Contains(oj, "DNAT") {
		t.Fatalf("output args are not a DNAT rule: %v", out)
	}
	if !strings.Contains(oj, "10.166.0.9:6443") {
		t.Errorf("output rule does not target the route's destination: %v", out)
	}
	// Scoped to locally-destined traffic: without this the rule would
	// hijack every locally-originated connection to that port, whatever
	// its destination.
	if !strings.Contains(oj, "--dst-type") || !strings.Contains(oj, "LOCAL") {
		t.Errorf("output rule is not scoped to local destinations: %v", out)
	}
}

// Removal must undo both chains; leaving an OUTPUT rule behind would
// silently redirect a later, unrelated connection on that port.
func TestPassthroughRemovalCoversBothChains(t *testing.T) {
	chains := map[string]bool{}
	for _, args := range passthroughDeleteArgs(36443, "tcp") {
		for i, a := range args {
			if a == "-D" && i+1 < len(args) {
				chains[args[i+1]] = true
			}
		}
	}
	for _, want := range []string{"PREROUTING", "OUTPUT"} {
		if !chains[want] {
			t.Errorf("removal does not delete the %s rule: %v", want, chains)
		}
	}
}
