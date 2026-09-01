package threatdetect

import (
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestFenceProbe_TwoOrgPeers_CrossTenantFlowAndDenyBurst is the #1642
// acceptance-criteria proof, driven through the real Engine (both rules
// registered, exactly as internal/server/dual_server.go wires them) rather
// than each rule in isolation.
//
// The issue and design doc ask for this reusing `cmd/isolation-sentry`'s
// two-org peer scaffolding against a real backend. That command/scaffolding
// does not exist in this repo (searched: no cmd/isolation-sentry directory,
// no isolation-sentry references anywhere in the tree) — the design doc's
// reference to it is stale. Flagged on the issue and in the PR as a gap:
// the full two-org Incus/eBPF e2e needs new scaffolding built first, which
// is out of scope for a single-package rules PR. This test is the
// Engine-level fallback the coordinating story's directive calls for
// instead, and should be superseded by a real e2e once that scaffolding
// exists.
func TestFenceProbe_TwoOrgPeers_CrossTenantFlowAndDenyBurst(t *testing.T) {
	// "Two-org peers on one backend": org-a's container at 10.10.0.5,
	// org-b's at 10.10.0.9, both resolvable via the enforcer's ip_tenant
	// cache (faked here as RuleContext.TenantForIP would be in production).
	tenants := map[string]string{
		"10.10.0.5": "org-a",
		"10.10.0.9": "org-b",
	}
	clock := time.Unix(2_000_000, 0)
	now := func() time.Time { return clock }

	sink := &fakeSink{}
	engine := NewEngine(sink, "backend-1", false, fakeTenants(tenants), now)
	engine.Register(NewCrossTenantFlowRule())
	engine.Register(NewDenyBurstRule(20, 5*time.Minute)) // design doc defaults

	t.Run("breached fence: org-a probes org-b directly, CRITICAL", func(t *testing.T) {
		engine.OnFlows([]netbpf.FlowRecord{{
			Saddr: beIP(10, 10, 0, 5), Daddr: beIP(10, 10, 0, 9),
			Sport: 44000, Dport: 22, Proto: 6, Bytes: 512, Packets: 4,
		}})

		found := findUpsert(sink.calls(), pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW)
		if found == nil {
			t.Fatal("no cross-tenant-flow finding upserted")
		}
		if found.Severity != pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL {
			t.Errorf("severity = %v, want CRITICAL", found.Severity)
		}
		if found.TenantID != "org-a" || found.Subject != "org-b" {
			t.Errorf("tenant/subject = %s/%s, want org-a/org-b", found.TenantID, found.Subject)
		}
	})

	t.Run("probed fence: org-b's container accumulates a deny burst against org-a, MEDIUM", func(t *testing.T) {
		sink.reset()
		// The network-policy enforcer would deny each of these (blocked
		// cross-tenant attempts, e.g. under enforce mode); we drive the
		// engine's OnDeny hook directly the same way the enforcer does.
		for i := 0; i < 20; i++ {
			engine.OnDeny(netbpf.DenyEvent{
				Saddr: beIP(10, 10, 0, 9), Daddr: beIP(10, 10, 0, 5),
				Dport: 22, Proto: 6, Reason: netbpf.DenyReasonPolicy,
			})
		}
		// deny-burst is Sweep-driven (30s engine tick in production).
		engine.Sweep(clock)

		found := findUpsert(sink.calls(), pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST)
		if found == nil {
			t.Fatal("no deny-burst finding upserted")
		}
		if found.Severity != pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM {
			t.Errorf("severity = %v, want MEDIUM", found.Severity)
		}
		if found.TenantID != "org-b" {
			t.Errorf("tenant = %s, want org-b (the probing side)", found.TenantID)
		}
	})

	t.Run("below threshold: 19 denies alone never fire", func(t *testing.T) {
		sink.reset()
		fresh := NewEngine(sink, "backend-1", false, fakeTenants(tenants), now)
		fresh.Register(NewDenyBurstRule(20, 5*time.Minute))
		for i := 0; i < 19; i++ {
			fresh.OnDeny(netbpf.DenyEvent{Saddr: beIP(10, 10, 0, 9), Daddr: beIP(10, 10, 0, 5)})
		}
		fresh.Sweep(clock)
		if found := findUpsert(sink.calls(), pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST); found != nil {
			t.Errorf("finding upserted below threshold: %+v", found)
		}
	})
}

func findUpsert(calls []*Finding, rule pb.ThreatRuleId) *Finding {
	for _, f := range calls {
		if f.Rule == rule {
			return f
		}
	}
	return nil
}
