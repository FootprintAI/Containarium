//go:build integration

package threatdetect

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/events"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Both stores must use the new rule-generated subject without changing the
// dedupe scope of other rules or rewriting historical shared findings.
func TestMinerSignature_PerContainerStores(t *testing.T) {
	for _, backend := range []string{"postgres", "memory"} {
		t.Run(backend, func(t *testing.T) {
			ctx := context.Background()
			var store responseNotifyStore
			if backend == "postgres" {
				s, _, _ := newStores(t, threatdetectPool(t))
				store = s
			} else {
				audit, bus := memTestDeps(t)
				s, err := NewMemFindingStore(events.NewEmitter(bus), audit)
				if err != nil {
					t.Fatal(err)
				}
				store = s
			}
			// A valid old name pattern can itself end with @<box>. The new
			// namespace must not alias that historical unscoped subject.
			legacy, err := store.Upsert(ctx, &Finding{Rule: pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE,
				Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH, TenantID: "t1", Container: "box-legacy", Subject: "name:xmrig@box-a"})
			if err != nil {
				t.Fatal(err)
			}
			n := NewWebhookNotifier(newFakeConfigSource("http://127.0.0.1:1", ""), nil)
			store.SetNotifier(n) // no worker: inspect the real delivery gate
			rule := newTestMinerSigRule(t, nil)
			finding := func(box string) *Finding {
				ev := execEv("/tmp/xmrig", "xmrig", "xmrig")
				ev.Container = box
				raw := rule.OnExec(RuleContext{}, ev)[0]
				return &Finding{Rule: raw.Rule, Severity: raw.Severity, TenantID: raw.TenantID,
					Container: raw.Container, Subject: raw.Subject, Evidence: raw.Evidence}
			}
			a, err := store.Upsert(ctx, finding("box-a"))
			if err != nil {
				t.Fatal(err)
			}
			b, err := store.Upsert(ctx, finding("box-b"))
			if err != nil {
				t.Fatal(err)
			}
			if a.ID == b.ID || a.ID == legacy.ID || b.ID == legacy.ID {
				t.Fatal("new per-box findings collided with each other or legacy data")
			}
			// Concurrent re-fires of the same pattern retain one open row per
			// box and do not send repeat notifications inside the interval.
			var wg sync.WaitGroup
			for range 8 {
				for _, box := range []string{"box-a", "box-b"} {
					wg.Go(func() {
						if _, err := store.Upsert(ctx, finding(box)); err != nil {
							t.Errorf("repeat %s: %v", box, err)
						}
					})
				}
			}
			wg.Wait()
			for _, f := range []*Finding{a, b} {
				got, err := store.Get(ctx, f.ID)
				if err != nil || got.Count != 9 || got.Container != f.Container {
					t.Fatalf("repeat count/owner = %+v, %v", got, err)
				}
				if _, err := store.SetResponse(ctx, f.ID, FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE,
					State: pb.ResponseState_RESPONSE_STATE_APPLIED, Container: f.Container}); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now()
			release := func(f *Finding) {
				out, err := store.ResolveWithResponse(ctx, f.ID, FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE,
					State: pb.ResponseState_RESPONSE_STATE_RELEASED, Container: f.Container, ReleasedAt: now, ReleasedBy: ReleasedByOperator})
				if err != nil || out.State != FindingStateResolved {
					t.Fatalf("release = %+v, %v", out, err)
				}
			}
			release(a)
			got, err := store.Get(ctx, b.ID)
			if err != nil || got.State != FindingStateOpen || got.Response.State != pb.ResponseState_RESPONSE_STATE_APPLIED || got.Response.Container != "box-b" {
				t.Fatalf("B after A release = %+v, %v", got, err)
			}
			release(b)
			if got, err := store.Get(ctx, legacy.ID); err != nil || got.Count != 1 || got.State != FindingStateOpen {
				t.Fatalf("legacy finding modified = %+v, %v", got, err)
			}
			if len(n.queue) != 6 {
				t.Fatalf("deliveries = %d, want two new, two applies, two releases", len(n.queue))
			}
		})
	}
}
