package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/guardrailrate"
	"github.com/footprintai/containarium/internal/guardrailstage"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Rate limits on the guardrail APIs (#2404). Every limiter here runs on a
// frozen clock: nothing refills during a test, and nothing sleeps.

func frozenLimiter(name string, lim guardrailrate.Limit) *guardrailrate.Limiter {
	at := time.Unix(1_700_000_000, 0)
	return guardrailrate.New(name, lim,
		guardrailrate.WithClock(func() time.Time { return at }),
		guardrailrate.WithLogf(func(string, ...any) {}))
}

// stagingListing is every path under the staging root with its size and
// mtime, so a test can assert a refused deploy left it untouched.
func stagingListing(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		out[p] = fmt.Sprintf("%s %v %d", fi.ModTime(), fi.Mode(), fi.Size())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Acceptance criterion 1: over the gated-deploy limit, the deploy is
// RESOURCE_EXHAUSTED before any snapshot is taken; the fake backend creates
// nothing and the staging directory is untouched.
func TestDeployGate_RateLimitedBeforeAnySnapshot(t *testing.T) {
	f := newGateFixture(t)
	f.srv.SetGuardrailDeployRateLimit(frozenLimiter("gated deploy", guardrailrate.Limit{PerMinute: 6, Burst: 1}))
	snapshots := 0
	f.srv.guardrailSnapshot = func(a *guardrailstage.Area, ref, parent string) (*guardrailstage.Snapshot, error) {
		snapshots++
		return a.Snapshot(ref, parent)
	}

	if _, err := f.deploy(t); err != nil {
		t.Fatalf("first deploy (within burst): %v", err)
	}
	if snapshots != 1 || len(f.boxes.created) != 1 {
		t.Fatalf("first deploy: %d snapshot(s), created %v; want 1 and one box", snapshots, f.boxes.created)
	}
	before := stagingListing(t, f.srv.guardrailStagingRoot)
	events := len(f.boxes.events)

	_, err := f.deploy(t)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second deploy = %v, want ResourceExhausted", err)
	}
	if snapshots != 1 {
		t.Errorf("throttled deploy took a snapshot (%d total), want none", snapshots)
	}
	if len(f.boxes.created) != 1 || len(f.boxes.events) != events {
		t.Errorf("throttled deploy touched the backend: created %v, events %v", f.boxes.created, f.boxes.events[events:])
	}
	after := stagingListing(t, f.srv.guardrailStagingRoot)
	if len(before) != len(after) {
		t.Errorf("staging root changed: %d entries before, %d after", len(before), len(after))
	}
	for p, v := range before {
		if after[p] != v {
			t.Errorf("staging entry %s changed: %q -> %q", p, v, after[p])
		}
	}
	f.assertNoSnapshotLeft(t)
}

// Acceptance criterion 2 on the deploy path: alice exhausting her budget
// does not throttle bob.
func TestDeployGate_RateLimitIsPerSubject(t *testing.T) {
	f := newGateFixture(t)
	f.srv.SetGuardrailDeployRateLimit(frozenLimiter("gated deploy", guardrailrate.Limit{PerMinute: 6, Burst: 1}))
	if _, err := f.deploy(t); err != nil {
		t.Fatalf("alice's first deploy: %v", err)
	}
	if _, err := f.deploy(t); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("alice's second deploy = %v, want ResourceExhausted", err)
	}
	bob := &pb.DeployRecipeRequest{RecipeId: "gated", Name: "bob", GuardrailInput: f.req.GetGuardrailInput()}
	_, err := f.srv.DeployRecipe(tenantWithScopes("bob", auth.ScopeContainersWrite), bob)
	if status.Code(err) == codes.ResourceExhausted {
		t.Fatalf("bob throttled by alice's budget: %v", err)
	}
}

// Ungated recipes are not on the guardrail surface and are never limited by
// it.
func TestDeployGate_RateLimitSkipsUngatedRecipes(t *testing.T) {
	f := newGateFixture(t)
	if err := f.srv.catalog.LoadFromBytes([]byte("recipes:\n  - id: gated\n    image: x\n")); err != nil {
		t.Fatal(err)
	}
	f.srv.SetGuardrailDeployRateLimit(frozenLimiter("gated deploy", guardrailrate.Limit{PerMinute: 6, Burst: 1}))
	for i := 0; i < 3; i++ {
		if _, err := f.deploy(t); err != nil {
			t.Fatalf("ungated deploy %d: %v", i, err)
		}
	}
}

// Acceptance criterion 3: Set is limited more tightly than Get, and the
// admin role is no exemption from the Set limit.
func TestGuardrailPolicy_SetAndGetLimits(t *testing.T) {
	s, _ := newGPServer()
	s.SetRateLimits(
		frozenLimiter("guardrail policy set", guardrailrate.Limit{PerMinute: 10, Burst: 2}),
		frozenLimiter("guardrail policy get", guardrailrate.Limit{PerMinute: 120, Burst: 5}),
	)
	sets := 0
	for i := 0; i < 10; i++ {
		_, err := s.SetGuardrailPolicy(gpAdminCtx(), gpRequest(0, gpSigner(1)))
		switch status.Code(err) {
		case codes.OK:
			sets++
		case codes.ResourceExhausted:
		default:
			t.Fatalf("Set %d: %v", i, err)
		}
	}
	if sets != 2 {
		t.Fatalf("admin Sets allowed in one instant = %d, want 2 (the Set burst; admins are not exempt)", sets)
	}
	gets := 0
	for i := 0; i < 10; i++ {
		_, err := s.GetGuardrailPolicy(gpUserCtx(), &pb.GetGuardrailPolicyRequest{})
		switch status.Code(err) {
		case codes.OK:
			gets++
		case codes.ResourceExhausted:
		default:
			t.Fatalf("Get %d: %v", i, err)
		}
	}
	if gets != 5 {
		t.Fatalf("Gets allowed in one instant = %d, want 5 (the Get burst)", gets)
	}
	// A different subject's Get budget is its own.
	if _, err := s.GetGuardrailPolicy(gpAdminCtx(), &pb.GetGuardrailPolicyRequest{}); err != nil {
		t.Fatalf("admin Get throttled by another subject's Gets: %v", err)
	}
}

// The Get limit refuses with RESOURCE_EXHAUSTED before the store is read.
func TestGuardrailPolicy_GetRefusedBeforeStoreRead(t *testing.T) {
	s := NewGuardrailPolicyServer(failingPolicyStore{})
	s.SetRateLimits(nil, frozenLimiter("guardrail policy get", guardrailrate.Limit{PerMinute: 120, Burst: 1}))
	if _, err := s.GetGuardrailPolicy(gpUserCtx(), &pb.GetGuardrailPolicyRequest{}); status.Code(err) != codes.Internal {
		t.Fatalf("first Get = %v, want the store's Internal error (within burst)", err)
	}
	if _, err := s.GetGuardrailPolicy(gpUserCtx(), &pb.GetGuardrailPolicyRequest{}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second Get = %v, want ResourceExhausted", err)
	}
}
