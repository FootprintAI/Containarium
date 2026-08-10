package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #1188 AC1 and AC3: NetworkPolicyService changes reach the K8s backend, and
// a removed policy reverts to the default-deny floor.

// recordingApplier captures what the reconciler asked the backend to apply.
type recordingApplier struct {
	mu    sync.Mutex
	calls []applyCall
	err   error
}

type applyCall struct {
	tenant string
	policy *pb.NetworkPolicy
}

func (a *recordingApplier) ApplyTenantPolicy(_ context.Context, tenant string, p *pb.NetworkPolicy) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, applyCall{tenant: tenant, policy: p})
	return a.err
}

func (a *recordingApplier) since(n int) []applyCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n >= len(a.calls) {
		return nil
	}
	return append([]applyCall(nil), a.calls[n:]...)
}

// listStore is a NetworkPolicyStore whose List is all the reconciler uses.
type listStore struct {
	policies []*pb.NetworkPolicy
	err      error
}

func (s *listStore) List(context.Context) ([]*pb.NetworkPolicy, error) {
	return s.policies, s.err
}
func (s *listStore) Set(context.Context, *pb.NetworkPolicy) error { return nil }
func (s *listStore) Get(context.Context, string) (*pb.NetworkPolicy, error) {
	return nil, errors.New("not used")
}
func (s *listStore) Delete(context.Context, string) error { return nil }
func (s *listStore) MutateDenyRules(context.Context, string,
	func([]*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error)) (*pb.NetworkPolicy, error) {
	return nil, errors.New("not used")
}

func TestK8sNetPolicyReconcile_AppliesEachTenantsPolicy(t *testing.T) {
	store := &listStore{policies: []*pb.NetworkPolicy{
		{Tenant: "alice", EgressCidrs: []string{"10.0.0.0/8"}},
		{Tenant: "bob", EgressCidrs: []string{"192.168.0.0/16"}},
	}}
	applier := &recordingApplier{}
	r := NewK8sNetworkPolicyReconciler(store, applier, 0)

	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(applier.calls) != 2 {
		t.Fatalf("applied %d policies, want 2", len(applier.calls))
	}
}

// THE property that needs the applied-set. A deleted policy simply stops
// appearing in the store — nothing announces it. Without remembering that we
// wrote one, the tenant's last allowlist would persist forever: a permission
// that was revoked and kept working.
func TestK8sNetPolicyReconcile_RemovedPolicyRevertsToTheFloor(t *testing.T) {
	store := &listStore{policies: []*pb.NetworkPolicy{
		{Tenant: "alice", EgressCidrs: []string{"10.0.0.0/8"}},
	}}
	applier := &recordingApplier{}
	r := NewK8sNetworkPolicyReconciler(store, applier, 0)

	ctx := context.Background()
	if err := r.Reconcile(ctx); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	before := len(applier.calls)

	// The policy is deleted.
	store.policies = nil
	if err := r.Reconcile(ctx); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}

	reverts := applier.since(before)
	if len(reverts) != 1 {
		t.Fatalf("after deletion the reconciler made %d calls, want 1 revert: %+v", len(reverts), reverts)
	}
	if reverts[0].tenant != "alice" {
		t.Errorf("reverted tenant %q, want alice", reverts[0].tenant)
	}
	// A nil policy is how the backend is told to fall back to the floor.
	if reverts[0].policy != nil {
		t.Errorf("revert passed a policy (%+v); nil is what reverts to the default-deny floor",
			reverts[0].policy)
	}
}

// And once reverted, it must not be reverted again on every subsequent pass —
// that would rewrite the object forever.
func TestK8sNetPolicyReconcile_RevertHappensOnce(t *testing.T) {
	store := &listStore{policies: []*pb.NetworkPolicy{{Tenant: "alice"}}}
	applier := &recordingApplier{}
	r := NewK8sNetworkPolicyReconciler(store, applier, 0)
	ctx := context.Background()

	_ = r.Reconcile(ctx)
	store.policies = nil
	_ = r.Reconcile(ctx)
	after := len(applier.calls)
	_ = r.Reconcile(ctx)

	if len(applier.calls) != after {
		t.Errorf("a tenant with no policy was reverted again (%d extra calls); the object would be "+
			"rewritten on every pass", len(applier.calls)-after)
	}
}

// A refused policy must not stop the other tenants converging, and must not
// be forgotten — the tenant may still be carrying an earlier policy of ours
// that has to be reverted when theirs is deleted.
func TestK8sNetPolicyReconcile_OneFailureDoesNotBlockOthers(t *testing.T) {
	store := &listStore{policies: []*pb.NetworkPolicy{
		{Tenant: "alice"}, {Tenant: "bob"}, {Tenant: "carol"},
	}}
	applier := &recordingApplier{err: errors.New("cannot express deny_rules")}
	r := NewK8sNetworkPolicyReconciler(store, applier, 0)

	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("a per-tenant failure aborted the whole reconcile: %v", err)
	}
	if len(applier.calls) != 3 {
		t.Errorf("attempted %d tenants, want all 3 despite failures", len(applier.calls))
	}

	// The failing tenant is still tracked, so a later deletion still reverts.
	applier.err = nil
	store.policies = nil
	before := len(applier.calls)
	_ = r.Reconcile(context.Background())
	if got := len(applier.since(before)); got != 3 {
		t.Errorf("reverted %d tenants, want 3 — a tenant whose apply failed was forgotten, so its "+
			"namespace would keep whatever policy it had", got)
	}
}

// A tenant with an empty name cannot be mapped to a namespace; skipping it is
// right, applying it to "" would be a namespace nobody owns.
func TestK8sNetPolicyReconcile_SkipsAnEmptyTenant(t *testing.T) {
	store := &listStore{policies: []*pb.NetworkPolicy{{Tenant: ""}}}
	applier := &recordingApplier{}
	r := NewK8sNetworkPolicyReconciler(store, applier, 0)

	_ = r.Reconcile(context.Background())
	if len(applier.calls) != 0 {
		t.Errorf("applied a policy with no tenant: %+v", applier.calls)
	}
}

func TestK8sNetPolicyReconcile_StoreFailureIsReported(t *testing.T) {
	store := &listStore{err: errors.New("postgres down")}
	r := NewK8sNetworkPolicyReconciler(store, &recordingApplier{}, 0)

	if err := r.Reconcile(context.Background()); err == nil {
		t.Error("a store failure was swallowed; the reconciler would look healthy while diverged")
	}
}
