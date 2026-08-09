package server

import (
	"context"
	"log"
	"sync"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Converging tenant NetworkPolicy objects on the K8s backend (#1188).
//
// The eBPF enforcer drives the LXC path from the same store, re-reading it on
// a ticker so a dropped event cannot leave the world diverged. This mirrors
// that: the store is the source of truth on every pass, and the K8s objects
// are made to match it.
//
// It is a separate type rather than a mode of NetworkPolicyEnforcer because
// the enforcer is type-coupled to incus — its inspector returns
// []incus.ContainerInfo and it attaches TCX to host veths. Pods have neither.
// Only the store is shared, which is why the store interface is the seam.

// tenantPolicyApplier applies a tenant's policy to a backend. Satisfied by
// the K8s box backend; an interface so the reconcile logic is testable
// without a cluster.
type tenantPolicyApplier interface {
	ApplyTenantPolicy(ctx context.Context, tenant string, policy *pb.NetworkPolicy) error
}

// defaultK8sNetPolicyInterval matches the eBPF enforcer's cadence. The store
// is re-read each pass, so a missed change costs at most one interval.
const defaultK8sNetPolicyInterval = 10 * time.Second

// K8sNetworkPolicyReconciler converges each tenant's NetworkPolicy object
// with the tenant policy held in the store.
type K8sNetworkPolicyReconciler struct {
	store    NetworkPolicyStore
	applier  tenantPolicyApplier
	interval time.Duration

	// applied is the set of tenants this reconciler has written a policy for.
	//
	// Load-bearing: a tenant whose policy is DELETED simply stops appearing
	// in the store, so without remembering that we wrote one, nothing would
	// ever revert their namespace to the default-deny floor and the last
	// applied allowlist would persist indefinitely. A stale allowlist
	// outliving its policy is a permission that was revoked and kept working.
	mu      sync.Mutex
	applied map[string]struct{}

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewK8sNetworkPolicyReconciler builds a reconciler. A zero interval uses the
// default.
func NewK8sNetworkPolicyReconciler(store NetworkPolicyStore, applier tenantPolicyApplier, interval time.Duration) *K8sNetworkPolicyReconciler {
	if interval <= 0 {
		interval = defaultK8sNetPolicyInterval
	}
	return &K8sNetworkPolicyReconciler{
		store:    store,
		applier:  applier,
		interval: interval,
		applied:  map[string]struct{}{},
	}
}

// Start begins the reconcile loop. Safe to call once.
func (r *K8sNetworkPolicyReconciler) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	r.cancel = cancel

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		tick := time.NewTicker(r.interval)
		defer tick.Stop()
		for {
			// Reconcile immediately, then on each tick, so a daemon restart
			// converges without waiting out an interval.
			if err := r.Reconcile(ctx); err != nil {
				log.Printf("[k8s-netpolicy] reconcile: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	log.Printf("[k8s-netpolicy] reconciler started (interval=%s)", r.interval)
}

// Stop ends the loop and waits for it.
func (r *K8sNetworkPolicyReconciler) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
}

// Reconcile makes every tenant's NetworkPolicy match the store once.
//
// One tenant's failure never stops the others. A policy the backend refuses
// — because it contains something NetworkPolicy cannot express — is a
// standing condition, not a transient one, so it is logged on every pass
// rather than once: an operator who has not noticed yet should keep being
// told, and the alternative is a tenant silently running without the policy
// they configured.
func (r *K8sNetworkPolicyReconciler) Reconcile(ctx context.Context) error {
	policies, err := r.store.List(ctx)
	if err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(policies))
	for _, p := range policies {
		tenant := p.GetTenant()
		if tenant == "" {
			continue
		}
		seen[tenant] = struct{}{}

		if err := r.applier.ApplyTenantPolicy(ctx, tenant, p); err != nil {
			// Deliberately still marked applied: the tenant's namespace may
			// hold an earlier policy of ours, and forgetting it here would
			// mean never reverting it when the policy is later deleted.
			r.markApplied(tenant)
			log.Printf("[k8s-netpolicy] tenant %q: %v", tenant, err)
			continue
		}
		r.markApplied(tenant)
	}

	// Tenants we wrote a policy for that no longer have one: revert to the
	// default-deny floor. Not to allow-all — a delete must never widen.
	for _, tenant := range r.appliedNotIn(seen) {
		if err := r.applier.ApplyTenantPolicy(ctx, tenant, nil); err != nil {
			log.Printf("[k8s-netpolicy] tenant %q: reverting to the default-deny floor failed, so "+
				"its previous allowlist is still in force: %v", tenant, err)
			continue
		}
		r.forget(tenant)
		log.Printf("[k8s-netpolicy] tenant %q policy removed; reverted to the default-deny floor", tenant)
	}
	return nil
}

func (r *K8sNetworkPolicyReconciler) markApplied(tenant string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applied[tenant] = struct{}{}
}

func (r *K8sNetworkPolicyReconciler) forget(tenant string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.applied, tenant)
}

// appliedNotIn returns tenants we have written a policy for that are absent
// from the given set.
func (r *K8sNetworkPolicyReconciler) appliedNotIn(seen map[string]struct{}) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var gone []string
	for tenant := range r.applied {
		if _, ok := seen[tenant]; !ok {
			gone = append(gone, tenant)
		}
	}
	return gone
}
