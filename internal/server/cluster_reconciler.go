package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	clusterstore "github.com/footprintai/containarium/internal/cluster"
	clustercore "github.com/footprintai/containarium/pkg/core/cluster"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ClusterReconciler converges managed-cluster records (#1414): it
// reads desired state from the store, observes VMs on the host, and
// executes whatever the pure clustercore.Decide returns. All policy
// lives in Decide; this loop is plumbing plus bookkeeping (node rows,
// scale events, state transitions).
//
// One pass is idempotent and crash-safe: nothing here holds state
// between ticks, so a daemon restart resumes wherever the store and
// the host actually are.
type ClusterReconciler struct {
	store clusterstore.Store
	mgr   *clustercore.Manager

	// admit is the CPU-admission seam (nil = no gate, unit tests).
	// Refusals are recorded as events, never silent.
	admit func(owner, cpu string) error

	// publish allocates/records the external API endpoint for a
	// cluster whose control plane is up; unpublish reverses it.
	// Seamed for tests; production wires the passthrough route.
	publish   func(ctx context.Context, c *clusterstore.Cluster, cpIP string) (string, error)
	unpublish func(ctx context.Context, c *clusterstore.Cluster) error

	// vpaDisabled turns off VPA deployment (CONTAINARIUM_CLUSTER_VPA=false);
	// default is on — pod vertical autoscaling is a P0 story (#1416).
	vpaDisabled bool

	interval time.Duration
}

// NewClusterReconciler wires the loop. publish/unpublish may be nil
// (endpoint stays the CP IP; nothing to reverse).
func NewClusterReconciler(store clusterstore.Store, mgr *clustercore.Manager) *ClusterReconciler {
	return &ClusterReconciler{store: store, mgr: mgr, interval: 15 * time.Second}
}

// SetAdmission wires the CPU-admission gate.
func (r *ClusterReconciler) SetAdmission(f func(owner, cpu string) error) { r.admit = f }

// SetVPADisabled turns off VPA deployment into new clusters.
func (r *ClusterReconciler) SetVPADisabled(v bool) { r.vpaDisabled = v }

// SetEndpointPublisher wires endpoint publish/unpublish.
func (r *ClusterReconciler) SetEndpointPublisher(
	publish func(ctx context.Context, c *clusterstore.Cluster, cpIP string) (string, error),
	unpublish func(ctx context.Context, c *clusterstore.Cluster) error,
) {
	r.publish, r.unpublish = publish, unpublish
}

// ReadKubeconfig implements the ClusterServer's KubeconfigReader seam:
// read on demand from the CP VM, rewritten to the published endpoint,
// never persisted.
func (r *ClusterReconciler) ReadKubeconfig(ctx context.Context, c *clusterstore.Cluster) (string, error) {
	return r.mgr.Kubeconfig(c.Owner, c.Name, c.APIEndpoint)
}

// VMCapable is the create-time capability probe.
func (r *ClusterReconciler) VMCapable() error { return r.mgr.VMCapable() }

// Run ticks until ctx ends.
func (r *ClusterReconciler) Run(ctx context.Context) {
	log.Printf("[cluster] reconciler running (interval %v)", r.interval)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.ReconcileOnce(ctx)
		}
	}
}

// ReconcileOnce runs one pass over every cluster.
func (r *ClusterReconciler) ReconcileOnce(ctx context.Context) {
	clusters, err := r.store.List(ctx, "")
	if err != nil {
		log.Printf("[cluster] reconcile: list: %v", err)
		return
	}
	for _, c := range clusters {
		if err := r.reconcileCluster(ctx, c); err != nil {
			log.Printf("[cluster] reconcile %s/%s: %v", c.Owner, c.Name, err)
			// Provisioning failures surface on the record; the next
			// pass retries (interval = natural backoff).
			_ = r.store.SetState(ctx, c.Owner, c.Name, clusterstore.StateError, err.Error())
		}
	}
}

func desiredFrom(c *clusterstore.Cluster) clustercore.Desired {
	d := clustercore.Desired{
		Tenant:   c.Owner,
		Cluster:  c.Name,
		Deleting: c.State == clusterstore.StateDeleting,
	}
	for _, g := range c.NodeGroups {
		// Decide's Min is the CREATION target: the autoscaler-owned
		// target size clamped into [min, max] (#1415). Decide itself
		// stays scale-up-only; explicit removals go through the CA
		// provider's DeleteNodes.
		d.Groups = append(d.Groups, clustercore.DesiredGroup{
			Name: g.Name, Min: int(g.EffectiveTarget()), Max: int(g.MaxNodes),
			CPU: g.Size.CPU, Memory: g.Size.Memory, Disk: g.Size.Disk,
		})
	}
	return d
}

// cpSize is the control-plane VM's fixed size — platform overhead,
// deliberately not part of any tenant node group.
var cpSize = clustercore.DesiredGroup{CPU: "2", Memory: "4GB", Disk: "40GB"}

func (r *ClusterReconciler) reconcileCluster(ctx context.Context, c *clusterstore.Cluster) error {
	desired := desiredFrom(c)
	observed, err := r.mgr.Observe(c.Owner, c.Name)
	if err != nil {
		return fmt.Errorf("observe: %w", err)
	}
	actions := clustercore.Decide(desired, observed)

	groupByName := make(map[string]clustercore.DesiredGroup, len(desired.Groups))
	for _, g := range desired.Groups {
		groupByName[g.Name] = g
	}

	for _, act := range actions {
		switch act.Kind {
		case clustercore.ActionCreateCP:
			if err := r.admitSize(c, cpSize, "control-plane"); err != nil {
				return nil // refusal recorded; retry next pass
			}
			cpIP, err := r.mgr.ProvisionCP(c.Owner, c.Name, cpSize, nil)
			if err != nil {
				return fmt.Errorf("provision control plane: %w", err)
			}
			_ = r.store.UpsertNode(ctx, &clusterstore.Node{
				Owner: c.Owner, Cluster: c.Name, VMName: act.Name,
				Role: clusterstore.RoleControlPlane, State: clusterstore.NodeStateReady,
				CreatedAt: time.Now().UTC(),
			})
			log.Printf("[cluster] %s/%s: control plane up at %s", c.Owner, c.Name, cpIP)

		case clustercore.ActionCreateWorker:
			g := groupByName[act.Group]
			if err := r.admitSize(c, g, act.Group); err != nil {
				return nil // refusal recorded; retry next pass
			}
			cpIP, err := r.mgr.CPIP(c.Owner, c.Name)
			if err != nil {
				return fmt.Errorf("control-plane IP: %w", err)
			}
			if err := r.mgr.ProvisionWorker(c.Owner, c.Name, g, act.Name, cpIP); err != nil {
				return fmt.Errorf("provision worker %s: %w", act.Name, err)
			}
			_ = r.store.UpsertNode(ctx, &clusterstore.Node{
				Owner: c.Owner, Cluster: c.Name, VMName: act.Name,
				Role: clusterstore.RoleWorker, Group: act.Group,
				State: clusterstore.NodeStateProvisioning, CreatedAt: time.Now().UTC(),
			})
			_ = r.store.AppendEvent(ctx, c.Owner, c.Name, clusterstore.Event{
				At: time.Now().UTC(), Kind: clusterstore.EventScaleUp,
				Group: act.Group, Reason: "reconciler: group below min_nodes",
			})

		case clustercore.ActionStartVM:
			if err := r.mgr.StartVM(act.Name); err != nil {
				return fmt.Errorf("start %s: %w", act.Name, err)
			}

		case clustercore.ActionDeleteVM:
			if err := r.mgr.DeleteVM(act.Name); err != nil {
				return fmt.Errorf("delete %s: %w", act.Name, err)
			}
			_ = r.store.DeleteNode(ctx, c.Owner, c.Name, act.Name)
		}
	}

	if desired.Deleting {
		// Torn down when nothing is left on the host: drop the
		// endpoint and the rows — the name becomes reusable and a
		// re-created cluster starts empty.
		observed, err := r.mgr.Observe(c.Owner, c.Name)
		if err != nil {
			return fmt.Errorf("observe after teardown: %w", err)
		}
		if observed.CP == nil && len(observed.Workers) == 0 {
			if r.unpublish != nil {
				if err := r.unpublish(ctx, c); err != nil {
					return fmt.Errorf("unpublish endpoint: %w", err)
				}
			}
			if err := r.store.Delete(ctx, c.Owner, c.Name); err != nil {
				return fmt.Errorf("delete record: %w", err)
			}
			log.Printf("[cluster] %s/%s: deleted", c.Owner, c.Name)
		}
		return nil
	}

	return r.settleState(ctx, c)
}

// admitSize runs the CPU-admission gate for one VM-sized request; a
// refusal is recorded as a REFUSED scale event (loud, never clamped).
func (r *ClusterReconciler) admitSize(c *clusterstore.Cluster, g clustercore.DesiredGroup, what string) error {
	if r.admit == nil {
		return nil
	}
	if err := r.admit(c.Owner, g.CPU); err != nil {
		_ = r.store.AppendEvent(context.Background(), c.Owner, c.Name, clusterstore.Event{
			At: time.Now().UTC(), Kind: clusterstore.EventRefused,
			Group: what, Reason: fmt.Sprintf("admission refused %s cpu=%s: %v", what, g.CPU, err),
		})
		return err
	}
	return nil
}

// settleState publishes the endpoint once the CP is up and flips the
// record to READY when the cluster's own API reports every expected
// node Ready.
func (r *ClusterReconciler) settleState(ctx context.Context, c *clusterstore.Cluster) error {
	observed, err := r.mgr.Observe(c.Owner, c.Name)
	if err != nil {
		return fmt.Errorf("observe: %w", err)
	}
	if observed.CP == nil || !observed.CP.Running {
		return nil // still converging; nothing to settle
	}

	if c.APIEndpoint == "" {
		cpIP, err := r.mgr.CPIP(c.Owner, c.Name)
		if err != nil {
			return fmt.Errorf("control-plane IP: %w", err)
		}
		endpoint := cpIP + ":6443"
		if r.publish != nil {
			endpoint, err = r.publish(ctx, c, cpIP)
			if err != nil {
				return fmt.Errorf("publish endpoint: %w", err)
			}
		}
		if err := r.store.SetEndpoint(ctx, c.Owner, c.Name, endpoint); err != nil {
			return fmt.Errorf("record endpoint: %w", err)
		}
		c.APIEndpoint = endpoint
	}

	// VPA rides the settle path: a transient deploy failure retries
	// every pass until READY; DeployVPA is idempotent and never
	// rotates a deployed webhook secret.
	if !r.vpaDisabled && c.State != clusterstore.StateReady {
		if err := r.mgr.DeployVPA(c.Owner, c.Name); err != nil {
			return fmt.Errorf("deploy VPA: %w", err)
		}
	}

	expected := 1 // control plane
	for _, g := range c.NodeGroups {
		expected += int(g.EffectiveTarget())
	}
	ready, err := r.mgr.ReadyNodes(c.Owner, c.Name)
	if err != nil {
		return nil // API not up yet; try next pass
	}
	if ready >= expected && c.State != clusterstore.StateReady {
		if err := r.store.SetState(ctx, c.Owner, c.Name, clusterstore.StateReady, ""); err != nil {
			return err
		}
		// Worker rows ride along: the cluster API says they joined.
		nodes, _ := r.store.ListNodes(ctx, c.Owner, c.Name)
		for _, n := range nodes {
			if n.State != clusterstore.NodeStateReady {
				n.State = clusterstore.NodeStateReady
				_ = r.store.UpsertNode(ctx, n)
			}
		}
		log.Printf("[cluster] %s/%s: READY (%d nodes)", c.Owner, c.Name, ready)
	} else if ready < expected && c.State == clusterstore.StateReady {
		if err := r.store.SetState(ctx, c.Owner, c.Name, clusterstore.StateDegraded,
			fmt.Sprintf("%d of %d expected nodes Ready", ready, expected)); err != nil {
			return err
		}
	}
	return nil
}

// --- endpoint publishing over the passthrough surface ------------------

// WireEndpointPublisher connects the reconciler to the durable
// passthrough surface (design: create flow step 3): allocate an
// external port from portRange, DNAT it to <cp>:6443, and record
// <advertiseAddr>:<port> as the cluster's API endpoint. Invoked with
// the _system identity — this is a daemon-internal reconciler path.
func (r *ClusterReconciler) WireEndpointPublisher(network *NetworkServer, advertiseAddr, portRange string) error {
	lo, hi, err := parsePortRange(portRange)
	if err != nil {
		return err
	}
	r.publish = func(ctx context.Context, c *clusterstore.Cluster, cpIP string) (string, error) {
		port, err := r.freeClusterPort(ctx, lo, hi)
		if err != nil {
			return "", err
		}
		sysCtx := auth.ContextWithSystemIdentity(ctx)
		if _, err := network.AddPassthroughRoute(sysCtx, &pb.AddPassthroughRouteRequest{
			ExternalPort:  int32(port), //nolint:gosec // freeClusterPort draws from parsePortRange's validated [1024,65535]
			TargetIp:      cpIP,
			TargetPort:    6443,
			Protocol:      pb.RouteProtocol_ROUTE_PROTOCOL_TCP,
			ContainerName: clustercore.CPName(c.Owner, c.Name),
		}); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s:%d", advertiseAddr, port), nil
	}
	r.unpublish = func(ctx context.Context, c *clusterstore.Cluster) error {
		port := portFromEndpoint(c.APIEndpoint)
		if port == 0 {
			return nil // never published
		}
		sysCtx := auth.ContextWithSystemIdentity(ctx)
		_, err := network.DeletePassthroughRoute(sysCtx, &pb.DeletePassthroughRouteRequest{
			ExternalPort: int32(port), //nolint:gosec // portFromEndpoint rejects values outside [1,65535]
			Protocol:     pb.RouteProtocol_ROUTE_PROTOCOL_TCP,
		})
		if err != nil && status.Code(err) == codes.NotFound {
			return nil // already gone — teardown is idempotent
		}
		return err
	}
	return nil
}

func parsePortRange(s string) (int, int, error) {
	var lo, hi int
	if _, err := fmt.Sscanf(s, "%d-%d", &lo, &hi); err != nil {
		return 0, 0, fmt.Errorf("invalid port range %q (want e.g. 36443-36542): %w", s, err)
	}
	if lo < 1024 || hi > 65535 || hi < lo {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	return lo, hi, nil
}

// freeClusterPort picks the first port in [lo,hi] not already recorded
// on some cluster's endpoint.
func (r *ClusterReconciler) freeClusterPort(ctx context.Context, lo, hi int) (int, error) {
	clusters, err := r.store.List(ctx, "")
	if err != nil {
		return 0, err
	}
	used := make(map[int]bool, len(clusters))
	for _, c := range clusters {
		if p := portFromEndpoint(c.APIEndpoint); p != 0 {
			used[p] = true
		}
	}
	for p := lo; p <= hi; p++ {
		if !used[p] {
			return p, nil
		}
	}
	return 0, fmt.Errorf("cluster API port range %d-%d exhausted", lo, hi)
}

func portFromEndpoint(endpoint string) int {
	_, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return 0
	}
	return p
}
