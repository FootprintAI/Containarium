package server

// Contract tests for the externalgrpc CloudProvider implementation
// (#1415): a REAL gRPC server dialed by the client generated from the
// SAME vendored proto — proto drift fails here, not in production.
// The scaling loop is closed against the reconciler rig: a target
// raised over the wire materializes as VMs on the fake host.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	clustercore "github.com/footprintai/containarium/pkg/core/cluster"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	capb "github.com/footprintai/containarium/pkg/pb/thirdparty/externalgrpc"
)

// caRig serves a CAProviderServer over a real listener, sharing the
// store/manager/reconciler with the cluster rig.
func caRig(t *testing.T) (capb.CloudProviderClient, *ClusterServer, *ClusterReconciler, *stateHost) {
	t.Helper()
	srv, rec, host := testReconcilerRig(t)
	mgr := clustercore.NewManagerWithLoader(host, func() ([]byte, error) { return []byte("k3s-bin"), nil })
	provider := NewCAProviderServer(srv.Store(), mgr)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	capb.RegisterCloudProviderServer(gs, provider)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return capb.NewCloudProviderClient(conn), srv, rec, host
}

// caCtx carries a cluster machine identity the way the production
// transport stamps it (subject k8s-cluster:<owner>/<name>, scope
// clusters:scale).
func caCtx(owner, name string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(),
		auth.MDKeyUsername, CASubject(owner, name),
		auth.MDKeyRoles, "machine",
		auth.MDKeyScopes, auth.ScopeClustersScale,
	)
}

func TestCAProvider_NodeGroupsAndIdentity(t *testing.T) {
	client, srv, _, _ := caRig(t)
	mustCreate(t, srv, tenantCtx("alice"), "demo")

	// The cluster's own identity sees its groups with truthful bounds.
	resp, err := client.NodeGroups(caCtx("alice", "demo"), &capb.NodeGroupsRequest{})
	if err != nil {
		t.Fatalf("NodeGroups: %v", err)
	}
	if len(resp.NodeGroups) != 3 {
		t.Fatalf("groups = %d, want 3 presets", len(resp.NodeGroups))
	}
	byID := map[string]*capb.NodeGroup{}
	for _, g := range resp.NodeGroups {
		byID[g.Id] = g
	}
	small := byID["alice/demo/small"]
	if small == nil || small.MinSize != 1 || small.MaxSize != 3 {
		t.Fatalf("small group = %+v, want min 1 max 3", small)
	}

	// A DIFFERENT cluster's identity cannot touch demo's groups.
	_, err = client.NodeGroupTargetSize(caCtx("alice", "other"), &capb.NodeGroupTargetSizeRequest{Id: "alice/demo/small"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-cluster call = %v, want PermissionDenied", err)
	}

	// A human token (no machine subject) is refused even with wildcard scope.
	human := metadata.AppendToOutgoingContext(context.Background(),
		auth.MDKeyUsername, "alice", auth.MDKeyRoles, auth.RoleAdmin, auth.MDKeyScopes, auth.ScopeWildcard)
	_, err = client.NodeGroups(human, &capb.NodeGroupsRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("human token = %v, want PermissionDenied", err)
	}

	// Missing scope is refused before anything else.
	noScope := metadata.AppendToOutgoingContext(context.Background(),
		auth.MDKeyUsername, CASubject("alice", "demo"), auth.MDKeyRoles, "machine", auth.MDKeyScopes, auth.ScopeClustersRead)
	_, err = client.NodeGroups(noScope, &capb.NodeGroupsRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("wrong scope = %v, want PermissionDenied", err)
	}
}

func TestCAProvider_ScaleUpMaterializesThroughReconciler(t *testing.T) {
	client, srv, rec, host := caRig(t)
	ctx := context.Background()
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	rec.ReconcileOnce(ctx) // CP
	rec.ReconcileOnce(ctx) // worker to min (1)

	ts, err := client.NodeGroupTargetSize(caCtx("alice", "demo"), &capb.NodeGroupTargetSizeRequest{Id: "alice/demo/small"})
	if err != nil || ts.TargetSize != 1 {
		t.Fatalf("initial target = %v (%v), want 1 (min)", ts.GetTargetSize(), err)
	}

	// CA raises the target by 2 (pending pods) — bounded at max 3.
	if _, err := client.NodeGroupIncreaseSize(caCtx("alice", "demo"), &capb.NodeGroupIncreaseSizeRequest{Id: "alice/demo/small", Delta: 2}); err != nil {
		t.Fatalf("IncreaseSize: %v", err)
	}
	rec.ReconcileOnce(ctx)
	workers := 0
	for name := range host.vms {
		if strings.Contains(name, "-small-") {
			workers++
		}
	}
	if workers != 3 {
		t.Fatalf("workers after target=3 pass = %d, want 3: %v", workers, vmNames(host))
	}

	// Past max is a loud, typed refusal + a REFUSED event.
	_, err = client.NodeGroupIncreaseSize(caCtx("alice", "demo"), &capb.NodeGroupIncreaseSizeRequest{Id: "alice/demo/small", Delta: 1})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("over-max IncreaseSize = %v, want ResourceExhausted", err)
	}
	st, err := srv.GetClusterStatus(tenantCtx("alice"), &pb.GetClusterStatusRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	foundRefused := false
	for _, e := range st.Events {
		if e.Kind == pb.ScaleEventKind_SCALE_EVENT_KIND_REFUSED {
			foundRefused = true
		}
	}
	if !foundRefused {
		t.Fatalf("no REFUSED event recorded: %+v", st.Events)
	}

	// Non-positive delta is invalid.
	_, err = client.NodeGroupIncreaseSize(caCtx("alice", "demo"), &capb.NodeGroupIncreaseSizeRequest{Id: "alice/demo/small", Delta: 0})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("zero delta = %v, want InvalidArgument", err)
	}
}

func TestCAProvider_DeleteNodesAndDecrease(t *testing.T) {
	client, srv, rec, host := caRig(t)
	ctx := context.Background()
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)
	if _, err := client.NodeGroupIncreaseSize(caCtx("alice", "demo"), &capb.NodeGroupIncreaseSizeRequest{Id: "alice/demo/small", Delta: 1}); err != nil {
		t.Fatal(err)
	}
	rec.ReconcileOnce(ctx) // 2 workers now

	// A node that exists NOWHERE — not in the store, not on the host —
	// is already gone, and asking for it to go is satisfied. This
	// assertion previously expected NotFound; #1505 changed it,
	// because the all-or-nothing rejection wedged every retry of a
	// partially-completed batch. The refusal it was protecting —
	// naming a node that is absent from this group but STILL RUNNING
	// — is unchanged and covered by
	// TestCAProvider_DeleteNodesStillRefusesANodeThatExistsOutsideTheGroup.
	before := len(host.vms)
	if _, err := client.NodeGroupDeleteNodes(caCtx("alice", "demo"), &capb.NodeGroupDeleteNodesRequest{
		Id: "alice/demo/small", Nodes: []*capb.ExternalGrpcNode{{Name: "alice-k8s-demo-small-9"}},
	}); err != nil {
		t.Fatalf("deleting a node that exists nowhere = %v, want success (already gone)", err)
	}
	if len(host.vms) != before {
		t.Fatalf("a no-op delete removed something: %v", vmNames(host))
	}
	if ts, tsErr := client.NodeGroupTargetSize(caCtx("alice", "demo"),
		&capb.NodeGroupTargetSizeRequest{Id: "alice/demo/small"}); tsErr != nil {
		t.Fatal(tsErr)
	} else if ts.GetTargetSize() != 2 {
		t.Fatalf("a no-op delete moved the target to %d, want 2", ts.GetTargetSize())
	}

	// CA drains and removes one node: VM gone, row gone, target back to 1.
	if _, err := client.NodeGroupDeleteNodes(caCtx("alice", "demo"), &capb.NodeGroupDeleteNodesRequest{
		Id: "alice/demo/small", Nodes: []*capb.ExternalGrpcNode{{Name: "alice-k8s-demo-small-2"}},
	}); err != nil {
		t.Fatalf("DeleteNodes: %v", err)
	}
	if _, ok := host.vms["alice-k8s-demo-small-2"]; ok {
		t.Fatal("VM survived DeleteNodes")
	}
	ts, _ := client.NodeGroupTargetSize(caCtx("alice", "demo"), &capb.NodeGroupTargetSizeRequest{Id: "alice/demo/small"})
	if ts.GetTargetSize() != 1 {
		t.Fatalf("target after delete = %d, want 1", ts.GetTargetSize())
	}
	// The reconciler does NOT resurrect it (target followed the delete).
	rec.ReconcileOnce(ctx)
	if _, ok := host.vms["alice-k8s-demo-small-2"]; ok {
		t.Fatal("reconciler resurrected a CA-deleted node")
	}

	// DecreaseTargetSize may not go below the existing node count.
	_, err := client.NodeGroupDecreaseTargetSize(caCtx("alice", "demo"), &capb.NodeGroupDecreaseTargetSizeRequest{Id: "alice/demo/small", Delta: -1})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("decrease below existing = %v, want InvalidArgument", err)
	}
}

func TestCAProvider_TemplateAndNodeMapping(t *testing.T) {
	client, srv, rec, _ := caRig(t)
	ctx := context.Background()
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)

	// The template must equal the typed size — the truthfulness the
	// fit simulation (and scale-from-zero for medium/large) depends on.
	tmpl, err := client.NodeGroupTemplateNodeInfo(caCtx("alice", "demo"), &capb.NodeGroupTemplateNodeInfoRequest{Id: "alice/demo/medium"})
	if err != nil {
		t.Fatalf("TemplateNodeInfo: %v", err)
	}
	cap := tmpl.NodeInfo.Status.Capacity
	if cap["cpu"].GetString_() != "4" {
		t.Fatalf("template cpu = %q, want 4", cap["cpu"].GetString_())
	}
	if cap["memory"].GetString_() != "8G" {
		t.Fatalf("template memory = %q, want 8G (k8s quantity for the 8GB class)", cap["memory"].GetString_())
	}

	// Worker maps to its group; the control plane maps to nothing.
	fn, err := client.NodeGroupForNode(caCtx("alice", "demo"), &capb.NodeGroupForNodeRequest{
		Node: &capb.ExternalGrpcNode{Name: "alice-k8s-demo-small-1"},
	})
	if err != nil || fn.NodeGroup.Id != "alice/demo/small" {
		t.Fatalf("worker mapping = %q (%v), want alice/demo/small", fn.GetNodeGroup().GetId(), err)
	}
	fn, err = client.NodeGroupForNode(caCtx("alice", "demo"), &capb.NodeGroupForNodeRequest{
		Node: &capb.ExternalGrpcNode{Name: "alice-k8s-demo-cp"},
	})
	if err != nil || fn.NodeGroup.Id != "" {
		t.Fatalf("control-plane mapping = %q (%v), want empty (CA skips)", fn.GetNodeGroup().GetId(), err)
	}

	// Instances carry provider IDs and states.
	nodes, err := client.NodeGroupNodes(caCtx("alice", "demo"), &capb.NodeGroupNodesRequest{Id: "alice/demo/small"})
	if err != nil || len(nodes.Instances) != 1 {
		t.Fatalf("NodeGroupNodes = %+v (%v), want 1 instance", nodes.GetInstances(), err)
	}
	if nodes.Instances[0].Id != "containarium://alice-k8s-demo-small-1" {
		t.Fatalf("provider id = %q", nodes.Instances[0].Id)
	}
}

// #1498: scale-down must survive a reconciler pass landing INSIDE the
// DeleteNodes batch.
//
// TestCAProvider_DeleteNodesAndDecrease already runs a reconciler pass
// after DeleteNodes returns and asserts the node is not resurrected —
// and it passed throughout, because by then the target has been
// lowered. Production interleaved differently: the loop ticks every
// 15s and DeleteVM (stop, then delete) takes seconds, so a pass landed
// between the instance being destroyed and the target being lowered.
// It saw target=1 with zero workers, and created the node the
// autoscaler had just drained. The replacement then reused the node
// name, which k3s refuses forever (see the manager-side test), so the
// cluster carried an instance it did not know about until the run
// timed out.
//
// The hook is the point of the test: the pass has to happen mid-batch,
// and calling the two in sequence cannot express that.
func TestCAProvider_DeleteNodesIsNotUndoneByAConcurrentReconcilerPass(t *testing.T) {
	client, srv, rec, host := caRig(t)
	ctx := context.Background()
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)
	if _, err := client.NodeGroupIncreaseSize(caCtx("alice", "demo"),
		&capb.NodeGroupIncreaseSizeRequest{Id: "alice/demo/small", Delta: 1}); err != nil {
		t.Fatal(err)
	}
	rec.ReconcileOnce(ctx) // two small workers
	if _, ok := host.vms["alice-k8s-demo-small-2"]; !ok {
		t.Fatalf("setup did not produce a second worker: %v", vmNames(host))
	}

	// A reconciler tick lands while the instance is being destroyed.
	var passes int
	host.onDelete = func(string) {
		passes++
		rec.ReconcileOnce(ctx)
	}

	if _, err := client.NodeGroupDeleteNodes(caCtx("alice", "demo"), &capb.NodeGroupDeleteNodesRequest{
		Id: "alice/demo/small", Nodes: []*capb.ExternalGrpcNode{{Name: "alice-k8s-demo-small-2"}},
	}); err != nil {
		t.Fatalf("DeleteNodes: %v", err)
	}
	if passes == 0 {
		t.Fatal("the mid-batch reconciler pass never ran; the test proves nothing")
	}

	host.onDelete = nil
	rec.ReconcileOnce(ctx) // let anything queued settle

	if _, ok := host.vms["alice-k8s-demo-small-2"]; ok {
		t.Error("a reconciler pass inside the batch recreated the drained node (#1498)")
	}
	workers := 0
	for name := range host.vms {
		if strings.HasPrefix(name, "alice-k8s-demo-small-") {
			workers++
		}
	}
	if workers != 1 {
		t.Errorf("small group has %d instances, want 1: %v", workers, vmNames(host))
	}
}

// The mechanism behind the test above, asserted directly: no instance
// may be destroyed while the store still advertises a target that
// counts it. Any reconciler pass in that window is entitled to rebuild
// the node, so the ordering — not the width of the window — is the
// fix.
func TestCAProvider_TargetIsLoweredBeforeAnyInstanceIsDestroyed(t *testing.T) {
	client, srv, rec, host := caRig(t)
	ctx := context.Background()
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)
	if _, err := client.NodeGroupIncreaseSize(caCtx("alice", "demo"),
		&capb.NodeGroupIncreaseSizeRequest{Id: "alice/demo/small", Delta: 1}); err != nil {
		t.Fatal(err)
	}
	rec.ReconcileOnce(ctx)

	var targetAtDelete int32 = -1
	host.onDelete = func(string) {
		c, err := srv.Store().Get(ctx, "alice", "demo")
		if err != nil {
			t.Errorf("store.Get inside delete: %v", err)
			return
		}
		for _, g := range c.NodeGroups {
			if g.Name == "small" {
				targetAtDelete = g.EffectiveTarget()
			}
		}
	}

	if _, err := client.NodeGroupDeleteNodes(caCtx("alice", "demo"), &capb.NodeGroupDeleteNodesRequest{
		Id: "alice/demo/small", Nodes: []*capb.ExternalGrpcNode{{Name: "alice-k8s-demo-small-2"}},
	}); err != nil {
		t.Fatalf("DeleteNodes: %v", err)
	}
	if targetAtDelete != 1 {
		t.Errorf("target was %d while the instance was being destroyed, want 1 (already lowered)", targetAtDelete)
	}
}

// The target must be derived from how many nodes the group ACTUALLY
// has, not by subtracting the batch length from the current target.
//
// Lowering the target before deleting (#1498) means the decrement is
// committed even when a delete then fails — and because the node row
// survives a failed delete, the autoscaler's retry is validated as
// legitimate and subtracts again. Repeated retries walk the target
// down to MinNodes while every instance is still there, leaving a
// group whose target is far below its node count. Upstream CA treats
// target != node count as not-in-steady-state and stops scaling the
// group, and the reconciler never scales down, so the surplus is never
// reclaimed.
func TestCAProvider_TargetDoesNotDriftWhenDeletionKeepsFailing(t *testing.T) {
	client, srv, rec, host := caRig(t)
	ctx := context.Background()
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)
	if _, err := client.NodeGroupIncreaseSize(caCtx("alice", "demo"),
		&capb.NodeGroupIncreaseSizeRequest{Id: "alice/demo/small", Delta: 2}); err != nil {
		t.Fatal(err)
	}
	rec.ReconcileOnce(ctx) // three small workers, target 3

	// Every delete fails, so no node is ever removed and no row goes.
	host.deleteErr = errors.New("incus: instance is busy")

	for attempt := 1; attempt <= 3; attempt++ {
		_, err := client.NodeGroupDeleteNodes(caCtx("alice", "demo"), &capb.NodeGroupDeleteNodesRequest{
			Id: "alice/demo/small", Nodes: []*capb.ExternalGrpcNode{{Name: "alice-k8s-demo-small-3"}},
		})
		if err == nil {
			t.Fatalf("attempt %d: DeleteNodes succeeded though every delete fails", attempt)
		}
		ts, tsErr := client.NodeGroupTargetSize(caCtx("alice", "demo"),
			&capb.NodeGroupTargetSizeRequest{Id: "alice/demo/small"})
		if tsErr != nil {
			t.Fatal(tsErr)
		}
		// Three nodes still exist; one was asked to go. The target
		// reflects that intent and must not move further on retries.
		if ts.GetTargetSize() != 2 {
			t.Fatalf("after %d failed attempt(s) target = %d, want 2 (three nodes present, one requested gone)",
				attempt, ts.GetTargetSize())
		}
	}

	nodes, err := client.NodeGroupNodes(caCtx("alice", "demo"), &capb.NodeGroupNodesRequest{Id: "alice/demo/small"})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes.GetInstances()) != 3 {
		t.Fatalf("group reports %d nodes, want 3 — nothing was deleted", len(nodes.GetInstances()))
	}
}

// The resurrect race is only closed if the reconciler's DESIRED state
// is at least as fresh as its OBSERVATION.
//
// ReconcileOnce lists every cluster once and reconcileCluster then
// derived Desired from that snapshot BEFORE calling Observe. A
// scale-down landing in between produced the stale-high target with a
// post-deletion observation — the #1498 symptom again, now with the
// node-password cleared, so the resurrected node rejoins silently as a
// node nothing asked for. On a multi-cluster host that window is as
// wide as all the preceding clusters' work in the same pass, and
// provisioning blocks on a multi-minute WaitReady.
//
// The hook lands the delete after the host has been read, which is the
// window the mid-batch test cannot reach (it re-reads the store fresh).
func TestReconcilerDoesNotDecideOnAStaleTarget(t *testing.T) {
	client, srv, rec, host := caRig(t)
	ctx := context.Background()
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)
	if _, err := client.NodeGroupIncreaseSize(caCtx("alice", "demo"),
		&capb.NodeGroupIncreaseSizeRequest{Id: "alice/demo/small", Delta: 1}); err != nil {
		t.Fatal(err)
	}
	rec.ReconcileOnce(ctx) // two small workers

	var fired bool
	host.onObserve = func() {
		if fired {
			return
		}
		fired = true
		host.onObserve = nil
		if _, err := client.NodeGroupDeleteNodes(caCtx("alice", "demo"), &capb.NodeGroupDeleteNodesRequest{
			Id: "alice/demo/small", Nodes: []*capb.ExternalGrpcNode{{Name: "alice-k8s-demo-small-2"}},
		}); err != nil {
			t.Errorf("DeleteNodes inside observe: %v", err)
		}
	}

	rec.ReconcileOnce(ctx)
	if !fired {
		t.Fatal("the delete never landed inside the observation; the test proves nothing")
	}
	host.onObserve = nil
	rec.ReconcileOnce(ctx)

	if _, ok := host.vms["alice-k8s-demo-small-2"]; ok {
		t.Error("a scale-down landing between Observe and Decide was undone by a stale target")
	}
}

// #1505: a delete batch must be able to make progress on a retry.
//
// The batch was validated all-or-nothing — any named node missing from
// the store rejected the whole request — while the delete loop aborts
// on the first error after having already removed earlier nodes and
// their rows. So for [A, B] where A succeeds and B fails, every retry
// that still names A was refused outright, and B could never be
// removed. A retry naming A is the likely case: nothing here deletes
// A's Kubernetes Node object, and upstream cluster-autoscaler derives
// its retry set from Node objects.
//
// A node that is absent from the store AND absent from the host is
// simply already gone — skipping it is the honest answer, because the
// end state the caller asked for already holds.
func TestCAProvider_DeleteNodesMakesProgressWhenPartOfTheBatchIsAlreadyGone(t *testing.T) {
	client, srv, rec, host := caRig(t)
	ctx := context.Background()
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)
	if _, err := client.NodeGroupIncreaseSize(caCtx("alice", "demo"),
		&capb.NodeGroupIncreaseSizeRequest{Id: "alice/demo/small", Delta: 2}); err != nil {
		t.Fatal(err)
	}
	rec.ReconcileOnce(ctx) // three small workers

	// First attempt removes small-2 and then fails on small-3.
	host.deleteErrFor = map[string]error{"alice-k8s-demo-small-3": errors.New("incus: instance is busy")}
	_, err := client.NodeGroupDeleteNodes(caCtx("alice", "demo"), &capb.NodeGroupDeleteNodesRequest{
		Id: "alice/demo/small", Nodes: []*capb.ExternalGrpcNode{
			{Name: "alice-k8s-demo-small-2"}, {Name: "alice-k8s-demo-small-3"},
		},
	})
	if err == nil {
		t.Fatal("first attempt should have failed on small-3")
	}
	if _, ok := host.vms["alice-k8s-demo-small-2"]; ok {
		t.Fatal("small-2 should already be gone after the first attempt")
	}

	// The retry still names small-2, exactly as cluster-autoscaler
	// would: its Kubernetes Node object was never deleted by us.
	host.deleteErrFor = nil
	if _, err := client.NodeGroupDeleteNodes(caCtx("alice", "demo"), &capb.NodeGroupDeleteNodesRequest{
		Id: "alice/demo/small", Nodes: []*capb.ExternalGrpcNode{
			{Name: "alice-k8s-demo-small-2"}, {Name: "alice-k8s-demo-small-3"},
		},
	}); err != nil {
		t.Fatalf("retry naming an already-removed node was refused, so small-3 can never go: %v", err)
	}
	if _, ok := host.vms["alice-k8s-demo-small-3"]; ok {
		t.Error("small-3 survived the retry")
	}
}

// Idempotence must not become blindness. A node that is absent from
// this group's rows but STILL PRESENT on the host is not "already
// gone" — it is a caller naming the wrong group, or store drift — and
// silently reporting success would leave a running instance nobody
// accounts for. That is what the original all-or-nothing check was
// actually worth, and it is kept.
func TestCAProvider_DeleteNodesStillRefusesANodeThatExistsOutsideTheGroup(t *testing.T) {
	client, srv, rec, host := caRig(t)
	ctx := context.Background()
	mustCreate(t, srv, tenantCtx("alice"), "demo")
	rec.ReconcileOnce(ctx)
	rec.ReconcileOnce(ctx)
	if _, err := client.NodeGroupIncreaseSize(caCtx("alice", "demo"),
		&capb.NodeGroupIncreaseSizeRequest{Id: "alice/demo/medium", Delta: 1}); err != nil {
		t.Fatal(err)
	}
	rec.ReconcileOnce(ctx)
	if _, ok := host.vms["alice-k8s-demo-medium-1"]; !ok {
		t.Fatalf("setup did not produce a medium worker: %v", vmNames(host))
	}

	// A medium node named in the small group's batch.
	_, err := client.NodeGroupDeleteNodes(caCtx("alice", "demo"), &capb.NodeGroupDeleteNodesRequest{
		Id: "alice/demo/small", Nodes: []*capb.ExternalGrpcNode{{Name: "alice-k8s-demo-medium-1"}},
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("naming a node from another group = %v, want NotFound", err)
	}
	if _, ok := host.vms["alice-k8s-demo-medium-1"]; !ok {
		t.Error("the refused node was deleted anyway")
	}
}
