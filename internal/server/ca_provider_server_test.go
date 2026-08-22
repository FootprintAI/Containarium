package server

// Contract tests for the externalgrpc CloudProvider implementation
// (#1415): a REAL gRPC server dialed by the client generated from the
// SAME vendored proto — proto drift fails here, not in production.
// The scaling loop is closed against the reconciler rig: a target
// raised over the wire materializes as VMs on the fake host.

import (
	"context"
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

	// Unknown node refused, nothing deleted.
	_, err := client.NodeGroupDeleteNodes(caCtx("alice", "demo"), &capb.NodeGroupDeleteNodesRequest{
		Id: "alice/demo/small", Nodes: []*capb.ExternalGrpcNode{{Name: "alice-k8s-demo-small-9"}},
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown node delete = %v, want NotFound", err)
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
	_, err = client.NodeGroupDecreaseTargetSize(caCtx("alice", "demo"), &capb.NodeGroupDecreaseTargetSizeRequest{Id: "alice/demo/small", Delta: -1})
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
