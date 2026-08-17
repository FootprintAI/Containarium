package server

// Unit coverage for ClusterServer (#1413): scope gates, tenant isolation
// (IDOR), lifecycle semantics, and the kubeconfig seam — all against the
// in-memory store (the Postgres impl is held to the same contract in
// internal/cluster's integration suite).

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/cluster"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func clusterTestServer() *ClusterServer {
	return NewClusterServer(cluster.NewMemStore())
}

// scopedCtx is a tenant context restricted to exactly the given scopes
// (unlike tenantCtx, whose nil scopes claim means "unrestricted").
func scopedCtx(username string, scopes ...string) context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), username, []string{"user"}, scopes)
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("got error %v (code %v), want code %v", err, status.Code(err), want)
	}
}

func mustCreate(t *testing.T, s *ClusterServer, ctx context.Context, name string) *pb.Cluster {
	t.Helper()
	resp, err := s.CreateCluster(ctx, &pb.CreateClusterRequest{Name: name})
	if err != nil {
		t.Fatalf("CreateCluster(%s): %v", name, err)
	}
	return resp.Cluster
}

// --- scope gates -------------------------------------------------------

func TestClusterServer_ScopeGates(t *testing.T) {
	s := clusterTestServer()
	readOnly := scopedCtx("alice", auth.ScopeClustersRead)
	writeOnly := scopedCtx("alice", auth.ScopeClustersWrite)
	unrelated := scopedCtx("alice", auth.ScopeContainersWrite)

	// Writes need clusters:write.
	if _, err := s.CreateCluster(readOnly, &pb.CreateClusterRequest{Name: "demo"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Create with read-only scope = %v, want PermissionDenied", err)
	}
	if _, err := s.CreateCluster(unrelated, &pb.CreateClusterRequest{Name: "demo"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Create with unrelated scope = %v, want PermissionDenied", err)
	}
	if _, err := s.CreateCluster(writeOnly, &pb.CreateClusterRequest{Name: "demo"}); err != nil {
		t.Fatalf("Create with write scope: %v", err)
	}

	// Reads need clusters:read (write does not imply read).
	if _, err := s.GetCluster(writeOnly, &pb.GetClusterRequest{Name: "demo"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Get with write-only scope = %v, want PermissionDenied", err)
	}
	if _, err := s.GetCluster(readOnly, &pb.GetClusterRequest{Name: "demo"}); err != nil {
		t.Fatalf("Get with read scope: %v", err)
	}
	if _, err := s.ListClusters(unrelated, &pb.ListClustersRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("List with unrelated scope = %v, want PermissionDenied", err)
	}
	if _, err := s.GetClusterStatus(readOnly, &pb.GetClusterStatusRequest{Name: "demo"}); err != nil {
		t.Fatalf("Status with read scope: %v", err)
	}

	// Kubeconfig is cluster-admin material: gated on clusters:write,
	// so a read-only (inspection) token cannot take control of the
	// cluster's workloads.
	if _, err := s.GetClusterKubeconfig(readOnly, &pb.GetClusterKubeconfigRequest{Name: "demo"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Kubeconfig with read-only scope = %v, want PermissionDenied", err)
	}

	if _, err := s.UpdateClusterNodePool(readOnly, &pb.UpdateClusterNodePoolRequest{Name: "demo"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("UpdateNodePool with read-only scope = %v, want PermissionDenied", err)
	}
	if _, err := s.DeleteCluster(readOnly, &pb.DeleteClusterRequest{Name: "demo"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Delete with read-only scope = %v, want PermissionDenied", err)
	}
}

// --- tenant isolation (IDOR) ------------------------------------------

func TestClusterServer_TenantIsolation(t *testing.T) {
	s := clusterTestServer()
	mustCreate(t, s, tenantCtx("bob"), "demo")

	alice := tenantCtx("alice")
	// Every RPC that names an owner must refuse a cross-tenant request
	// from a non-admin.
	cases := []struct {
		name string
		call func() error
	}{
		{"Get", func() error {
			_, err := s.GetCluster(alice, &pb.GetClusterRequest{Name: "demo", Owner: "bob"})
			return err
		}},
		{"Status", func() error {
			_, err := s.GetClusterStatus(alice, &pb.GetClusterStatusRequest{Name: "demo", Owner: "bob"})
			return err
		}},
		{"Kubeconfig", func() error {
			_, err := s.GetClusterKubeconfig(alice, &pb.GetClusterKubeconfigRequest{Name: "demo", Owner: "bob"})
			return err
		}},
		{"Delete", func() error {
			_, err := s.DeleteCluster(alice, &pb.DeleteClusterRequest{Name: "demo", Owner: "bob"})
			return err
		}},
		{"UpdateNodePool", func() error {
			_, err := s.UpdateClusterNodePool(alice, &pb.UpdateClusterNodePoolRequest{Name: "demo", Owner: "bob", NodeGroups: []*pb.NodeGroup{}})
			return err
		}},
		{"List filtered", func() error { _, err := s.ListClusters(alice, &pb.ListClustersRequest{Owner: "bob"}); return err }},
		{"Create for other", func() error {
			_, err := s.CreateCluster(alice, &pb.CreateClusterRequest{Name: "other", Owner: "bob"})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantCode(t, tc.call(), codes.PermissionDenied)
		})
	}

	// Admin passes the same checks.
	if _, err := s.GetCluster(adminCtx(), &pb.GetClusterRequest{Name: "demo", Owner: "bob"}); err != nil {
		t.Fatalf("admin Get for bob: %v", err)
	}

	// List without a filter is self-scoped for non-admins: alice sees
	// nothing, bob sees his cluster, admin sees everything.
	resp, err := s.ListClusters(alice, &pb.ListClustersRequest{})
	if err != nil || len(resp.Clusters) != 0 {
		t.Fatalf("alice list = %d clusters (%v), want 0", len(resp.Clusters), err)
	}
	resp, err = s.ListClusters(tenantCtx("bob"), &pb.ListClustersRequest{})
	if err != nil || len(resp.Clusters) != 1 {
		t.Fatalf("bob list = %d clusters (%v), want 1", len(resp.Clusters), err)
	}
	resp, err = s.ListClusters(adminCtx(), &pb.ListClustersRequest{})
	if err != nil || len(resp.Clusters) != 1 {
		t.Fatalf("admin list = %d clusters (%v), want 1", len(resp.Clusters), err)
	}
}

// --- create semantics --------------------------------------------------

func TestClusterServer_CreateSemantics(t *testing.T) {
	s := clusterTestServer()
	ctx := tenantCtx("alice")

	c := mustCreate(t, s, ctx, "demo")
	if c.State != pb.ClusterState_CLUSTER_STATE_PROVISIONING {
		t.Fatalf("new cluster state = %v, want PROVISIONING", c.State)
	}
	if c.Owner != "alice" {
		t.Fatalf("owner defaulted to %q, want alice", c.Owner)
	}
	// Empty node_groups → platform presets, typed through the proto.
	if len(c.NodeGroups) != 3 || c.NodeGroups[0].Name != "small" || c.NodeGroups[0].Size.Memory != "4GB" {
		t.Fatalf("default node groups not applied: %+v", c.NodeGroups)
	}

	if _, err := s.CreateCluster(ctx, &pb.CreateClusterRequest{Name: "demo"}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate create = %v, want AlreadyExists", status.Code(err))
	}

	invalid := []struct {
		name string
		req  *pb.CreateClusterRequest
		frag string
	}{
		{"bad name", &pb.CreateClusterRequest{Name: "Bad_Name"}, "invalid name"},
		{"bad groups", &pb.CreateClusterRequest{Name: "ok", NodeGroups: []*pb.NodeGroup{
			{Name: "small", Size: &pb.ResourceLimits{Cpu: "0", Memory: "4GB", Disk: "40GB"}, MaxNodes: 1},
		}}, "cpu"},
		{"gpu rejected", &pb.CreateClusterRequest{Name: "ok", NodeGroups: []*pb.NodeGroup{
			{Name: "small", Size: &pb.ResourceLimits{Cpu: "2", Memory: "4GB", Disk: "40GB", Gpus: []string{"0"}}, MaxNodes: 1},
		}}, "GPU"},
		{"nil size", &pb.CreateClusterRequest{Name: "ok", NodeGroups: []*pb.NodeGroup{
			{Name: "small", MaxNodes: 1},
		}}, "size"},
		{"storage_class rejected", &pb.CreateClusterRequest{Name: "ok", NodeGroups: []*pb.NodeGroup{
			{Name: "small", Size: &pb.ResourceLimits{Cpu: "2", Memory: "4GB", Disk: "40GB", StorageClass: "fast-nvme"}, MaxNodes: 1},
		}}, "storage_class"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.CreateCluster(ctx, tc.req)
			wantCode(t, err, codes.InvalidArgument)
			if !strings.Contains(err.Error(), tc.frag) {
				t.Fatalf("error %q does not mention %q", err, tc.frag)
			}
		})
	}
}

// --- delete / lifecycle ------------------------------------------------

func TestClusterServer_DeleteRemovesState(t *testing.T) {
	s := clusterTestServer()
	ctx := tenantCtx("alice")
	mustCreate(t, s, ctx, "demo")

	if _, err := s.DeleteCluster(ctx, &pb.DeleteClusterRequest{Name: "demo"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := s.GetCluster(ctx, &pb.GetClusterRequest{Name: "demo"})
	wantCode(t, err, codes.NotFound)

	// Name immediately reusable, and the new cluster starts empty.
	c := mustCreate(t, s, ctx, "demo")
	if c.State != pb.ClusterState_CLUSTER_STATE_PROVISIONING {
		t.Fatalf("re-created cluster state = %v, want PROVISIONING", c.State)
	}

	_, err = s.DeleteCluster(ctx, &pb.DeleteClusterRequest{Name: "missing"})
	wantCode(t, err, codes.NotFound)
}

// --- kubeconfig seam ---------------------------------------------------

type fakeKubeconfigReader struct{ out string }

func (f fakeKubeconfigReader) ReadKubeconfig(ctx context.Context, c *cluster.Cluster) (string, error) {
	return f.out, nil
}

func TestClusterServer_Kubeconfig(t *testing.T) {
	s := clusterTestServer()
	ctx := tenantCtx("alice")
	mustCreate(t, s, ctx, "demo")

	// Not READY yet → FailedPrecondition regardless of wiring.
	_, err := s.GetClusterKubeconfig(ctx, &pb.GetClusterKubeconfigRequest{Name: "demo"})
	wantCode(t, err, codes.FailedPrecondition)

	if err := s.store.SetState(context.Background(), "alice", "demo", cluster.StateReady, ""); err != nil {
		t.Fatalf("SetState: %v", err)
	}

	// READY but the provisioner (#1414) is not wired → Unimplemented,
	// stated loudly rather than a nil-panic or an empty kubeconfig.
	_, err = s.GetClusterKubeconfig(ctx, &pb.GetClusterKubeconfigRequest{Name: "demo"})
	wantCode(t, err, codes.Unimplemented)

	s.SetKubeconfigReader(fakeKubeconfigReader{out: "apiVersion: v1\nkind: Config\n"})
	resp, err := s.GetClusterKubeconfig(ctx, &pb.GetClusterKubeconfigRequest{Name: "demo"})
	if err != nil {
		t.Fatalf("Kubeconfig when READY+wired: %v", err)
	}
	if !strings.Contains(resp.Kubeconfig, "kind: Config") {
		t.Fatalf("kubeconfig = %q, want YAML config", resp.Kubeconfig)
	}
}

// --- status + node pool update ----------------------------------------

func TestClusterServer_StatusAndNodePool(t *testing.T) {
	s := clusterTestServer()
	ctx := tenantCtx("alice")
	mustCreate(t, s, ctx, "demo")

	// Seed a node and two events through the store (the reconciler's
	// job in #1414).
	if err := s.store.UpsertNode(context.Background(), &cluster.Node{
		Owner: "alice", Cluster: "demo", VMName: "alice-k8s-demo-small-1",
		Role: cluster.RoleWorker, Group: "small", State: "ready",
	}); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	for _, reason := range []string{"older", "newer"} {
		if err := s.store.AppendEvent(context.Background(), "alice", "demo",
			cluster.Event{Kind: cluster.EventScaleUp, Group: "small", Reason: reason}); err != nil {
			t.Fatalf("AppendEvent: %v", err)
		}
	}

	st, err := s.GetClusterStatus(ctx, &pb.GetClusterStatusRequest{Name: "demo"})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.Nodes) != 1 || st.Nodes[0].Role != pb.ClusterNodeRole_CLUSTER_NODE_ROLE_WORKER {
		t.Fatalf("status nodes = %+v, want 1 worker", st.Nodes)
	}
	if len(st.Groups) != 3 {
		t.Fatalf("status groups = %d, want 3 presets", len(st.Groups))
	}
	var small *pb.NodeGroupStatus
	for _, g := range st.Groups {
		if g.Group.Name == "small" {
			small = g
		}
	}
	if small == nil || small.CurrentNodes != 1 {
		t.Fatalf("small group status = %+v, want current_nodes 1", small)
	}
	if len(st.Events) != 2 || st.Events[0].Reason != "newer" {
		t.Fatalf("events = %+v, want newest-first", st.Events)
	}

	// Node pool replacement is validated like create and reflected back.
	upd, err := s.UpdateClusterNodePool(ctx, &pb.UpdateClusterNodePoolRequest{
		Name: "demo",
		NodeGroups: []*pb.NodeGroup{
			{Name: "small", Size: &pb.ResourceLimits{Cpu: "2", Memory: "4GB", Disk: "40GB"}, MinNodes: 2, MaxNodes: 5},
		},
	})
	if err != nil {
		t.Fatalf("UpdateNodePool: %v", err)
	}
	if len(upd.Cluster.NodeGroups) != 1 || upd.Cluster.NodeGroups[0].MaxNodes != 5 {
		t.Fatalf("updated groups = %+v", upd.Cluster.NodeGroups)
	}

	_, err = s.UpdateClusterNodePool(ctx, &pb.UpdateClusterNodePoolRequest{Name: "demo"})
	wantCode(t, err, codes.InvalidArgument)
}

func TestClampEventsLimit(t *testing.T) {
	cases := []struct {
		in   int32
		want int
	}{
		{0, defaultEventsLimit},
		{-5, defaultEventsLimit},
		{1, 1},
		{1000, 1000},
		{1001, maxEventsLimit},
		{2147483647, maxEventsLimit},
	}
	for _, tc := range cases {
		if got := clampEventsLimit(tc.in); got != tc.want {
			t.Fatalf("clampEventsLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
