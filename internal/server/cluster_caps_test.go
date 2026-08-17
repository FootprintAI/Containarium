package server

// Server-side caps (#1417): the operator's hard ceiling on what any
// tenant may configure a cluster to consume. Refusals are typed errors
// (and REFUSED events on updates) — never silent clamps.

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func group(name, cpu, mem, disk string, min, max int32) *pb.NodeGroup {
	return &pb.NodeGroup{
		Name: name, Size: &pb.ResourceLimits{Cpu: cpu, Memory: mem, Disk: disk},
		MinNodes: min, MaxNodes: max,
	}
}

func TestClusterCaps_ParseEnv(t *testing.T) {
	caps, err := parseClusterCaps("10", "cpu=8,memory=16GB,disk=200GB")
	if err != nil {
		t.Fatalf("parseClusterCaps: %v", err)
	}
	if caps.maxNodes != 10 || caps.maxCPU != 8 || caps.maxMemoryBytes != 16_000_000_000 || caps.maxDiskBytes != 200_000_000_000 {
		t.Fatalf("caps = %+v", caps)
	}
	// Unset means unlimited, not zero.
	caps, err = parseClusterCaps("", "")
	if err != nil || caps.maxNodes != 0 || caps.maxCPU != 0 {
		t.Fatalf("empty caps = %+v (%v), want unlimited", caps, err)
	}
	// Garbage is a startup error, not a silently-open gate.
	if _, err := parseClusterCaps("ten", ""); err == nil {
		t.Fatal("bad max-nodes accepted")
	}
	if _, err := parseClusterCaps("", "cpu=lots"); err == nil {
		t.Fatal("bad node-size accepted")
	}
	if _, err := parseClusterCaps("", "flavor=big"); err == nil {
		t.Fatal("unknown size key accepted")
	}
}

func TestClusterCaps_EnforcedOnCreate(t *testing.T) {
	s := clusterTestServer()
	s.SetCaps(clusterCaps{maxNodes: 4, maxCPU: 4, maxMemoryBytes: 8_000_000_000, maxDiskBytes: 100_000_000_000})
	ctx := tenantCtx("alice")

	cases := []struct {
		name   string
		groups []*pb.NodeGroup
		frag   string
	}{
		{"total max_nodes over cap", []*pb.NodeGroup{
			group("small", "2", "4GB", "40GB", 1, 3),
			group("medium", "4", "8GB", "80GB", 0, 2),
		}, "max_nodes"},
		{"cpu over cap", []*pb.NodeGroup{group("big", "8", "8GB", "80GB", 0, 1)}, "cpu"},
		{"memory over cap", []*pb.NodeGroup{group("big", "4", "16GB", "80GB", 0, 1)}, "memory"},
		{"disk over cap", []*pb.NodeGroup{group("big", "4", "8GB", "200GB", 0, 1)}, "disk"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.CreateCluster(ctx, &pb.CreateClusterRequest{Name: "demo", NodeGroups: tc.groups})
			wantCode(t, err, codes.InvalidArgument)
			if !strings.Contains(err.Error(), tc.frag) {
				t.Fatalf("error %q does not name the exceeded cap %q", err, tc.frag)
			}
		})
	}

	// Within caps still works.
	if _, err := s.CreateCluster(ctx, &pb.CreateClusterRequest{Name: "demo", NodeGroups: []*pb.NodeGroup{
		group("small", "2", "4GB", "40GB", 1, 4),
	}}); err != nil {
		t.Fatalf("within-caps create refused: %v", err)
	}

	// The platform presets must also fit whatever caps the operator
	// sets — otherwise a flagless create breaks confusingly.
	s2 := clusterTestServer()
	s2.SetCaps(clusterCaps{maxNodes: 2})
	_, err := s2.CreateCluster(ctx, &pb.CreateClusterRequest{Name: "demo"})
	wantCode(t, err, codes.InvalidArgument)
}

func TestClusterCaps_UpdateRefusalIsRecorded(t *testing.T) {
	s := clusterTestServer()
	s.SetCaps(clusterCaps{maxNodes: 4})
	ctx := tenantCtx("alice")
	if _, err := s.CreateCluster(ctx, &pb.CreateClusterRequest{Name: "demo", NodeGroups: []*pb.NodeGroup{
		group("small", "2", "4GB", "40GB", 1, 3),
	}}); err != nil {
		t.Fatal(err)
	}

	_, err := s.UpdateClusterNodePool(ctx, &pb.UpdateClusterNodePoolRequest{Name: "demo", NodeGroups: []*pb.NodeGroup{
		group("small", "2", "4GB", "40GB", 1, 5),
	}})
	wantCode(t, err, codes.InvalidArgument)

	// The refusal is on the record — visible in `cluster status`, not
	// silently clamped (the PRD's Story 5 requirement).
	st, err := s.GetClusterStatus(ctx, &pb.GetClusterStatusRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Events) == 0 || st.Events[0].Kind != pb.ScaleEventKind_SCALE_EVENT_KIND_REFUSED {
		t.Fatalf("cap refusal not recorded as REFUSED event: %+v", st.Events)
	}
	if !strings.Contains(st.Events[0].Reason, "max_nodes") {
		t.Fatalf("refusal reason does not name the cap: %q", st.Events[0].Reason)
	}

	// The pool is unchanged after the refusal.
	got, _ := s.GetCluster(ctx, &pb.GetClusterRequest{Name: "demo"})
	if got.Cluster.NodeGroups[0].MaxNodes != 3 {
		t.Fatalf("pool changed despite refusal: %+v", got.Cluster.NodeGroups)
	}
}
