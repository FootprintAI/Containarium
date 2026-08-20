package server

// Node isolation contract (#1428): a cluster's isolation class is the
// boundary that contains a tenant kernel exploit. The weaker class
// (CONTAINER) is operator-gated and must be unreachable by omission or
// by a typo — both directions fail closed.
//
// Design: docs/architecture/cluster-container-node-pools.md.

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/footprintai/containarium/internal/cluster"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// A cluster created without asking for an isolation class must come
// back — and be stored — as VM. The safe default is not reachable by
// omission of config; it IS the omission of config.
func TestClusterIsolation_UnspecifiedResolvesToVM(t *testing.T) {
	s := clusterTestServer()
	ctx := tenantCtx("alice")

	resp, err := s.CreateCluster(ctx, &pb.CreateClusterRequest{Name: "demo"})
	if err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}
	if got := resp.Cluster.NodeIsolation; got != pb.NodeIsolation_NODE_ISOLATION_VM {
		t.Fatalf("create response isolation = %v, want VM", got)
	}

	// The store holds the resolved class, not the unset one.
	rec, err := s.store.Get(ctx, "alice", "demo")
	if err != nil {
		t.Fatalf("store Get: %v", err)
	}
	if rec.NodeIsolation != cluster.IsolationVM {
		t.Fatalf("stored isolation = %q, want %q", rec.NodeIsolation, cluster.IsolationVM)
	}

	// And every read surface says so.
	got, err := s.GetCluster(ctx, &pb.GetClusterRequest{Name: "demo"})
	if err != nil {
		t.Fatalf("GetCluster: %v", err)
	}
	if got.Cluster.NodeIsolation != pb.NodeIsolation_NODE_ISOLATION_VM {
		t.Fatalf("GetCluster isolation = %v, want VM", got.Cluster.NodeIsolation)
	}
	st, err := s.GetClusterStatus(ctx, &pb.GetClusterStatusRequest{Name: "demo"})
	if err != nil {
		t.Fatalf("GetClusterStatus: %v", err)
	}
	if st.Cluster.NodeIsolation != pb.NodeIsolation_NODE_ISOLATION_VM {
		t.Fatalf("GetClusterStatus isolation = %v, want VM", st.Cluster.NodeIsolation)
	}
	list, err := s.ListClusters(ctx, &pb.ListClustersRequest{})
	if err != nil || len(list.Clusters) != 1 {
		t.Fatalf("ListClusters = %+v (%v)", list, err)
	}
	if list.Clusters[0].NodeIsolation != pb.NodeIsolation_NODE_ISOLATION_VM {
		t.Fatalf("ListClusters isolation = %v, want VM", list.Clusters[0].NodeIsolation)
	}
}

// The operator opt-in is parsed by the same fail-closed rule as the
// caps envs (cluster_caps.go): unset means "not permitted", a typo
// means "not permitted AND say so", never "permitted".
func TestParseIsolationGate(t *testing.T) {
	cases := []struct {
		name         string
		env          string
		wantAllow    bool
		wantParseErr bool
	}{
		{"unset is closed", "", false, false},
		{"explicit true opens", "true", true, false},
		{"explicit false is closed", "false", false, false},
		{"garbage is a config error, not an open gate", "yes-please", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := parseIsolationGate(tc.env)
			if (err != nil) != tc.wantParseErr {
				t.Fatalf("parseIsolationGate(%q) err = %v, wantErr %v", tc.env, err, tc.wantParseErr)
			}
			if err != nil && !strings.Contains(err.Error(), allowContainerNodesEnv) {
				t.Fatalf("parse error %q does not name %s", err, allowContainerNodesEnv)
			}
			if g.allowContainer != tc.wantAllow {
				t.Fatalf("allowContainer = %v, want %v", g.allowContainer, tc.wantAllow)
			}
		})
	}
}

// The create-path gate: a CONTAINER request is admitted only where the
// operator set the flag. Refusals are FailedPrecondition and name the
// flag, so an operator reading the error knows exactly what to set.
func TestClusterIsolation_CreateGate(t *testing.T) {
	cases := []struct {
		name       string
		env        string
		requested  pb.NodeIsolation
		wantAllow  bool
		wantStored cluster.Isolation
	}{
		{"container refused when the flag is unset", "", pb.NodeIsolation_NODE_ISOLATION_CONTAINER, false, ""},
		{"container allowed when the flag is true", "true", pb.NodeIsolation_NODE_ISOLATION_CONTAINER, true, cluster.IsolationContainer},
		{"container refused when the flag is garbage", "not-a-bool", pb.NodeIsolation_NODE_ISOLATION_CONTAINER, false, ""},
		{"container refused when the flag says false", "false", pb.NodeIsolation_NODE_ISOLATION_CONTAINER, false, ""},
		{"vm is never gated: flag unset", "", pb.NodeIsolation_NODE_ISOLATION_VM, true, cluster.IsolationVM},
		{"vm is never gated: flag garbage", "not-a-bool", pb.NodeIsolation_NODE_ISOLATION_VM, true, cluster.IsolationVM},
		{"unspecified is never gated: flag garbage", "not-a-bool", pb.NodeIsolation_NODE_ISOLATION_UNSPECIFIED, true, cluster.IsolationVM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := clusterTestServer()
			s.SetIsolationGateFromEnv(tc.env)
			ctx := tenantCtx("alice")

			resp, err := s.CreateCluster(ctx, &pb.CreateClusterRequest{
				Name: "demo", NodeIsolation: tc.requested,
			})
			if !tc.wantAllow {
				wantCode(t, err, codes.FailedPrecondition)
				if !strings.Contains(err.Error(), allowContainerNodesEnv) {
					t.Fatalf("refusal %q does not name %s", err, allowContainerNodesEnv)
				}
				// Fail closed means nothing was recorded either.
				if _, gerr := s.store.Get(ctx, "alice", "demo"); gerr == nil {
					t.Fatal("refused create still wrote a cluster row")
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateCluster: %v", err)
			}
			rec, gerr := s.store.Get(ctx, "alice", "demo")
			if gerr != nil {
				t.Fatalf("store Get: %v", gerr)
			}
			if rec.NodeIsolation != tc.wantStored {
				t.Fatalf("stored isolation = %q, want %q", rec.NodeIsolation, tc.wantStored)
			}
			if resp.Cluster.NodeIsolation != isolationToProto[tc.wantStored] {
				t.Fatalf("response isolation = %v, want %v", resp.Cluster.NodeIsolation, isolationToProto[tc.wantStored])
			}
		})
	}
}

// An isolation value the server does not know (a newer client, or a
// hand-rolled request) is refused rather than silently defaulted to
// the safe class — a caller who asked for something specific must
// never be told "fine" and given something else.
func TestClusterIsolation_UnknownValueRefused(t *testing.T) {
	s := clusterTestServer()
	_, err := s.CreateCluster(tenantCtx("alice"), &pb.CreateClusterRequest{
		Name: "demo", NodeIsolation: pb.NodeIsolation(99),
	})
	wantCode(t, err, codes.InvalidArgument)
}
