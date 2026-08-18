package cmd

// CLI half of the node isolation contract (#1428): --isolation is an
// enum-backed flag (a typo is rejected at parse time, never sent to the
// daemon as a silent default), and every cluster read surface prints
// the class an operator would be audited on.

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestIsolationFlag_ParsesEnumValuesOnly(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    pb.NodeIsolation
		wantErr bool
	}{
		{"vm", "vm", pb.NodeIsolation_NODE_ISOLATION_VM, false},
		{"container", "container", pb.NodeIsolation_NODE_ISOLATION_CONTAINER, false},
		{"case insensitive", "CONTAINER", pb.NodeIsolation_NODE_ISOLATION_CONTAINER, false},
		{"typo is refused, not defaulted", "containr", pb.NodeIsolation_NODE_ISOLATION_UNSPECIFIED, true},
		{"the wire spelling is not the flag spelling", "NODE_ISOLATION_VM", pb.NodeIsolation_NODE_ISOLATION_UNSPECIFIED, true},
		{"empty is refused", "", pb.NodeIsolation_NODE_ISOLATION_UNSPECIFIED, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var f isolationFlag
			err := f.Set(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Set(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if f.value != tc.want {
				t.Fatalf("Set(%q) = %v, want %v", tc.in, f.value, tc.want)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "container") {
				t.Fatalf("error %q does not list the accepted values", err)
			}
		})
	}
}

// `cluster get` and `cluster status` both render through printClusterTo:
// the isolation class is visible on every cluster read, so "which
// clusters share a kernel with this host" is answerable from the CLI.
func TestPrintClusterTo_ShowsIsolation(t *testing.T) {
	cases := []struct {
		name string
		in   pb.NodeIsolation
		want string
	}{
		{"vm", pb.NodeIsolation_NODE_ISOLATION_VM, "Isolation:  vm"},
		{"container", pb.NodeIsolation_NODE_ISOLATION_CONTAINER, "Isolation:  container"},
		// A daemon too old to know the field must not render as a VM
		// cluster — an unknown boundary is not a strong boundary.
		{"unspecified", pb.NodeIsolation_NODE_ISOLATION_UNSPECIFIED, "Isolation:  unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			printClusterTo(&buf, &pb.Cluster{
				Name: "demo", Owner: "alice", NodeIsolation: tc.in,
				State: pb.ClusterState_CLUSTER_STATE_READY,
				NodeGroups: []*pb.NodeGroup{{
					Name: "small", MinNodes: 1, MaxNodes: 3,
					Size: &pb.ResourceLimits{Cpu: "2", Memory: "4GB", Disk: "40GB"},
				}},
			})
			if !strings.Contains(buf.String(), tc.want) {
				t.Fatalf("printClusterTo output missing %q:\n%s", tc.want, buf.String())
			}
		})
	}
}

func TestWriteClusterList_ShowsIsolationColumn(t *testing.T) {
	var buf bytes.Buffer
	if err := writeClusterList(&buf, []*pb.Cluster{
		{Name: "hw", Owner: "alice", State: pb.ClusterState_CLUSTER_STATE_READY,
			NodeIsolation: pb.NodeIsolation_NODE_ISOLATION_VM},
		{Name: "shared", Owner: "alice", State: pb.ClusterState_CLUSTER_STATE_READY,
			NodeIsolation: pb.NodeIsolation_NODE_ISOLATION_CONTAINER},
	}); err != nil {
		t.Fatalf("writeClusterList: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ISOLATION") {
		t.Fatalf("list header has no ISOLATION column:\n%s", out)
	}
	for _, want := range []string{"hw", "vm", "shared", "container"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list output missing %q:\n%s", want, out)
		}
	}
}
