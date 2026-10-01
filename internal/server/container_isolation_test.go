package server

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// toProtoContainer must surface the backend-reported isolation so
// `containarium list` and the anonymous-box e2e assertion can read it
// without inspecting Incus (#2196).
func TestToProtoContainer_IsolationSurfaced(t *testing.T) {
	for _, want := range []pb.IsolationType{
		pb.IsolationType_ISOLATION_TYPE_VM,
		pb.IsolationType_ISOLATION_TYPE_CONTAINER,
		pb.IsolationType_ISOLATION_TYPE_UNSPECIFIED,
	} {
		pc := toProtoContainer(&box.BoxStatus{
			Ref:       box.BoxRef{Tenant: "alice", Name: "alice-container"},
			Isolation: want,
		})
		if pc.Isolation != want {
			t.Errorf("Isolation = %v, want %v", pc.Isolation, want)
		}
	}
}
