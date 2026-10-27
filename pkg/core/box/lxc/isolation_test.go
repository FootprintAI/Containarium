package lxc

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestStatusFromInfo_Isolation(t *testing.T) {
	tests := []struct {
		instanceType string
		want         pb.IsolationType
	}{
		{"virtual-machine", pb.IsolationType_ISOLATION_TYPE_VM},
		{"container", pb.IsolationType_ISOLATION_TYPE_CONTAINER},
		{"", pb.IsolationType_ISOLATION_TYPE_UNSPECIFIED},
	}
	for _, tt := range tests {
		st := StatusFromInfo(&incus.ContainerInfo{Name: "a-container", InstanceType: tt.instanceType})
		if st.Isolation != tt.want {
			t.Errorf("InstanceType %q → Isolation %v, want %v", tt.instanceType, st.Isolation, tt.want)
		}
	}
}

func TestSpecToCreateOptions_Isolation(t *testing.T) {
	opts := specToCreateOptions(box.BoxSpec{
		Ref:       box.BoxRef{Tenant: "alice"},
		Isolation: pb.IsolationType_ISOLATION_TYPE_VM,
	})
	if opts.Isolation != pb.IsolationType_ISOLATION_TYPE_VM {
		t.Errorf("Isolation = %v, want VM", opts.Isolation)
	}
}
