package k8s

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// A pod is a container; the K8s backend has no VM to offer, so a VM
// isolation request fails up front instead of silently producing a
// shared-kernel box the caller believed was VM-isolated (#2196).
func TestCreate_RejectsVMIsolation(t *testing.T) {
	b := &Backend{}
	_, err := b.Create(context.Background(), box.BoxSpec{
		Ref:       box.BoxRef{Tenant: "alice"},
		Isolation: pb.IsolationType_ISOLATION_TYPE_VM,
	})
	if err == nil {
		t.Fatal("Create with ISOLATION_TYPE_VM: want error, got nil")
	}
}
