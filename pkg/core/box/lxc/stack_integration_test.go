//go:build incus

package lxc

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/testsupport/incusenv"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2163: the stack a box was created with is stored in Incus config and read
// back by BOTH real reads (GetContainer and ListContainers). Unit tests fake
// the Incus side, so deleting either read leaves them green; only a real
// instance settles it.
func TestIntegrationIncus_StackRoundTripsThroughGetAndList(t *testing.T) {
	client := incusenv.Require(t)
	if err := client.InitializeInfrastructure(incus.DefaultNetworkConfig()); err != nil {
		t.Fatalf("the daemon's own infrastructure init failed: %v", err)
	}

	const stack = "nodejs"
	base := fmt.Sprintf("ci%dstk", os.Getpid())
	withTenant, withoutTenant := base+"a", base+"b"
	withInstance, withoutInstance := withTenant+"-container", withoutTenant+"-container"
	t.Cleanup(func() { incusenv.DeleteInstance(t, withInstance) })
	t.Cleanup(func() { incusenv.DeleteInstance(t, withoutInstance) })

	backend := New(container.NewWithBackend(client))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// With a stack: through the daemon's own create path (writes the key).
	if _, err := backend.Create(ctx, box.BoxSpec{
		Ref:       box.BoxRef{Tenant: withTenant},
		Image:     incusenv.BoxImage(),
		OSType:    pb.OSType_OS_TYPE_UBUNTU_2404,
		Stack:     stack,
		AutoStart: true,
	}); err != nil {
		t.Fatalf("create with stack %q: %v", stack, err)
	}
	// Without a stack: the same path, no stack requested.
	if _, err := backend.Create(ctx, box.BoxSpec{
		Ref:       box.BoxRef{Tenant: withoutTenant},
		Image:     incusenv.BoxImage(),
		OSType:    pb.OSType_OS_TYPE_UBUNTU_2404,
		AutoStart: true,
	}); err != nil {
		t.Fatalf("create without a stack: %v", err)
	}

	all, err := client.ListContainers()
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	for _, tc := range []struct{ instance, want string }{
		{withInstance, stack},
		{withoutInstance, ""},
	} {
		info, err := client.GetContainer(tc.instance)
		if err != nil || info == nil {
			t.Fatalf("GetContainer(%s) = %v, %v", tc.instance, info, err)
		}
		if info.Stack != tc.want {
			t.Errorf("GetContainer(%s).Stack = %q, want %q", tc.instance, info.Stack, tc.want)
		}

		found := false
		for _, c := range all {
			if c.Name == tc.instance {
				found = true
				if c.Stack != tc.want {
					t.Errorf("ListContainers[%s].Stack = %q, want %q", tc.instance, c.Stack, tc.want)
				}
			}
		}
		if !found {
			t.Errorf("ListContainers did not return %s", tc.instance)
		}
	}

	// And through the box seam the server reads.
	st, err := backend.Get(ctx, box.BoxRef{Tenant: withTenant})
	if err != nil || st == nil || st.Stack != stack {
		t.Errorf("backend.Get stack = %+v, %v; want %q", st, err, stack)
	}
}
