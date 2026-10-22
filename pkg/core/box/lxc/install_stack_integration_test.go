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

// #2859: installing a stack on a running box records it, visible through BOTH
// real reads (GetContainer and ListContainers); a second stack replaces the
// first; a base script (the startup timezone reconcile runs one in every box)
// does not touch it. Unit tests fake the Incus side, so only a real instance
// settles that the write and the reads agree.
func TestIntegrationIncus_InstallStackUpdatesStoredStack(t *testing.T) {
	client := incusenv.Require(t)
	if err := client.InitializeInfrastructure(incus.DefaultNetworkConfig()); err != nil {
		t.Fatalf("the daemon's own infrastructure init failed: %v", err)
	}

	tenant := fmt.Sprintf("ci%dist", os.Getpid())
	instance := tenant + "-container"
	t.Cleanup(func() { incusenv.DeleteInstance(t, instance) })

	mgr := container.NewWithBackend(client)
	backend := New(mgr)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()

	// Created with no stack: it starts out reporting none.
	if _, err := backend.Create(ctx, box.BoxSpec{
		Ref:       box.BoxRef{Tenant: tenant},
		Image:     incusenv.BoxImage(),
		OSType:    pb.OSType_OS_TYPE_UBUNTU_2404,
		AutoStart: true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	stackOf := func(t *testing.T) (viaGet, viaList string) {
		t.Helper()
		info, err := client.GetContainer(instance)
		if err != nil || info == nil {
			t.Fatalf("GetContainer(%s) = %v, %v", instance, info, err)
		}
		all, err := client.ListContainers()
		if err != nil {
			t.Fatalf("ListContainers: %v", err)
		}
		found := false
		for _, c := range all {
			if c.Name == instance {
				found, viaList = true, c.Stack
			}
		}
		if !found {
			t.Fatalf("ListContainers did not return %s", instance)
		}
		return info.Stack, viaList
	}
	expect := func(t *testing.T, want string) {
		t.Helper()
		g, l := stackOf(t)
		if g != want {
			t.Errorf("GetContainer.Stack = %q, want %q", g, want)
		}
		if l != want {
			t.Errorf("ListContainers.Stack = %q, want %q", l, want)
		}
	}

	expect(t, "")

	if err := mgr.InstallStack(tenant, "nodejs"); err != nil {
		t.Fatalf("InstallStack(nodejs): %v", err)
	}
	expect(t, "nodejs")

	// A base script is not a stack: the stored value is untouched.
	if err := mgr.InstallStack(tenant, "ntp"); err != nil {
		t.Fatalf("InstallStack(ntp): %v", err)
	}
	expect(t, "nodejs")

	// Single-valued: the latest stack replaces the previous one.
	if err := mgr.InstallStack(tenant, "python"); err != nil {
		t.Fatalf("InstallStack(python): %v", err)
	}
	expect(t, "python")
}
