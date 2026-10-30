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

// #2858: the podman flag a box was created with is stored in Incus config and
// read back by BOTH real reads (GetContainer and ListContainers), in both
// directions; a box that predates the key reports true. Unit tests fake the
// Incus side, so deleting either read leaves them green.
func TestIntegrationIncus_PodmanEnabledRoundTripsThroughGetAndList(t *testing.T) {
	client := incusenv.Require(t)
	if err := client.InitializeInfrastructure(incus.DefaultNetworkConfig()); err != nil {
		t.Fatalf("the daemon's own infrastructure init failed: %v", err)
	}

	base := fmt.Sprintf("ci%dpod", os.Getpid())
	onTenant, offTenant, legacyName := base+"a", base+"b", base+"c-container"
	onInstance, offInstance := onTenant+"-container", offTenant+"-container"
	for _, inst := range []string{onInstance, offInstance, legacyName} {
		inst := inst
		t.Cleanup(func() { incusenv.DeleteInstance(t, inst) })
	}

	backend := New(container.NewWithBackend(client))
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()

	for _, c := range []struct {
		tenant string
		podman bool
	}{{onTenant, true}, {offTenant, false}} {
		if _, err := backend.Create(ctx, box.BoxSpec{
			Ref:          box.BoxRef{Tenant: c.tenant},
			Image:        incusenv.BoxImage(),
			OSType:       pb.OSType_OS_TYPE_UBUNTU_2404,
			EnablePodman: c.podman,
			AutoStart:    true,
		}); err != nil {
			t.Fatalf("create (podman=%v): %v", c.podman, err)
		}
	}

	// A box that predates the key: created straight through Incus, so it has
	// no user.containarium.podman_enabled at all.
	if err := client.CreateContainer(incus.ContainerConfig{
		Name:  legacyName,
		Image: incusenv.BoxImage(),
	}); err != nil {
		t.Fatalf("create the legacy-shaped box: %v", err)
	}

	all, err := client.ListContainers()
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	for _, tc := range []struct {
		instance string
		want     bool
	}{
		{onInstance, true},
		{offInstance, false},
		{legacyName, true},
	} {
		info, err := client.GetContainer(tc.instance)
		if err != nil || info == nil {
			t.Fatalf("GetContainer(%s) = %v, %v", tc.instance, info, err)
		}
		if info.PodmanEnabled != tc.want {
			t.Errorf("GetContainer(%s).PodmanEnabled = %v, want %v", tc.instance, info.PodmanEnabled, tc.want)
		}
		found := false
		for _, c := range all {
			if c.Name == tc.instance {
				found = true
				if c.PodmanEnabled != tc.want {
					t.Errorf("ListContainers[%s].PodmanEnabled = %v, want %v", tc.instance, c.PodmanEnabled, tc.want)
				}
			}
		}
		if !found {
			t.Errorf("ListContainers did not return %s", tc.instance)
		}
	}

	st, err := backend.Get(ctx, box.BoxRef{Tenant: offTenant})
	if err != nil || st == nil || st.PodmanEnabled {
		t.Errorf("backend.Get(podman off) = %+v, %v; want PodmanEnabled=false", st, err)
	}
}
