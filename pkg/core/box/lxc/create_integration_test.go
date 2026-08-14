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

// The environment #1199 has been blocked on (#1332).
//
// Every other piece of per-tenant ZFS encryption is proven: the zfscrypt
// semantics against a real pool (#1200), the hooks' orchestration in unit
// tests, and PreCreate itself against a real pool. The one step left —
// wiring PreCreate into the create path — had nowhere to run, because
// nothing in CI could create a container through the daemon's own code
// against a real Incus on a real ZFS pool.
//
// This test is that environment. It deliberately drives the box seam
// (box.BoxBackend.Create → container.Manager.Create → the daemon's Incus
// client) rather than `incus launch`: the point is not that a container can
// exist on the runner, it is that OUR create path runs there. Driving Incus
// directly would prove the runner works and leave #1199 exactly as blocked
// as it was.

// tenant is a per-process name so a rerun on a dirty machine cannot collide
// with a leftover from a previous one. The daemon derives the instance name
// from it as "<tenant>-container".
func tenant() string { return fmt.Sprintf("ci%d", os.Getpid()) }

// TestIntegrationIncus_CreateThroughTheDaemonsOwnPath is #1332's acceptance
// criteria 1 and 2, in order: the daemon initialises Incus against a ZFS
// storage pool, then creates a container through its own Create() and the
// container is running.
func TestIntegrationIncus_CreateThroughTheDaemonsOwnPath(t *testing.T) {
	client := incusenv.Require(t)

	// AC1 — initialise through InitializeInfrastructure, which is what the
	// daemon itself calls at startup, not a hand-written preseed. If the
	// daemon's own storage selection cannot land on ZFS here, that is a
	// finding about the daemon and we want to see it as a failure.
	if err := client.InitializeInfrastructure(incus.DefaultNetworkConfig()); err != nil {
		t.Fatalf("the daemon's own infrastructure init failed: %v", err)
	}

	driver, err := client.PoolDriver(client.StoragePool())
	if err != nil {
		t.Fatalf("could not read the storage pool %q the daemon just ensured: %v", client.StoragePool(), err)
	}
	if driver != incus.StorageDriverZFS {
		// Not a cosmetic assertion. On the `dir` driver there is no
		// per-container dataset, so there is nothing for #1199 to encrypt
		// and the lane would prove nothing about the encrypted path while
		// still going green.
		t.Fatalf("storage pool %q is on the %q driver, want %q — an Incus lane on a non-ZFS pool "+
			"cannot exercise the encrypted create path #1199 needs",
			client.StoragePool(), driver, incus.StorageDriverZFS)
	}

	// AC2 — through the daemon's Create(), not `incus launch`.
	backend := New(container.NewWithBackend(client))
	name := tenant()
	instance := name + "-container"
	t.Cleanup(func() { incusenv.DeleteInstance(t, instance) })

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()

	st, err := backend.Create(ctx, box.BoxSpec{
		Ref:       box.BoxRef{Tenant: name},
		Image:     "images:ubuntu/24.04",
		OSType:    pb.OSType_OS_TYPE_UBUNTU_2404,
		AutoStart: true,
		// No SSH keys on purpose: seeding them creates a jump-server
		// account on the HOST, which is a side effect this lane has no
		// business having and which #1199 does not need.
	})
	if err != nil {
		t.Fatalf("the daemon's create path failed against a real Incus: %v", err)
	}
	if st == nil {
		t.Fatal("create reported success and returned no status")
	}
	if st.State != pb.ContainerState_CONTAINER_STATE_RUNNING {
		t.Fatalf("container state = %v, want RUNNING — #1199's hooks run around a create that "+
			"actually starts the box, so a created-but-not-running container is not the path it wires into",
			st.State)
	}
	if st.Ref.Name != instance {
		t.Errorf("instance name = %q, want %q", st.Ref.Name, instance)
	}

	// The box seam has to agree with Incus after the fact, not only in the
	// value Create happened to return.
	got, err := backend.Get(ctx, box.BoxRef{Tenant: name})
	if err != nil {
		t.Fatalf("reading back the container the daemon just created: %v", err)
	}
	if got == nil {
		t.Fatal("the container the daemon reported creating is not there when read back")
	}
	if got.State != pb.ContainerState_CONTAINER_STATE_RUNNING {
		t.Errorf("read-back state = %v, want RUNNING", got.State)
	}

	// The answer #1199 needs from this lane: the container has a ZFS dataset
	// of its own, and it is nameable from the container's name. That mapping
	// is exactly what encryptionHooks' datasetResolver has to provide before
	// the instance exists, so a lane where it cannot be resolved would not
	// unblock #1199 even with a green create above.
	dataset := incusenv.DatasetFor(t, instance)
	if dataset == "" {
		t.Fatalf("no ZFS dataset for instance %s — the pool reports the zfs driver but the "+
			"container did not get a dataset of its own, so there is nothing for #1199 to encrypt", instance)
	}
	t.Logf("instance %s is backed by dataset %s", instance, dataset)
}
