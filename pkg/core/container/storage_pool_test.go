package container

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

// #1213 AC2: a container created after the storage pool is changed must land
// on the configured pool.
//
// The failure this guards is quiet by construction. An operator migrating a
// backend off a shared-filesystem `dir` pool moves existing tenants across
// with `incus move --storage`, sees the contention probe go clean, and is
// done. Meanwhile every NEW tenant keeps being created on the pool named
// literally "default" — the one they migrated away from — so the exposure
// returns as tenants arrive, weeks later, with nothing connecting it to the
// migration.

func TestCreate_UsesTheConfiguredStoragePool(t *testing.T) {
	var created incus.ContainerConfig
	mock := &incustest.MockBackend{
		StoragePoolName:     "tenants",
		CreateContainerFunc: func(cfg incus.ContainerConfig) error { created = cfg; return nil },
	}
	m := NewWithBackend(mock)

	// A disk size is what triggers an explicit root-disk device; without one
	// the container inherits the default profile, which EnsureDefaultProfile
	// repoints separately.
	_, err := m.Create(CreateOptions{
		Username: "alice",
		Image:    "ubuntu:24.04",
		Disk:     "20GB",
	})
	// The create goes on to do host-account work that a unit test host cannot
	// perform; the assertion is on what was handed to incus, which happens
	// first.
	_ = err

	if created.Disk == nil {
		t.Fatal("no root disk device was configured for a create with an explicit disk size")
	}
	if created.Disk.Pool != "tenants" {
		t.Errorf("root disk pool = %q, want %q — a container created after the backend was "+
			"repointed still landed on the old pool, which is how a storage migration "+
			"silently undoes itself (#1213)", created.Disk.Pool, "tenants")
	}
}

// With nothing configured the behaviour is exactly what it always was, so
// this cannot change any existing deployment.
func TestCreate_DefaultsToTheDefaultPool(t *testing.T) {
	var created incus.ContainerConfig
	mock := &incustest.MockBackend{
		CreateContainerFunc: func(cfg incus.ContainerConfig) error { created = cfg; return nil },
	}
	m := NewWithBackend(mock)

	_, _ = m.Create(CreateOptions{
		Username: "bob",
		Image:    "ubuntu:24.04",
		Disk:     "10GB",
	})

	if created.Disk == nil {
		t.Fatal("no root disk device configured")
	}
	if created.Disk.Pool != incus.DefaultStoragePool {
		t.Errorf("root disk pool = %q, want %q", created.Disk.Pool, incus.DefaultStoragePool)
	}
}
