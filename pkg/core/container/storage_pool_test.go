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

// Per-request storage pool (#1339), for per-tenant encrypted pools.
//
// #1213 made the pool a process-global so a repointed backend could not
// un-migrate itself. Per-tenant encryption needs the opposite axis: each
// tenant's containers land on THAT tenant's pool, so the pool becomes a
// property of the request rather than of the daemon. The global stays as the
// default; this overrides it per create.

func TestCreate_ExplicitStoragePoolOverridesTheConfiguredOne(t *testing.T) {
	var created incus.ContainerConfig
	mock := &incustest.MockBackend{
		StoragePoolName:     "tenants",
		CreateContainerFunc: func(cfg incus.ContainerConfig) error { created = cfg; return nil },
	}
	m := NewWithBackend(mock)

	_, _ = m.Create(CreateOptions{
		Username:    "alice",
		Image:       "ubuntu:24.04",
		Disk:        "20GB",
		StoragePool: "containarium-tenant-alice",
	})

	if created.Disk == nil {
		t.Fatal("no root disk device configured")
	}
	if created.Disk.Pool != "containarium-tenant-alice" {
		t.Errorf("root disk pool = %q, want %q — the container landed on the daemon-wide pool "+
			"instead of the tenant's, which for an encrypted create means it is outside that "+
			"tenant's encryptionroot and unencrypted", created.Disk.Pool, "containarium-tenant-alice")
	}
}

// The trap this issue exists to close.
//
// A root disk device was only ever emitted when a disk size was requested;
// with no size the container inherits the DEFAULT PROFILE's root disk — the
// daemon-wide pool. So an encrypted create that simply did not ask for a disk
// size would land outside its tenant's encryptionroot, unencrypted, and report
// success. Nothing about the request would look wrong.
func TestCreate_ExplicitStoragePoolEmitsARootDiskWithoutADiskSize(t *testing.T) {
	var created incus.ContainerConfig
	mock := &incustest.MockBackend{
		CreateContainerFunc: func(cfg incus.ContainerConfig) error { created = cfg; return nil },
	}
	m := NewWithBackend(mock)

	_, _ = m.Create(CreateOptions{
		Username:    "alice",
		Image:       "ubuntu:24.04",
		StoragePool: "containarium-tenant-alice",
		// No Disk on purpose.
	})

	if created.Disk == nil {
		t.Fatal("a create naming a storage pool but no disk size emitted no root disk device — " +
			"the container inherits the default profile's pool, silently ignoring the pool it " +
			"was told to use")
	}
	if created.Disk.Pool != "containarium-tenant-alice" {
		t.Errorf("root disk pool = %q, want %q", created.Disk.Pool, "containarium-tenant-alice")
	}
	if created.Disk.Size != "" {
		t.Errorf("root disk size = %q, want empty — the caller asked for no size and one was "+
			"invented", created.Disk.Size)
	}
	if created.Disk.Path != "/" {
		t.Errorf("root disk path = %q, want /", created.Disk.Path)
	}
}

// A create that names no pool must behave exactly as it did before this
// change — same device, or same absence of one. This is the assertion that
// keeps every existing deployment untouched.
func TestCreate_WithoutAnExplicitPoolIsUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name     string
		disk     string
		wantDisk bool
	}{
		{"a disk size still emits a device on the configured pool", "20GB", true},
		{"no disk size and no pool still emits nothing", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var created incus.ContainerConfig
			mock := &incustest.MockBackend{
				StoragePoolName:     "tenants",
				CreateContainerFunc: func(cfg incus.ContainerConfig) error { created = cfg; return nil },
			}
			m := NewWithBackend(mock)

			_, _ = m.Create(CreateOptions{Username: "bob", Image: "ubuntu:24.04", Disk: tc.disk})

			if tc.wantDisk {
				if created.Disk == nil {
					t.Fatal("no root disk device configured")
				}
				if created.Disk.Pool != "tenants" {
					t.Errorf("root disk pool = %q, want the configured %q", created.Disk.Pool, "tenants")
				}
				if created.Disk.Size != tc.disk {
					t.Errorf("root disk size = %q, want %q", created.Disk.Size, tc.disk)
				}
				return
			}
			if created.Disk != nil {
				t.Errorf("a create with neither a pool nor a size gained a root disk device %+v — "+
					"it should still inherit the default profile, as it always has", created.Disk)
			}
		})
	}
}
