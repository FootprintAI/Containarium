package incus

import (
	"errors"
	"strings"
	"testing"
)

// TestStorageDriver_Isolation pins the property that actually matters for
// tenant isolation: does a pool on this driver give every container its own
// filesystem, or do they all share one?
//
// This is the classification #1206 turns on. A `dir` pool puts every tenant
// rootfs on one ext4 filesystem, so they share one jbd2 journal and one
// tenant's writeback stalls another's fsync. zfs/btrfs/lvm/ceph each hand a
// container its own dataset / subvolume / logical volume, so there is no
// shared journal to contend on.
func TestStorageDriver_Isolation(t *testing.T) {
	tests := []struct {
		name   string
		driver StorageDriver
		want   StorageIsolation
	}{
		{
			name:   "dir shares one filesystem across every tenant",
			driver: StorageDriverDir,
			want:   StorageIsolationSharedFilesystem,
		},
		{
			name:   "zfs gives each container its own dataset",
			driver: StorageDriverZFS,
			want:   StorageIsolationPerContainer,
		},
		{
			name:   "btrfs gives each container its own subvolume",
			driver: StorageDriverBtrfs,
			want:   StorageIsolationPerContainer,
		},
		{
			name:   "lvm gives each container its own logical volume",
			driver: StorageDriverLVM,
			want:   StorageIsolationPerContainer,
		},
		{
			name:   "ceph gives each container its own RBD image",
			driver: StorageDriverCeph,
			want:   StorageIsolationPerContainer,
		},
		{
			name:   "an unrecognised driver is unknown, not assumed safe",
			driver: StorageDriver("some-future-driver"),
			want:   StorageIsolationUnknown,
		},
		{
			name:   "the empty driver is unknown",
			driver: StorageDriver(""),
			want:   StorageIsolationUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.driver.Isolation(); got != tt.want {
				t.Errorf("StorageDriver(%q).Isolation() = %v, want %v", tt.driver, got, tt.want)
			}
		})
	}
}

// TestSelectStorageDriver_PrefersPerContainerVolumes is the core of #1206's
// suggested direction (1): when provisioning a pool, pick the most isolating
// driver the host can actually support, and only land on `dir` when there is
// nothing better.
//
// btrfs sits between zfs and dir deliberately: it is in-tree, so a long-lived
// backend does not need a DKMS module rebuilt across kernel upgrades, but it
// still gives every container its own subvolume.
func TestSelectStorageDriver_PrefersPerContainerVolumes(t *testing.T) {
	tests := []struct {
		name       string
		zfsDataset bool
		btrfsPath  bool
		wantDriver StorageDriver
		wantSource string
	}{
		{
			name:       "zfs dataset present wins",
			zfsDataset: true,
			btrfsPath:  false,
			wantDriver: StorageDriverZFS,
			wantSource: zfsContainersDataset,
		},
		{
			name:       "zfs still wins when btrfs is also available",
			zfsDataset: true,
			btrfsPath:  true,
			wantDriver: StorageDriverZFS,
			wantSource: zfsContainersDataset,
		},
		{
			name:       "btrfs is chosen when there is no zfs dataset",
			zfsDataset: false,
			btrfsPath:  true,
			wantDriver: StorageDriverBtrfs,
			wantSource: incusStoragePoolsRoot,
		},
		{
			name:       "dir only when nothing isolating is available",
			zfsDataset: false,
			btrfsPath:  false,
			wantDriver: StorageDriverDir,
			wantSource: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SelectStorageDriver(StorageProbe{
				ZFSContainersDataset: func() bool { return tt.zfsDataset },
				BtrfsFilesystemAt:    func(string) bool { return tt.btrfsPath },
			})
			if got.Driver != tt.wantDriver {
				t.Errorf("Driver = %q, want %q", got.Driver, tt.wantDriver)
			}
			if got.Config["source"] != tt.wantSource {
				t.Errorf("Config[source] = %q, want %q", got.Config["source"], tt.wantSource)
			}
			if got.Reason == "" {
				t.Error("Reason is empty; the operator log needs to say why this driver was picked")
			}
		})
	}
}

// TestSelectStorageDriver_NilProbesFallBackToDir guards the zero-value
// StorageProbe: a caller that forgets to wire a detector must not panic, and
// must not be silently told the host has isolating storage it does not have.
func TestSelectStorageDriver_NilProbesFallBackToDir(t *testing.T) {
	got := SelectStorageDriver(StorageProbe{})
	if got.Driver != StorageDriverDir {
		t.Errorf("Driver = %q, want %q for a probe with no detectors wired", got.Driver, StorageDriverDir)
	}
}

// TestSharedFilesystemWarning_NamesTheFailure asserts the fallback is *loud*.
// The bug in #1206 is invisible until tenants are concurrently busy, and the
// pre-existing log line ("No ZFS dataset found, using dir driver") reads like
// routine autodetection rather than a tenant-isolation downgrade. The warning
// has to name the mechanism and the ticket, or an operator scrolling boot logs
// will not connect it to a 700x fsync stall months later.
func TestSharedFilesystemWarning_NamesTheFailure(t *testing.T) {
	got := sharedFilesystemWarning("default", StorageDriverDir)

	for _, want := range []string{
		"default",   // which pool
		"dir",       // which driver
		"fsync",     // the symptom an operator will actually observe
		"journal",   // the mechanism
		"#1206",     // where the evidence lives
		"isolation", // the class of problem, not just a perf note
	} {
		if !strings.Contains(got, want) {
			t.Errorf("warning does not mention %q; got:\n%s", want, got)
		}
	}

	if strings.Count(got, "\n") == 0 {
		t.Error("warning is a single line; it needs to stand out in a boot log")
	}
}

// TestCheckStoragePolicy covers the "refuse" half of #1206's direction (1):
// an operator running real tenants must be able to make a shared-filesystem
// pool a provisioning failure rather than a silent downgrade.
func TestCheckStoragePolicy(t *testing.T) {
	tests := []struct {
		name    string
		policy  StoragePolicy
		driver  StorageDriver
		wantErr bool
	}{
		{
			name:    "default policy allows dir (dev hosts and single-tenant boxes)",
			policy:  StoragePolicyWarnOnSharedFilesystem,
			driver:  StorageDriverDir,
			wantErr: false,
		},
		{
			name:    "require-isolation refuses dir",
			policy:  StoragePolicyRequireIsolation,
			driver:  StorageDriverDir,
			wantErr: true,
		},
		{
			name:    "require-isolation accepts zfs",
			policy:  StoragePolicyRequireIsolation,
			driver:  StorageDriverZFS,
			wantErr: false,
		},
		{
			name:    "require-isolation accepts btrfs",
			policy:  StoragePolicyRequireIsolation,
			driver:  StorageDriverBtrfs,
			wantErr: false,
		},
		{
			name:    "require-isolation refuses an unknown driver it cannot vouch for",
			policy:  StoragePolicyRequireIsolation,
			driver:  StorageDriver("some-future-driver"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkStoragePolicy(tt.policy, "default", tt.driver)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				if !errors.Is(err, ErrSharedFilesystemStorage) {
					t.Errorf("error does not wrap ErrSharedFilesystemStorage: %v", err)
				}
				if !strings.Contains(err.Error(), string(tt.driver)) {
					t.Errorf("error does not name the driver %q: %v", tt.driver, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestReviewStoragePool is the decision EnsureStorage applies at both of its
// exits: the pool it just chose, and — importantly — the pool that already
// existed.
//
// The already-exists path is the one that matters in practice. EnsureStorage
// returns early when the pool is present, so a backend that was provisioned on
// `dir` before this change never re-runs selection and would otherwise stay
// silent forever. That is exactly the state the host in #1206 is in.
func TestReviewStoragePool(t *testing.T) {
	tests := []struct {
		name        string
		policy      StoragePolicy
		driver      StorageDriver
		wantWarning bool
		wantErr     bool
	}{
		{
			name:        "existing dir pool warns under the default policy",
			policy:      StoragePolicyWarnOnSharedFilesystem,
			driver:      StorageDriverDir,
			wantWarning: true,
			wantErr:     false,
		},
		{
			name:        "existing dir pool is a hard failure under require-isolation",
			policy:      StoragePolicyRequireIsolation,
			driver:      StorageDriverDir,
			wantWarning: false,
			wantErr:     true,
		},
		{
			name:        "zfs pool is silent",
			policy:      StoragePolicyWarnOnSharedFilesystem,
			driver:      StorageDriverZFS,
			wantWarning: false,
			wantErr:     false,
		},
		{
			name:        "btrfs pool is silent",
			policy:      StoragePolicyRequireIsolation,
			driver:      StorageDriverBtrfs,
			wantWarning: false,
			wantErr:     false,
		},
		{
			name:        "an unknown driver warns but does not fail the default policy",
			policy:      StoragePolicyWarnOnSharedFilesystem,
			driver:      StorageDriver("some-future-driver"),
			wantWarning: true,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning, err := reviewStoragePool(tt.policy, "default", tt.driver)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				if !errors.Is(err, ErrSharedFilesystemStorage) {
					t.Errorf("error does not wrap ErrSharedFilesystemStorage: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := warning != ""; got != tt.wantWarning {
				t.Errorf("warning present = %v, want %v (warning: %q)", got, tt.wantWarning, warning)
			}
		})
	}
}

// TestReviewStoragePool_UnknownDriverWarningIsHonest guards against
// overclaiming. An unrecognised driver is worth flagging — we cannot vouch for
// its isolation — but the `dir` warning asserts a specific mechanism (one ext4
// filesystem, one jbd2 journal, a measured ~700x stall) that we have not
// established for a driver we do not recognise. Saying so anyway would train
// operators to ignore the warning.
func TestReviewStoragePool_UnknownDriverWarningIsHonest(t *testing.T) {
	warning, err := reviewStoragePool(
		StoragePolicyWarnOnSharedFilesystem, "default", StorageDriver("some-future-driver"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if warning == "" {
		t.Fatal("an unrecognised driver should still be flagged")
	}

	if !strings.Contains(warning, "some-future-driver") {
		t.Errorf("warning does not name the driver; got:\n%s", warning)
	}
	for _, mustNotSay := range []string{"jbd2", "11,885", "700x"} {
		if strings.Contains(warning, mustNotSay) {
			t.Errorf("warning claims %q, which is only established for the dir driver; got:\n%s",
				mustNotSay, warning)
		}
	}

	// The dir warning, by contrast, has earned those specifics.
	dirWarning, _ := reviewStoragePool(StoragePolicyWarnOnSharedFilesystem, "default", StorageDriverDir)
	if !strings.Contains(dirWarning, "jbd2") {
		t.Errorf("the dir warning lost its mechanism; got:\n%s", dirWarning)
	}
}

// TestStoragePolicyFromRequireFlag maps the daemon's boolean flag onto the
// typed policy, so the flag cannot drift from the behaviour it selects.
func TestStoragePolicyFromRequireFlag(t *testing.T) {
	if got := StoragePolicyFromRequireFlag(true); got != StoragePolicyRequireIsolation {
		t.Errorf("StoragePolicyFromRequireFlag(true) = %v, want StoragePolicyRequireIsolation", got)
	}
	if got := StoragePolicyFromRequireFlag(false); got != StoragePolicyWarnOnSharedFilesystem {
		t.Errorf("StoragePolicyFromRequireFlag(false) = %v, want StoragePolicyWarnOnSharedFilesystem", got)
	}
}
