package incus

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// StorageDriver is an incus storage-pool driver. Typed rather than a bare
// string so the isolation classification below is attached to the value and
// callers cannot pass an arbitrary string where a driver is expected.
type StorageDriver string

const (
	StorageDriverZFS   StorageDriver = "zfs"
	StorageDriverBtrfs StorageDriver = "btrfs"
	StorageDriverLVM   StorageDriver = "lvm"
	StorageDriverCeph  StorageDriver = "ceph"
	StorageDriverDir   StorageDriver = "dir"
)

// StorageIsolation says whether a pool on a given driver hands each container
// its own filesystem, or puts them all on one shared filesystem.
//
// This is the distinction behind #1206. On the `dir` driver every tenant
// rootfs is a directory on one ext4 filesystem, and therefore shares one jbd2
// journal. ext4's default `data=ordered` mode writes back a transaction's
// dirty data while holding the journal lock, so one tenant's buffered writes
// block another tenant's fsync() — measured at 17 ms → 11,885 ms on a backend
// with three CI tenants, with the host and the physical device both idle.
// That is a tenant-isolation gap, not only a performance one: a tenant
// degrades its neighbours by writing normally, with no privilege and no
// misconfiguration.
//
// Drivers that allocate per-container volumes (a zfs dataset, a btrfs
// subvolume, an LVM logical volume, a ceph RBD image) have no shared journal
// for tenants to contend on.
type StorageIsolation int

const (
	// StorageIsolationUnknown is an unrecognised driver. Deliberately distinct
	// from "shared": we cannot vouch for it either way, and a policy that
	// requires isolation should refuse it rather than assume the best.
	StorageIsolationUnknown StorageIsolation = iota

	// StorageIsolationPerContainer means each container gets its own
	// dataset/subvolume/volume, so tenants do not share a filesystem journal.
	StorageIsolationPerContainer

	// StorageIsolationSharedFilesystem means every container's rootfs lives on
	// one filesystem — one journal, cross-tenant fsync stalls.
	StorageIsolationSharedFilesystem
)

func (i StorageIsolation) String() string {
	switch i {
	case StorageIsolationPerContainer:
		return "per-container-volume"
	case StorageIsolationSharedFilesystem:
		return "shared-filesystem"
	default:
		return "unknown"
	}
}

// Isolation classifies the driver. See StorageIsolation.
func (d StorageDriver) Isolation() StorageIsolation {
	switch d {
	case StorageDriverZFS, StorageDriverBtrfs, StorageDriverLVM, StorageDriverCeph:
		return StorageIsolationPerContainer
	case StorageDriverDir:
		return StorageIsolationSharedFilesystem
	default:
		return StorageIsolationUnknown
	}
}

const (
	// zfsContainersDataset is the ZFS dataset the installer creates. Its
	// presence is what the pre-existing autodetection keyed on.
	zfsContainersDataset = "incus-local/containers"

	// incusStoragePoolsRoot is where incus puts pool sources. Used both as the
	// btrfs probe target and as the btrfs pool source.
	incusStoragePoolsRoot = "/var/lib/incus/storage-pools"
)

// ErrSharedFilesystemStorage is returned when a pool would be provisioned on
// (or is already running on) a driver that does not isolate tenant volumes and
// the configured policy requires isolation. Wrapped, so callers can test with
// errors.Is.
var ErrSharedFilesystemStorage = errors.New("storage pool does not isolate tenant volumes")

// StorageProbe reports which per-container-volume backing stores this host can
// support. Injected rather than called directly so driver selection is
// testable without a real ZFS pool or btrfs filesystem — which matters here
// because no CI environment currently has either (see #1200).
type StorageProbe struct {
	// ZFSContainersDataset reports whether the installer's ZFS dataset exists.
	ZFSContainersDataset func() bool

	// BtrfsFilesystemAt reports whether the given path is on a btrfs
	// filesystem.
	BtrfsFilesystemAt func(path string) bool
}

// DefaultStorageProbe is the real host probe.
func DefaultStorageProbe() StorageProbe {
	return StorageProbe{
		ZFSContainersDataset: detectZFSContainersDataset,
		BtrfsFilesystemAt:    btrfsFilesystemAt,
	}
}

// StorageChoice is the outcome of driver selection: the driver, the pool
// config to create it with, and a human-readable reason for the operator log.
type StorageChoice struct {
	Driver StorageDriver
	Config map[string]string
	Reason string
}

// SelectStorageDriver picks the most isolating driver this host can support,
// falling back to `dir` only when there is nothing better (#1206).
//
// Order is zfs, then btrfs, then dir. btrfs sits second deliberately: it is
// in-tree, so a long-lived backend does not need a DKMS module rebuilt across
// kernel upgrades, while still giving every container its own subvolume.
//
// A probe with no detectors wired selects `dir` rather than panicking — a
// caller that forgot to wire detection must not be told the host has isolating
// storage it does not have.
func SelectStorageDriver(p StorageProbe) StorageChoice {
	if p.ZFSContainersDataset != nil && p.ZFSContainersDataset() {
		return StorageChoice{
			Driver: StorageDriverZFS,
			Config: map[string]string{"source": zfsContainersDataset},
			Reason: fmt.Sprintf("detected ZFS dataset %s; each container gets its own dataset", zfsContainersDataset),
		}
	}

	if p.BtrfsFilesystemAt != nil && p.BtrfsFilesystemAt(incusStoragePoolsRoot) {
		return StorageChoice{
			Driver: StorageDriverBtrfs,
			Config: map[string]string{"source": incusStoragePoolsRoot},
			Reason: fmt.Sprintf("no ZFS dataset, but %s is on btrfs; each container gets its own subvolume", incusStoragePoolsRoot),
		}
	}

	return StorageChoice{
		Driver: StorageDriverDir,
		Config: map[string]string{},
		Reason: "no ZFS dataset and no btrfs filesystem available; falling back to the dir driver",
	}
}

// StoragePolicy decides what happens when a pool does not isolate tenant
// volumes.
type StoragePolicy int

const (
	// StoragePolicyWarnOnSharedFilesystem provisions anyway and logs a loud
	// warning. The default: it preserves existing behaviour for dev hosts and
	// single-tenant boxes, where a shared journal has nobody to contend with.
	StoragePolicyWarnOnSharedFilesystem StoragePolicy = iota

	// StoragePolicyRequireIsolation makes a non-isolating pool a hard failure.
	// For backends that run mutually untrusting tenants, where landing on
	// `dir` silently is the failure mode #1206 describes.
	StoragePolicyRequireIsolation
)

// StoragePolicyFromRequireFlag maps the daemon's --require-isolated-storage
// boolean onto the typed policy.
func StoragePolicyFromRequireFlag(require bool) StoragePolicy {
	if require {
		return StoragePolicyRequireIsolation
	}
	return StoragePolicyWarnOnSharedFilesystem
}

// checkStoragePolicy returns an error when policy forbids running the named
// pool on the given driver. Anything not positively known to isolate tenant
// volumes is refused under StoragePolicyRequireIsolation — including unknown
// drivers, which we cannot vouch for.
func checkStoragePolicy(policy StoragePolicy, pool string, driver StorageDriver) error {
	if policy != StoragePolicyRequireIsolation {
		return nil
	}
	if driver.Isolation() == StorageIsolationPerContainer {
		return nil
	}
	return fmt.Errorf(
		"%w: pool %q uses the %q driver (%s) and --require-isolated-storage is set; "+
			"provision the pool on zfs or btrfs, or drop the flag to accept cross-tenant fsync stalls (see #1206)",
		ErrSharedFilesystemStorage, pool, driver, driver.Isolation())
}

// reviewStoragePool applies the isolation policy to a pool — one that already
// exists, or one that was just selected — and returns the warning to log
// (empty when the pool isolates tenant volumes) plus an error when the policy
// forbids running on it at all.
//
// Both of EnsureStorage's exits route through here so the already-provisioned
// path cannot silently skip the check: a backend created on `dir` before this
// change never re-runs selection, and would otherwise stay quiet forever.
func reviewStoragePool(policy StoragePolicy, pool string, driver StorageDriver) (string, error) {
	if err := checkStoragePolicy(policy, pool, driver); err != nil {
		return "", err
	}
	switch driver.Isolation() {
	case StorageIsolationPerContainer:
		return "", nil
	case StorageIsolationSharedFilesystem:
		return sharedFilesystemWarning(pool, driver), nil
	default:
		return unknownDriverWarning(pool, driver), nil
	}
}

// unknownDriverWarning flags a driver we do not recognise.
//
// Deliberately weaker than sharedFilesystemWarning: an unrecognised driver is
// worth an operator's attention, but the dir warning asserts a specific
// mechanism and a measured degradation that we have established only for dir.
// Claiming them for a driver we cannot classify would be wrong, and would
// train operators to ignore the warning that is right.
func unknownDriverWarning(pool string, driver StorageDriver) string {
	return fmt.Sprintf(
		"  WARNING: storage pool %q uses the unrecognised %q driver; Containarium cannot "+
			"confirm whether it isolates tenant volumes. If containers on this pool share one "+
			"filesystem, they share its journal and can stall each other's fsync (see #1206).",
		pool, driver)
}

// sharedFilesystemWarning is the operator-facing warning for a pool that does
// not isolate tenant volumes.
//
// Deliberately multi-line and explicit. The pre-existing log line ("No ZFS
// dataset found, using dir driver") read like routine autodetection, so the
// downgrade was invisible; the failure it causes only appears months later,
// under concurrent tenant load, as an unexplained fsync stall. Naming the
// mechanism and the ticket is what lets an operator connect the two.
func sharedFilesystemWarning(pool string, driver StorageDriver) string {
	return strings.Join([]string{
		"",
		"  ############################################################",
		fmt.Sprintf("  # WARNING: storage pool %q uses the %q driver.", pool, driver),
		"  #",
		"  # Every container's rootfs is a directory on ONE shared",
		"  # filesystem, so all tenants share one ext4 jbd2 journal.",
		"  # Under concurrent write-heavy tenants, one tenant's dirty",
		"  # pages block another tenant's fsync() for seconds — measured",
		"  # at ~700x degradation (17 ms -> 11,885 ms) with the host and",
		"  # the physical device both idle.",
		"  #",
		"  # This is a tenant-isolation gap, not just a performance one:",
		"  # a tenant can degrade its neighbours by writing normally,",
		"  # with no privilege and no misconfiguration. Idle benchmarks",
		"  # show the opposite of the truth.",
		"  #",
		"  # Fix: provision the pool on zfs or btrfs, so each container",
		"  # gets its own dataset/subvolume. Run with",
		"  # --require-isolated-storage to make this a hard failure.",
		"  #",
		"  # See issue #1206 for the measurements and the reproduction:",
		"  # https://github.com/FootprintAI/Containarium/issues/1206",
		"  ############################################################",
		"",
	}, "\n")
}

// btrfsFilesystemAt reports whether path sits on a btrfs filesystem.
//
// The path may not exist yet on a fresh host (incus creates the storage-pools
// root lazily), so the probe walks up to the nearest existing ancestor before
// asking. Shells out to findmnt for the same reason detectZFSContainersDataset
// shells out to zfs: it is the tool that is actually present on a Linux
// backend, and there is no stable Go API for it.
func btrfsFilesystemAt(path string) bool {
	target := nearestExistingAncestor(path)
	if target == "" {
		return false
	}
	cmd := exec.Command("findmnt", "-n", "-o", "FSTYPE", "--target", target) // #nosec G204 -- target is a resolved absolute path
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == string(StorageDriverBtrfs)
}

// nearestExistingAncestor returns path if it exists, else its closest existing
// parent directory, else "".
func nearestExistingAncestor(path string) string {
	for p := filepath.Clean(path); ; {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return ""
		}
		p = parent
	}
}
