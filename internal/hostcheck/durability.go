//go:build !windows

package hostcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultRecoveryDir is where the daemon writes containarium-recovery.yaml.
// The file exists to survive instance recreation, so it is only useful if
// this path is backed by a disk that outlives the instance.
const DefaultRecoveryDir = "/mnt/incus-data"

// IsDurable reports whether path is its own mount point — i.e. backed by
// a filesystem mounted there, rather than being a plain directory on some
// ancestor's volume.
//
// This is the distinction os.Stat cannot make, and it is the whole of
// #1154: the daemon gated its recovery-config write on the directory
// merely existing. Any host where /mnt/incus-data existed for any reason
// — a leftover mkdir from the startup script, a partial migration — was
// treated as durable storage, and the config was written to the boot
// disk, destroyed by exactly the event it exists to survive.
//
// An error means the answer is unknown; callers must not read that as
// "not durable", because a guess presented as a fact is what caused the
// original bug.
func IsDurable(path string) (bool, error) {
	return isOwnMount("/proc/mounts", path)
}

// isOwnMount is IsDurable with an injectable /proc/mounts, for tests.
func isOwnMount(procMountsPath, target string) (bool, error) {
	raw, err := os.ReadFile(procMountsPath) // #nosec G304 -- procMountsPath is /proc/mounts in production; the parameter exists so tests can supply a fixture
	if err != nil {
		return false, fmt.Errorf("read %s: %w", procMountsPath, err)
	}

	// Normalise so "/mnt/incus-data/" and "/mnt/incus-data" compare
	// equal; filepath.Clean also collapses "." and duplicate separators.
	target = filepath.Clean(target)

	_, mountPoint := deviceForPath(string(raw), target)
	if mountPoint == "" {
		// No real device covers the path at all. Not durable, and not an
		// error: an overlay-only or wholly pseudo-filesystem root is a
		// legitimate host shape, just not a durable one.
		return false, nil
	}
	return filepath.Clean(mountPoint) == target, nil
}

// recoveryConfigDurableCheck reports whether the recovery config's
// directory is on storage that survives instance recreation.
//
// Surfaced through `containarium doctor` rather than left as a log line,
// because the failure is silent by construction: the write succeeds, the
// file looks current, and the problem is discovered during an actual
// recovery — the worst possible moment (#1154).
func recoveryConfigDurableCheck(p posturePaths) Check {
	c := Check{Name: "recovery config on durable storage"}

	dir := p.recoveryDir
	if dir == "" {
		dir = DefaultRecoveryDir
	}

	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			// No persistent storage provisioned. Reported as not-OK
			// rather than OK: this host writes no recovery config at
			// all, so it cannot be rebuilt after instance recreation —
			// which is a true and actionable finding, not a pass.
			//
			// It is also what the posture contract requires: a check
			// may not claim OK without positive evidence, and "the
			// directory is missing" is the absence of evidence
			// (TestRunPosture_UnknownHostReportsNoPasses).
			c.Detail = fmt.Sprintf(
				"%s does not exist: no persistent storage is provisioned, so no recovery config is "+
					"written and this host cannot be rebuilt after instance recreation", dir)
			return c
		}
		c.Detail = fmt.Sprintf("cannot stat %s: %v", dir, err)
		return c
	}

	durable, err := isOwnMount(p.procMounts, dir)
	if err != nil {
		c.Detail = fmt.Sprintf("cannot determine whether %s is durable: %v", dir, err)
		return c
	}
	if !durable {
		c.Detail = fmt.Sprintf(
			"%s is a directory on another filesystem, not its own mount: a recovery config written "+
				"there does NOT survive instance recreation, which is the only event it exists for",
			dir)
		return c
	}

	c.OK = true
	c.Detail = fmt.Sprintf("%s is its own mount point", dir)
	return c
}

// DescribeDurability renders a one-line operator-facing warning for a
// non-durable recovery directory, or "" when the location is fine or
// undeterminable. Used by the daemon at write time so the condition is
// visible in the startup log as well as in `doctor`.
func DescribeDurability(dir string) string {
	durable, err := IsDurable(dir)
	if err != nil || durable {
		return ""
	}
	return strings.Join([]string{
		fmt.Sprintf("WARNING: %s is not its own mount point.", dir),
		"The recovery config has been written, but it lives on the boot disk and will be",
		"destroyed by instance recreation — the exact event it exists to survive.",
		"Attach persistent storage there, or treat this host as non-recoverable.",
	}, " ")
}
