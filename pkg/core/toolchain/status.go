package toolchain

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// InstallDoc is the operator doc with the host install steps. Refusals,
// `containarium doctor` and the daemon's startup warning all point here so an
// operator who upgraded the binary alone learns the second step (#3360).
const InstallDoc = "docs/MANAGED-TOOLCHAINS.md"

// MissingAdvice is the operator-facing explanation shared by every surface
// that reports a host without an active toolchain release.
const MissingAdvice = "BUILD_TOOLS runs are refused until a managed toolchain release is installed under " +
	HostRoot + " (a binary-only upgrade does not install it; NONE and FULL_SUDO runs are unaffected): see " + InstallDoc

// Status is what the host has installed under a toolchain root.
type Status struct {
	// Installed is true when current/manifest.json is a regular file that
	// parses; Release and Arch then come from it.
	Installed bool
	Release   string
	Arch      string
	// Err is the reason the release is not usable when Installed is false.
	Err error
}

// Missing reports whether no release is installed at all, as opposed to a
// release that is present but unreadable or malformed.
func (s Status) Missing() bool { return !s.Installed && errors.Is(s.Err, os.ErrNotExist) }

// releaseManifest is the subset of manifest.json (scripts/toolchains/build.py)
// that status reporting needs.
type releaseManifest struct {
	Release string `json:"release"`
	Arch    string `json:"arch"`
}

// ReadStatus inspects root's active release. It shares CheckRelease's
// classification, so "missing" here means exactly what a refused run means.
func ReadStatus(root string) Status {
	if err := CheckRelease(root); err != nil {
		return Status{Err: err}
	}
	path := filepath.Join(root, "current", "manifest.json")
	data, err := os.ReadFile(path) // #nosec G304 -- fixed manifest name under the platform toolchain root (HostRoot; a temp dir in tests)
	if err != nil {
		return Status{Err: fmt.Errorf("read managed toolchain manifest %s: %w", path, err)}
	}
	var m releaseManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Status{Err: fmt.Errorf("parse managed toolchain manifest %s: %w", path, err)}
	}
	return Status{Installed: true, Release: m.Release, Arch: m.Arch}
}
