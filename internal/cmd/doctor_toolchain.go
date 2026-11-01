//go:build !windows && !containarium_client

package cmd

import (
	"fmt"
	"io"

	"github.com/footprintai/containarium/pkg/core/toolchain"
)

// Managed toolchain reporting (#3360). Since v0.123.0 a BUILD_TOOLS run needs
// a host toolchain release, and a binary-only upgrade does not install one.
// These surfaces make that visible before the first refused run. Advisory
// only: the result is deliberately kept out of hostcheck.Run, so it never
// changes doctor's exit code or the cloud's self_check_ok.

func toolchainStatusDetail(st toolchain.Status) string {
	if st.Missing() {
		return "not installed"
	}
	return st.Err.Error()
}

// printToolchainStatus renders the managed toolchain section of `doctor`.
func printToolchainStatus(w io.Writer, st toolchain.Status) {
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Managed toolchain (advisory — does not affect the exit code):")
	if st.Installed {
		_, _ = fmt.Fprintf(w, "  ✓ %s — release %s (%s)\n", toolchain.HostRoot, st.Release, st.Arch)
		return
	}
	_, _ = fmt.Fprintf(w, "  ! %s — %s\n", toolchain.HostRoot, toolchainStatusDetail(st))
	_, _ = fmt.Fprintf(w, "    %s\n", toolchain.MissingAdvice)
}

// logStartupToolchainCheck logs the host's toolchain state at daemon boot and
// returns true when it warned. Non-fatal: the daemon serves every other run.
func logStartupToolchainCheck(logf func(string, ...any), st toolchain.Status) bool {
	if st.Installed {
		logf("Managed toolchain: release %s (%s) active under %s", st.Release, st.Arch, toolchain.HostRoot)
		return false
	}
	logf("WARNING: managed toolchain %s: %s", toolchain.HostRoot, toolchainStatusDetail(st))
	logf("WARNING: %s", toolchain.MissingAdvice)
	return true
}
