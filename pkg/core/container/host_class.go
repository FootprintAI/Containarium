package container

import (
	"os/exec"
	"strings"
	"sync"
)

// Host-class detection for environment-specific code paths in
// jump_server.go and friends.
//
// Background: the useradd preconditions (`systemctl stop google-guest-
// agent`, force-removing `/etc/.pwd.lock`) were written for GCP VMs,
// where `google-guest-agent` races with local `useradd` over the
// passwd lock. On any non-GCP host (a VirtualBox lab spot, an on-prem
// box, AWS, Azure, …) those steps are at best no-ops with misleading
// "Access denied" stderr, and at worst actively harmful (force-removing
// a lock file held by something else). Issue #351.
//
// Hosts don't change class at runtime, so we cache the answer behind
// sync.Once. The detector is a package var so tests can swap in a
// deterministic stub without shelling out to `systemd-detect-virt`.

var (
	hostClassOnce   sync.Once
	hostClassResult hostClass

	// hostClassDetector returns the detected hostClass. Real impl
	// runs `systemd-detect-virt`; tests can replace.
	hostClassDetector func() hostClass = detectHostClassViaSystemd
)

// hostClass identifies the platform a host runs on, for the small
// number of places (useradd preconditions) that need to behave
// differently per-platform. Keep this enum tight — we don't want a
// proliferation of platform-specific branches.
type hostClass int

const (
	hostClassUnknown hostClass = iota
	hostClassGCP
)

// getHostClass returns the detected host class, computing it on the
// first call and caching for the lifetime of the process.
func getHostClass() hostClass {
	hostClassOnce.Do(func() {
		hostClassResult = hostClassDetector()
	})
	return hostClassResult
}

// isGCPHost reports whether this daemon is running on a GCP VM.
// Use it to gate code that talks to GCP-specific services
// (google-guest-agent, OS Login, the metadata server's user feed).
func isGCPHost() bool {
	return getHostClass() == hostClassGCP
}

// detectHostClassViaSystemd asks systemd-detect-virt what we're on.
// On GCP that returns "gcp"; KVM/AWS/Azure return their own strings;
// VirtualBox returns "oracle"; bare metal returns "none". Anything
// other than "gcp" is treated as "not GCP" — we can extend the enum
// if other platforms grow their own special-cased code paths.
//
// systemd-detect-virt is in systemd-tools / systemd-container / the
// base systemd package on every host we currently support. If it's
// missing (very old / minimal containers), we treat that as unknown
// rather than crashing — the gated code paths fall back to
// generic behavior, which is the safe default.
func detectHostClassViaSystemd() hostClass {
	out, err := exec.Command("systemd-detect-virt").Output()
	if err != nil {
		return hostClassUnknown
	}
	if strings.TrimSpace(string(out)) == "gcp" {
		return hostClassGCP
	}
	return hostClassUnknown
}
