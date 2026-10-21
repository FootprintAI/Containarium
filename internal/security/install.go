package security

import (
	"fmt"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Installing ClamAV in a tenant's box (#2631, #2659).
//
// The platform runs the package install INSIDE the box, in the box's own
// context, started by its owner. It does not read the box's files and keeps no
// package-manager output: the result is a typed outcome and a short fixed
// message.

// installTimeout bounds the package install and the first signature download.
const installTimeout = 15 * time.Minute

// installFreshclamTimeout bounds the first signature download on its own.
const installFreshclamTimeout = 10 * time.Minute

// Messages. Fixed strings only: nothing from the box's output is echoed back.
const (
	msgInstalled      = "ClamAV and its signatures are installed in the box"
	msgAlreadyPresent = "ClamAV and its signatures are already installed; nothing was run"
	msgNotRunning     = "the box is not running; start it and try again"
	msgFamily         = "this command installs ClamAV on Debian/Ubuntu boxes only; install ClamAV manually in this box"
	msgSizeFmt        = "the box's memory limit %s is below the %d GB ClamAV needs; resize it first"
	msgInstallFailed  = "the ClamAV package install failed in the box (no network egress to the package mirror, or apt is locked); retry, or install manually"
	msgSigFailed      = "ClamAV installed, but downloading signatures failed (the box needs outbound access to the ClamAV signature servers); run freshclam in the box once reachable"
	msgVerifyFailed   = "the install finished but ClamAV or its signatures are still missing in the box"
)

// debianFamilyProbe exits 0 on a Debian-family box (apt-get present, no
// /etc/redhat-release) and 1 otherwise, never 127 (see presenceProbe).
const debianFamilyProbe = "if command -v apt-get >/dev/null 2>&1 && [ ! -f /etc/redhat-release ]; then exit 0; else exit 1; fi"

// clamavPresent reports whether clamscan and a signature database exist in the
// box. err means the box could not be asked at all.
func clamavPresent(box boxAPI, name string) (haveBin, haveSigs bool, err error) {
	_, _, code, err := box.ExecWithExitCode(name, []string{"sh", "-c", presenceProbe("clamscan")})
	if err != nil {
		return false, false, err
	}
	haveBin = code == 0
	_, _, code, err = box.ExecWithExitCode(name, []string{"sh", "-c", "ls /var/lib/clamav/main.c?d /var/lib/clamav/daily.c?d >/dev/null 2>&1"})
	if err != nil {
		return false, false, err
	}
	return haveBin, code == 0, nil
}

// isDebianFamily mirrors ostype.DetectFamily's probes through the exit-code
// exec: a Debian-family box has apt-get and no /etc/redhat-release.
func isDebianFamily(box boxAPI, name string) (bool, error) {
	_, _, code, err := box.ExecWithExitCode(name, []string{"sh", "-c", debianFamilyProbe})
	if err != nil {
		return false, err
	}
	return code == 0, nil
}

// InstallClamav installs ClamAV and its signatures inside the named box and
// returns a typed outcome with a fixed message. It is idempotent: a box that
// already has both runs nothing.
func InstallClamav(box boxAPI, name string) (pb.ClamavInstallOutcome, string) {
	info, err := box.GetContainer(name)
	if err != nil {
		return pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_FAILED, fmt.Sprintf("could not look up the box: %v", err)
	}
	if info.State != "Running" {
		return pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_FAILED, msgNotRunning
	}
	if boxTooSmall(info.Memory) {
		return pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_UNSUPPORTED_SIZE,
			fmt.Sprintf(msgSizeFmt, info.Memory, MinBoxMemoryBytes/1_000_000_000)
	}

	haveBin, haveSigs, err := clamavPresent(box, name)
	if err != nil {
		return pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_FAILED, fmt.Sprintf("could not reach the box: %v", err)
	}
	if haveBin && haveSigs {
		return pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_ALREADY_PRESENT, msgAlreadyPresent
	}

	if !haveBin {
		debian, err := isDebianFamily(box, name)
		if err != nil {
			return pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_FAILED, fmt.Sprintf("could not reach the box: %v", err)
		}
		if !debian {
			return pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_UNSUPPORTED_FAMILY, msgFamily
		}
		_, _, code, err := box.ExecWithExitCode(name, []string{"sh", "-c", fmt.Sprintf(
			"DEBIAN_FRONTEND=noninteractive timeout %d sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends clamav'",
			int(installTimeout/time.Second))})
		if err != nil || code != 0 {
			return pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_FAILED, msgInstallFailed
		}
	}

	// Signatures: the package's freshclam service may already be fetching them
	// and holds the lock, so stop it for the one-shot run and start it again.
	_, _, code, err := box.ExecWithExitCode(name, []string{"sh", "-c", fmt.Sprintf(
		"systemctl stop clamav-freshclam >/dev/null 2>&1; timeout %d freshclam --quiet; rc=$?; systemctl start clamav-freshclam >/dev/null 2>&1; exit $rc",
		int(installFreshclamTimeout/time.Second))})
	if err != nil || code != 0 {
		// The service may have downloaded them anyway; trust the check below.
		if _, sigs, perr := clamavPresent(box, name); perr != nil || !sigs {
			return pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_FAILED, msgSigFailed
		}
	}

	if bin, sigs, err := clamavPresent(box, name); err != nil || !bin || !sigs {
		return pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_FAILED, msgVerifyFailed
	}
	return pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_INSTALLED, msgInstalled
}
