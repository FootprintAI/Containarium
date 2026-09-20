package submit

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// MinGitMajor/MinGitMinor is the minimum host git version
// SubmitTrackerChange requires — decision D2's ">= 2.31", needed for
// GIT_CONFIG_COUNT/GIT_CONFIG_KEY_N/GIT_CONFIG_VALUE_N env-based config
// (GitPusher's hardening mechanism). See
// docs/architecture/agent-tracker-broker.md.
const (
	MinGitMajor = 2
	MinGitMinor = 31
)

var (
	// ErrGitMissing is returned when no git binary is found on PATH.
	ErrGitMissing = errors.New("submit: git not found on host PATH")
	// ErrGitTooOld is returned when git is present but older than
	// MinGitMajor.MinGitMinor.
	ErrGitTooOld = errors.New("submit: host git is older than the minimum required version")
)

// CheckHostGit runs `git version` on the host and confirms it meets
// MinGitMajor.MinGitMinor. Host git is a preflight, not an assumption:
// SubmitTrackerChange calls this before doing any box or network work,
// and a later PR surfaces the same version string in `tracker status`
// so an operator sees the gap before an agent hits it.
func CheckHostGit() (version string, err error) {
	gitPath, lookErr := exec.LookPath("git")
	if lookErr != nil {
		return "", fmt.Errorf("%w: %v", ErrGitMissing, lookErr)
	}
	// #nosec G204 -- fixed "version" subcommand, no caller-supplied argv.
	out, runErr := exec.Command(gitPath, "version").Output()
	if runErr != nil {
		return "", fmt.Errorf("%w: %v", ErrGitMissing, runErr)
	}
	version = strings.TrimSpace(string(out))
	if !GitVersionAtLeast(version, MinGitMajor, MinGitMinor) {
		return version, fmt.Errorf("%w: got %q, want >= %d.%d", ErrGitTooOld, version, MinGitMajor, MinGitMinor)
	}
	return version, nil
}
