package server

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Where a run's token lives in the box. The directory is world-writable and
// sticky, like /tmp: the run user can create and remove its own token file but
// cannot touch another's. Nothing here is ever written through a path the run
// user controls: the token is written to a root-only staging directory, given
// to the run user, and renamed into place. mv replaces a symlink at the
// destination rather than following it.
const (
	boxRunTokenDir     = "/run/containarium/run-tokens"
	boxRunTokenStaging = "/run/containarium/token-staging"
)

// boxRunTokenPath is the file a run's engine and helper read, named by run.
func boxRunTokenPath(name string) string {
	return boxRunTokenDir + "/" + name + ".token"
}

// boxRunTokenPrepScript makes the two directories, as root, idempotently.
func boxRunTokenPrepScript() string {
	q := shellSingleQuote
	return "set -e\n" +
		"mkdir -p " + q(boxRunTokenDir) + " " + q(boxRunTokenStaging) + "\n" +
		"chmod 1777 " + q(boxRunTokenDir) + "\n" +
		"chmod 0700 " + q(boxRunTokenStaging) + "\n"
}

// boxRunTokenMoveScript hands a staged token to the run user and renames it
// into place, as root. It contains no token: the content travels by file push.
func boxRunTokenMoveScript(staged, runAs, name string) string {
	q := shellSingleQuote
	return "set -e\n" +
		"chown " + q(runAs) + ":" + q(runAs) + " " + q(staged) + "\n" +
		"chmod 0600 " + q(staged) + "\n" +
		"mv -fT " + q(staged) + " " + q(boxRunTokenPath(name)) + "\n"
}

// boxRunTokenInstallFunc installs one run's token into the box. The token
// travels as file content only, never in a command line.
type boxRunTokenInstallFunc func(box, runAs, name, token string) error

// boxRunTokenInstallFn is the production install: a root exec to prepare the
// directories, a file push of the token into staging, then a root exec to
// hand it over and rename it into place. The test seam is boxRunTokenInstall.
func (s *ContainerServer) boxRunTokenInstallFn() boxRunTokenInstallFunc {
	if s.boxRunTokenInstall != nil {
		return s.boxRunTokenInstall
	}
	if s.manager == nil {
		return nil
	}
	mgr := s.manager
	return func(box, runAs, name, token string) error {
		if _, stderr, code, err := mgr.ExecWithExitCode(box, []string{"sh", "-c", boxRunTokenPrepScript()}); err != nil || code != 0 {
			return fmt.Errorf("prepare token directories: exit %d: %s", code, strings.TrimSpace(stderr))
		}
		staged := boxRunTokenStaging + "/" + name + "." + uuid.NewString()
		if err := mgr.PushFile(box, staged, strings.NewReader(token), "0600"); err != nil {
			return fmt.Errorf("stage run token: %w", err)
		}
		if _, stderr, code, err := mgr.ExecWithExitCode(box, []string{"sh", "-c", boxRunTokenMoveScript(staged, runAs, name)}); err != nil || code != 0 {
			// Do not leave the staged copy behind: staging is root-only, but
			// nothing else would ever remove it.
			_, _, _, _ = mgr.ExecWithExitCode(box, []string{"rm", "-f", staged})
			return fmt.Errorf("place run token: exit %d: %s", code, strings.TrimSpace(stderr))
		}
		return nil
	}
}

// installRunToken is the StartBoxRun hook: a run with no token installs nothing.
func (s *ContainerServer) installRunToken(box, runAs, name, token string) error {
	if token == "" {
		return nil
	}
	install := s.boxRunTokenInstallFn()
	if install == nil {
		return fmt.Errorf("no container backend to install a run token")
	}
	return install(box, runAs, name, token)
}
