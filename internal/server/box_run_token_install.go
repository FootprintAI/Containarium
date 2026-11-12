package server

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
			// The push can fail after the file was created or written.
			_, _, _, _ = mgr.ExecWithExitCode(box, []string{"rm", "-f", staged})
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

// runTokenMaxBytes caps a token the daemon will write into a box. A run token is
// a few hundred bytes; anything much larger is not one.
const runTokenMaxBytes = 8 << 10

// runTokenInstallTimeout bounds how long StartBoxRun waits for the install while
// it holds the run's lock. The install itself may finish later, after the start
// has failed. No run was spawned, so no exit or stop path would remove what it
// places: installRunToken removes it, as root, once that install finishes, and
// until then another start of the same run name is refused
// (refuseWhileRunTokenInstallPending).
var runTokenInstallTimeout = 30 * time.Second

// runTokenDiscardRetries are the waits before each further attempt to remove a
// run's token when a removal after a failed start did not succeed. The run
// name stays refused while they run; after the last one it is released either
// way, so a box that stays unreachable does not block the name forever.
var runTokenDiscardRetries = []time.Duration{time.Second, 5 * time.Second, 15 * time.Second}

// validateRunToken refuses a token that is too large, or that contains a byte
// a single-line consumer would split on. An empty token is valid (no token).
func validateRunToken(token string) error {
	if token == "" {
		return nil
	}
	if len(token) > runTokenMaxBytes {
		return fmt.Errorf("run_token is larger than %d bytes", runTokenMaxBytes)
	}
	if strings.ContainsAny(token, "\x00\r\n") {
		return fmt.Errorf("run_token contains a NUL or line break")
	}
	return nil
}

// installRunToken is the StartBoxRun hook: a run with no token installs nothing.
// The install is bounded by runTokenInstallTimeout and by the request context.
// Whenever it does not succeed, the run's token is removed as root, so a start
// that gave up never leaves one behind: at once after a failed install (it may
// have placed the token before it failed), and after the install has finished
// when the wait ended first.
func (s *ContainerServer) installRunToken(ctx context.Context, listExec boxScriptFunc, box, runAs, name, token string) error {
	if token == "" {
		return nil
	}
	install := s.boxRunTokenInstallFn()
	if install == nil {
		return fmt.Errorf("no container backend to install a run token")
	}
	done := make(chan error, 1)
	go func() { done <- install(box, runAs, name, token) }()
	timer := time.NewTimer(runTokenInstallTimeout)
	defer timer.Stop()
	var gaveUp error
	select {
	case err := <-done:
		if err != nil {
			s.discardRunTokenOrRetry(listExec, box, name, token)
		}
		return err
	case <-ctx.Done():
		gaveUp = ctx.Err()
	case <-timer.C:
		gaveUp = fmt.Errorf("the token install did not finish within %s", runTokenInstallTimeout)
	}
	// Marked while the caller still holds the run's lock, so the next start of
	// this name sees it.
	key := boxRunLockKey(box, name)
	s.boxRunTokenPending.Store(key, struct{}{})
	go func() {
		<-done
		if discardRunToken(listExec, box, name, token) != nil {
			retryRunTokenDiscard(listExec, box, name, token)
		}
		s.boxRunTokenPending.Delete(key)
	}()
	return gaveUp
}

// discardRunTokenOrRetry removes a run's token after a start that asked for its
// install failed. When that removal does not succeed, the run name is refused
// (refuseWhileRunTokenInstallPending) while it is retried in the background
// (runTokenDiscardRetries). The caller holds the run's lock.
func (s *ContainerServer) discardRunTokenOrRetry(listExec boxScriptFunc, box, name, token string) {
	if discardRunToken(listExec, box, name, token) == nil {
		return
	}
	key := boxRunLockKey(box, name)
	s.boxRunTokenPending.Store(key, struct{}{})
	go func() {
		retryRunTokenDiscard(listExec, box, name, token)
		s.boxRunTokenPending.Delete(key)
	}()
}

// retryRunTokenDiscard retries a failed token removal, waiting
// runTokenDiscardRetries between attempts, and logs when every attempt failed.
func retryRunTokenDiscard(listExec boxScriptFunc, box, name, token string) {
	var err error
	for _, wait := range runTokenDiscardRetries {
		time.Sleep(wait)
		if err = discardRunToken(listExec, box, name, token); err == nil {
			return
		}
	}
	log.Printf("[box-run] could not remove the token of run %q on %q after a failed start: %v; a tokenless start of this run name fails until the token is gone or the box restarts", name, box, err)
}

// refuseWhileRunTokenInstallPending refuses a start of a run name whose earlier
// start failed with its token install or removal still unfinished: the start
// gave up waiting for the install, or the removal after a failed start is
// being retried. The install may yet place its token, and the removal that
// follows it would then take the token of a run started in the meantime; a
// tokenless run's spawn would fail to remove a token the run user owns. The
// caller holds the run's lock.
func (s *ContainerServer) refuseWhileRunTokenInstallPending(box, name, username string) error {
	if _, pending := s.boxRunTokenPending.Load(boxRunLockKey(box, name)); pending {
		return status.Errorf(codes.Unavailable,
			"an earlier start of run %q on %q has not finished installing or removing its token; retry shortly", name, username)
	}
	return nil
}
