package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tokenFile is the run's token file in a fake box (#3622): an install places
// it, a root removal of the run's own token path takes it away, and a run as
// the box owner cannot remove it (it belongs to the run user in a sticky
// directory), so a tokenless spawn's `rm -f` of it fails under `set -e`.
type tokenFile struct {
	mu       sync.Mutex
	placed   bool
	removals int
	removed  chan struct{} // closed by the first root removal
}

func newTokenFile() *tokenFile { return &tokenFile{removed: make(chan struct{})} }

func (f *tokenFile) place() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.placed = true
}

func (f *tokenFile) state() (placed bool, removals int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.placed, f.removals
}

// wire puts the fake file behind s's exec seams.
func (f *tokenFile) wire(t *testing.T, s *ContainerServer, name string) {
	t.Helper()
	removal := "rm -f " + shellSingleQuote(boxRunTokenPath(name)) + "\n"
	innerRoot, innerUser := s.boxRunExec, s.boxRunStartExec
	s.boxRunExec = func(box, script string) (string, error) {
		if script == removal {
			f.mu.Lock()
			f.placed = false
			f.removals++
			if f.removals == 1 {
				close(f.removed)
			}
			f.mu.Unlock()
			return "", nil
		}
		return innerRoot(box, script)
	}
	s.boxRunStartExec = func(box, username, script string) (string, error) {
		if strings.Contains(script, removal) {
			if placed, _ := f.state(); placed {
				return "", errors.New("exit 1: rm: cannot remove '" + boxRunTokenPath(name) + "': Operation not permitted")
			}
		}
		return innerUser(box, username, script)
	}
}

// waitRemoved waits for the root removal the start owes once its install has
// finished.
func (f *tokenFile) waitRemoved(t *testing.T) {
	t.Helper()
	select {
	case <-f.removed:
	case <-time.After(5 * time.Second):
		t.Fatal("the token was never removed after the install finished")
	}
}

// waitNotPending waits until s no longer refuses a start of (box, name).
func waitNotPending(t *testing.T, s *ContainerServer, box, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, pending := s.boxRunTokenPending.Load(boxRunLockKey(box, name)); !pending {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the run name stayed refused after its install finished and its token was removed")
		}
		time.Sleep(time.Millisecond)
	}
}

// A start whose token install fails removes the run's token as root, even when
// the install placed it before failing (the rename went through, its exec
// reported an error). Afterwards a tokenless run as the box owner under the same
// name starts normally: its spawn's `rm -f` finds nothing it cannot remove.
func TestStartBoxRun_FailedTokenInstallRemovesTheToken(t *testing.T) {
	for mode, base := range tokenRunModes() {
		t.Run(mode, func(t *testing.T) {
			s, r := newTokenRunServer(t, "none")
			f := newTokenFile()
			f.wire(t, s, "r1")
			s.boxRunTokenInstall = func(string, string, string, string) error {
				f.place()
				return errors.New("place run token: exit 1: transport closed")
			}
			req := base
			req.RunToken = testBoxRunToken
			_, err := s.StartBoxRun(adminCtx(), req)
			if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "install run token") {
				t.Fatalf("err = %v, want Unavailable from the failed install", err)
			}
			if sp := r.spawnScript(); sp != "" {
				t.Fatalf("a start whose install failed was spawned:\n%s", sp)
			}
			if placed, removals := f.state(); placed || removals != 1 {
				t.Fatalf("after the failed install: token placed = %v, root removals = %d; want removed once", placed, removals)
			}
			if _, pending := s.boxRunTokenPending.Load(boxRunLockKey("alice-container", "r1")); pending {
				t.Error("a failed install, which has finished, left the run name refused")
			}

			s.boxRunToolAccess = func(context.Context, string) (string, error) { return "", nil }
			req.RunToken = ""
			if _, err := s.StartBoxRun(adminCtx(), req); err != nil {
				t.Fatalf("a tokenless owner run under the same name failed: %v", err)
			}
			if r.spawnScript() == "" {
				t.Fatal("the owner run was never spawned")
			}
		})
	}
}

// A start that stops waiting for a slow install (the timeout) fails without
// spawning; the install, finishing after StartBoxRun returned, leaves no token
// once it is done. Until then another start of the same name is refused, so the
// removal cannot take the token of a run started in the meantime; afterwards a
// tokenless owner run under that name starts normally.
func TestStartBoxRun_LateTokenInstallIsRemovedOnceItFinishes(t *testing.T) {
	old := runTokenInstallTimeout
	runTokenInstallTimeout = 20 * time.Millisecond
	defer func() { runTokenInstallTimeout = old }()
	for mode, base := range tokenRunModes() {
		t.Run(mode, func(t *testing.T) {
			s, r := newTokenRunServer(t, "none")
			f := newTokenFile()
			f.wire(t, s, "r1")
			release := make(chan struct{})
			s.boxRunTokenInstall = func(string, string, string, string) error {
				<-release
				f.place()
				return nil
			}
			req := base
			req.RunToken = testBoxRunToken
			_, err := s.StartBoxRun(adminCtx(), req)
			if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "did not finish") {
				close(release)
				t.Fatalf("err = %v, want Unavailable from the install timeout", err)
			}
			if sp := r.spawnScript(); sp != "" {
				close(release)
				t.Fatalf("a start that gave up on its install was spawned:\n%s", sp)
			}

			// The install is still in flight: the same name is refused, and
			// nothing is installed for the second start.
			s.boxRunTokenInstall = func(string, string, string, string) error {
				t.Error("a start of a name with an install still in flight installed a token")
				return nil
			}
			_, err = s.StartBoxRun(adminCtx(), req)
			if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "still finishing") {
				close(release)
				t.Fatalf("second start err = %v, want Unavailable while the first install is in flight", err)
			}

			close(release)
			f.waitRemoved(t)
			waitNotPending(t, s, "alice-container", "r1")
			if placed, removals := f.state(); placed || removals != 1 {
				t.Fatalf("after the late install finished: token placed = %v, root removals = %d; want removed once", placed, removals)
			}

			s.boxRunToolAccess = func(context.Context, string) (string, error) { return "", nil }
			req.RunToken = ""
			if _, err := s.StartBoxRun(adminCtx(), req); err != nil {
				t.Fatalf("a tokenless owner run under the same name failed: %v", err)
			}
		})
	}
}

// A cancelled request stops the wait at once; the install, finishing later,
// leaves no token: its removal runs as root once it is done, never before.
func TestInstallRunToken_CancelledInstallIsRemovedOnceItFinishes(t *testing.T) {
	release := make(chan struct{})
	finished := make(chan struct{})
	s := &ContainerServer{boxRunTokenInstall: func(string, string, string, string) error {
		<-release
		close(finished)
		return nil
	}}
	removal := "rm -f " + shellSingleQuote(boxRunTokenPath("r1")) + "\n"
	removed := make(chan string, 1)
	root := func(box, script string) (string, error) {
		select {
		case <-finished:
		default:
			t.Error("the token was removed while its install was still running")
		}
		removed <- box + "|" + script
		return "", nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.installRunToken(ctx, root, "box1", "ctn-run", "r1", "tok"); !errors.Is(err, context.Canceled) {
		close(release)
		t.Fatalf("cancelled install returned %v, want context.Canceled", err)
	}
	if err := s.refuseWhileRunTokenInstallPending("box1", "r1", "alice"); status.Code(err) != codes.Unavailable {
		close(release)
		t.Fatalf("a start of the name while its install is in flight returned %v, want Unavailable", err)
	}
	close(release)
	select {
	case got := <-removed:
		if got != "box1|"+removal {
			t.Errorf("root removal = %q, want the run's own token path on its box", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the token was never removed after the cancelled install finished")
	}
	waitNotPending(t, s, "box1", "r1")
	if err := s.refuseWhileRunTokenInstallPending("box1", "r1", "alice"); err != nil {
		t.Errorf("the name is still refused after the install finished: %v", err)
	}
}
