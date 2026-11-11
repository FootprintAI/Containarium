//go:build !containarium_client

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3529: a run started over SSH (`containarium code run`, the MCP code_run
// tool) never reaches the daemon's gate, so the apply holds a marker in the
// box owner's tree that the SSH run path reads before launching. These tests
// run that path's own check (coderun.GuardSkillSetsApply, what
// Session.ProcessStart calls before process_start) through a stand-in for
// agent-box's shell_exec as the box owner: the local sh against the same temp
// home the apply writes to.

// ownerShell runs a command as agent-box's shell_exec would for the box
// owner whose home is home, answering in shell_exec's framing.
func ownerShell(home string) func(context.Context, string) (string, error) {
	return func(_ context.Context, command string) (string, error) {
		cmd := osexec.Command("sh", "-c", command)
		cmd.Env = append(os.Environ(), "HOME="+home)
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		code := 0
		if err := cmd.Run(); err != nil {
			code = 1
			if ee, ok := err.(*osexec.ExitError); ok {
				code = ee.ExitCode()
			}
		}
		return fmt.Sprintf("exit_code: %d\ntimeout_seconds: 30\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout.String(), stderr.String()), nil
	}
}

func applyMarkerPath(home string) string {
	return filepath.Join(home, ".claude", "skills", sdlcskills.ApplyMarkerFile)
}

func readApplyMarker(t *testing.T, home string) sdlcskills.ApplyMarker {
	t.Helper()
	data, err := os.ReadFile(applyMarkerPath(home))
	if err != nil {
		t.Fatalf("read the apply marker: %v", err)
	}
	var m sdlcskills.ApplyMarker
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("apply marker %q: %v", data, err)
	}
	return m
}

func startBlockedApply(t *testing.T, s *ContainerServer, home string) (release chan struct{}, applied chan error) {
	t.Helper()
	entered, release := blockInstall(t, s, home)
	applied = make(chan error, 1)
	go func() {
		_, err := apply(t, s, "qa")
		applied <- err
	}()
	select {
	case <-entered:
	case err := <-applied:
		t.Fatalf("apply returned before reaching the install: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("apply never reached the install")
	}
	return release, applied
}

func TestSSHPathRun_RefusedWhileASkillSetApplyIsInstalling(t *testing.T) {
	home := t.TempDir()
	s, _, _ := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
	release, applied := startBlockedApply(t, s, home)

	_, err := coderun.GuardSkillSetsApply(context.Background(), ownerShell(home))
	if !errors.Is(err, coderun.ErrSkillSetsApplyInProgress) {
		close(release)
		<-applied
		t.Fatalf("an SSH-path run started mid-install: err = %v, want ErrSkillSetsApplyInProgress", err)
	}
	if !strings.Contains(err.Error(), "ApplyBoxSkillSets") {
		t.Errorf("refusal %q does not name the apply", err)
	}

	close(release)
	if err := <-applied; err != nil {
		t.Fatalf("the apply itself must complete: %v", err)
	}
	// Once the apply has returned, an SSH-path run starts as before.
	warning, err := coderun.GuardSkillSetsApply(context.Background(), ownerShell(home))
	if err != nil || warning != "" {
		t.Fatalf("a run after the apply: err = %v, warning = %q; want a plain start", err, warning)
	}
	if _, err := os.Stat(applyMarkerPath(home)); !os.IsNotExist(err) {
		t.Fatalf("the marker must be gone once the apply returned: stat err = %v", err)
	}
}

func TestApplyBoxSkillSets_RemovesTheMarkerOnFailureAndPanic(t *testing.T) {
	for _, tc := range []struct {
		name    string
		install func()
	}{
		{"install fails", nil},
		{"install panics", func() { panic("installer seam panicked") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			s, _, _ := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
			sawMarker := false
			s.boxSkillSetsInstall = func(_, _, _ string, _ sdlcskills.SkillSets) (string, error) {
				_, err := os.Stat(applyMarkerPath(home))
				sawMarker = err == nil
				if tc.install != nil {
					tc.install()
				}
				return "", errors.New("download failed")
			}
			func() {
				defer func() { _ = recover() }()
				if _, err := apply(t, s, "qa"); err == nil {
					t.Error("a failed install must fail the apply")
				}
			}()
			if !sawMarker {
				t.Fatal("the marker was not held while the installer ran")
			}
			if _, err := os.Stat(applyMarkerPath(home)); !os.IsNotExist(err) {
				t.Fatalf("the marker must be removed when the apply ends this way: stat err = %v", err)
			}
		})
	}
}

func TestApplyBoxSkillSets_RenewsTheMarkerWhileInstalling(t *testing.T) {
	home := t.TempDir()
	s, _, _ := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
	s.skillSetsApplyLease = 2 * time.Second
	release, applied := startBlockedApply(t, s, home)
	defer func() {
		close(release)
		<-applied
	}()
	first := readApplyMarker(t, home)

	// Longer than the lease: only a renewal keeps the marker held.
	time.Sleep(3500 * time.Millisecond)
	if _, err := coderun.GuardSkillSetsApply(context.Background(), ownerShell(home)); !errors.Is(err, coderun.ErrSkillSetsApplyInProgress) {
		t.Fatalf("a run past the first lease of a still-running apply: err = %v, want ErrSkillSetsApplyInProgress", err)
	}
	if now := readApplyMarker(t, home); now.ExpiresAt <= first.ExpiresAt || now.StartedAt != first.StartedAt {
		t.Fatalf("marker not renewed: first %+v, now %+v", first, now)
	}
}

// A crashed apply stops renewing and never removes the marker: here the
// marker is taken exactly as an apply takes it, then abandoned.
func TestSkillSetsApplyMarker_ACrashedApplyLapses(t *testing.T) {
	home := t.TempDir()
	if out, err := ownerShell(home)(context.Background(), sdlcskills.ApplyMarkerWriteScript(0, 2*time.Second)); err != nil || !strings.HasPrefix(out, "exit_code: 0\n") {
		t.Fatalf("take the marker: %v %s", err, out)
	}
	if _, err := coderun.GuardSkillSetsApply(context.Background(), ownerShell(home)); !errors.Is(err, coderun.ErrSkillSetsApplyInProgress) {
		t.Fatalf("a fresh marker must refuse: err = %v", err)
	}
	// Whole box-clock seconds: written at T with expiry T+2, so held when checked
	// within the next second, and lapsed at any T+3 or later.
	time.Sleep(3100 * time.Millisecond)
	warning, err := coderun.GuardSkillSetsApply(context.Background(), ownerShell(home))
	if err != nil {
		t.Fatalf("a lapsed marker must not refuse the run: %v", err)
	}
	if !strings.Contains(warning, "lease lapsed") {
		t.Errorf("warning %q does not say the marker was stale", warning)
	}
	if _, err := os.Stat(applyMarkerPath(home)); !os.IsNotExist(err) {
		t.Fatalf("a lapsed marker must be cleared: stat err = %v", err)
	}
}

// release waits for a renewal already in flight before it removes the
// marker, so a renewal can never write the marker back after its removal and
// leave a returned apply holding it for a whole lease.
func TestApplyBoxSkillSets_NoRenewalAfterTheMarkerIsRemoved(t *testing.T) {
	home := t.TempDir()
	s, _, _ := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
	s.skillSetsApplyLease = 3 * time.Second // a renewal every second

	renewing, letRenew, renewed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	user := s.boxRunStartExec
	s.boxRunStartExec = func(box, username, script string) (string, error) {
		// The first write takes the start from the clock; a renewal carries it.
		isRenewal := strings.Contains(script, sdlcskills.ApplyMarkerFile) && strings.Contains(script, "expires_at") && !strings.Contains(script, `start="$now"`)
		first := false
		if isRenewal {
			once.Do(func() { first = true })
		}
		if !first {
			return user(box, username, script)
		}
		close(renewing)
		<-letRenew
		defer close(renewed)
		return user(box, username, script)
	}
	// The install ends while the first renewal is in flight.
	inner := s.boxSkillSetsInstall
	s.boxSkillSetsInstall = func(box, user, rel string, sets sdlcskills.SkillSets) (string, error) {
		select {
		case <-renewing:
		case <-time.After(10 * time.Second):
			return "", errors.New("no renewal within 10s")
		}
		return inner(box, user, rel, sets)
	}

	applied := make(chan error, 1)
	go func() {
		_, err := apply(t, s, "qa")
		applied <- err
	}()
	select {
	case <-renewing:
	case <-time.After(10 * time.Second):
		t.Fatal("no renewal within 10s")
	}
	// The renewal goes on once the apply has reached its release.
	time.AfterFunc(500*time.Millisecond, func() { close(letRenew) })
	if err := <-applied; err != nil {
		t.Fatalf("apply: %v", err)
	}
	select {
	case <-renewed:
	case <-time.After(10 * time.Second):
		t.Fatal("the renewal never finished")
	}
	if _, err := os.Stat(applyMarkerPath(home)); !os.IsNotExist(err) {
		t.Fatalf("a renewal wrote the marker back after the apply removed it: stat err = %v", err)
	}
}
