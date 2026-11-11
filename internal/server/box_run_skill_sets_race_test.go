//go:build !containarium_client

package server

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3510: ApplyBoxSkillSets' run-in-progress check and its install are not
// atomic on their own, so a run started while the installer is writing
// ~/.claude/skills would read (or stage a copy of) a half-written tree. A run
// start is refused while an apply is installing, with a typed
// APPLY_IN_PROGRESS naming the box, before the run touches the box at all; an
// apply that arrives while a run is starting waits for that start to finish
// and then sees the run, so it refuses with RUN_IN_PROGRESS.

// blockInstall makes s's install seam stop once it is entered, mid-install:
// it writes one skill of the bundle (the half-written tree), signals entered,
// and waits for release before running the real installer.
func blockInstall(t *testing.T, s *ContainerServer, home string) (entered, release chan struct{}) {
	t.Helper()
	inner := s.boxSkillSetsInstall
	entered, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.boxSkillSetsInstall = func(box, user, rel string, sets sdlcskills.SkillSets) (string, error) {
		writeSkill(t, home, "qa-half-written", "partial")
		once.Do(func() { close(entered) })
		<-release
		return inner(box, user, rel, sets)
	}
	return entered, release
}

// countBoxExecs counts every exec s makes on the box, root or as a user, while
// counting is on.
func countBoxExecs(s *ContainerServer) (on *atomic.Bool, n *atomic.Int64) {
	on, n = &atomic.Bool{}, &atomic.Int64{}
	root, user := s.boxRunExec, s.boxRunStartExec
	s.boxRunExec = func(box, script string) (string, error) {
		if on.Load() {
			n.Add(1)
		}
		return root(box, script)
	}
	s.boxRunStartExec = func(box, username, script string) (string, error) {
		if on.Load() {
			n.Add(1)
		}
		return user(box, username, script)
	}
	return on, n
}

func TestStartBoxRun_RefusedWhileASkillSetApplyIsInstalling(t *testing.T) {
	home := t.TempDir()
	s, _, _ := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
	entered, release := blockInstall(t, s, home)
	counting, execs := countBoxExecs(s)

	applied := make(chan error, 1)
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

	counting.Store(true)
	for _, tc := range []struct {
		name string
		req  *pb.StartBoxRunRequest
	}{
		{"an engine run", &pb.StartBoxRunRequest{Username: "alice", Prompt: "do the thing", RunName: "during-apply"}},
		{"a command run", &pb.StartBoxRunRequest{Username: "alice", Command: "ls ~/.claude/skills", RunName: "during-apply-cmd"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.StartBoxRun(tenantCtx("alice"), tc.req)
			reason, subject := skillSetRefusalOf(t, err)
			if status.Code(err) != codes.FailedPrecondition || reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_APPLY_IN_PROGRESS || subject != "alice-container" {
				t.Fatalf("err = %v (reason %v, subject %q), want FAILED_PRECONDITION APPLY_IN_PROGRESS on alice-container", err, reason, subject)
			}
			if msg := status.Convert(err).Message(); !strings.Contains(msg, "applying skill sets") {
				t.Errorf("message %q does not name the apply", msg)
			}
		})
	}
	counting.Store(false)
	if got := execs.Load(); got != 0 {
		t.Fatalf("a refused run made %d exec(s) on the box mid-install; it must not touch (or stage) the half-written skills tree", got)
	}

	close(release)
	if err := <-applied; err != nil {
		t.Fatalf("the apply itself must complete: %v", err)
	}
	// Once the apply has returned, a run starts as before.
	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Command: "true", RunName: "after-apply"}); err != nil {
		t.Fatalf("a run after the apply returned must start: %v", err)
	}
}

func TestApplyBoxSkillSets_WaitsForARunStartThenRefusesIt(t *testing.T) {
	home := t.TempDir()
	s, _, installs := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)

	// Hold the run's start at its first exec on the box, inside StartBoxRun.
	inStart, letStartGo := make(chan struct{}), make(chan struct{})
	var holding atomic.Bool
	holding.Store(true)
	var once sync.Once
	user := s.boxRunStartExec
	s.boxRunStartExec = func(box, username, script string) (string, error) {
		if holding.Load() {
			once.Do(func() { close(inStart) })
			<-letStartGo
		}
		return user(box, username, script)
	}

	started := make(chan error, 1)
	go func() {
		_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Command: "sleep 5", RunName: "starting"})
		started <- err
	}()
	select {
	case <-inStart:
	case err := <-started:
		t.Fatalf("run start returned before its first exec: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("run start never reached the box")
	}

	// The held start makes no exec of its own until released, so any exec
	// counted from here is the apply's: without the lock it would run its
	// run-in-progress check (a root exec) while the start is held.
	counting, execs := countBoxExecs(s)
	counting.Store(true)
	applied := make(chan error, 1)
	go func() {
		_, err := apply(t, s, "qa")
		applied <- err
	}()
	select {
	case err := <-applied:
		t.Fatalf("apply returned while a run was still starting: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if got := execs.Load(); got != 0 {
		t.Fatalf("apply made %d exec(s) on the box while a run was still starting; it must wait before touching the box", got)
	}
	if *installs != 0 {
		t.Fatal("apply installed while a run was still starting")
	}
	counting.Store(false)

	holding.Store(false)
	close(letStartGo)
	if err := <-started; err != nil {
		t.Fatalf("run start: %v", err)
	}
	err := <-applied
	reason, _ := skillSetRefusalOf(t, err)
	if status.Code(err) != codes.FailedPrecondition || reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS || !strings.Contains(status.Convert(err).Message(), `"starting"`) {
		t.Fatalf("err = %v, want RUN_IN_PROGRESS naming the run that just started", err)
	}
	if *installs != 0 {
		t.Errorf("installer ran %d times; the refused apply must change nothing", *installs)
	}
}
