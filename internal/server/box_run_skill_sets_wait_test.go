//go:build !containarium_client

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3530: ApplyBoxSkillSets' wait for the per-box gate is bounded and honours
// the caller's cancellation, and an apply that only waits does not make runs
// fail with the "installing" refusal.

// heldRunCommand is what the held start runs: it stays live until endFile
// exists, so an apply that reads run records right after the start returns
// still finds the run active however slow the machine is (#3557). The test
// creates the file when it ends; the run's own timeout bounds a leak.
func heldRunCommand(endFile string) string {
	return "while [ ! -e " + coderun.ShellQuoteSingle(endFile) + " ]; do sleep 0.05; done"
}

// settleDetachedRuns waits, at the end of the test, until every run recorded in
// logDir has written its exit sidecar. A started run is a setsid-detached
// process that keeps writing (tools probe, exit sidecar) into logDir after
// StartBoxRun returns, so without this the t.TempDir cleanup races it and fails
// with "directory not empty" (#3541). Register it after the server's TempDir
// exists: cleanups run last-in first-out, so it runs before that cleanup.
func settleDetachedRuns(t *testing.T, logDir string) {
	t.Helper()
	t.Cleanup(func() {
		deadline := time.Now().Add(30 * time.Second)
		for {
			records, _ := filepath.Glob(filepath.Join(logDir, "*.json"))
			pending := 0
			for _, r := range records {
				if _, err := os.Stat(strings.TrimSuffix(r, ".json") + ".exit"); err != nil {
					pending++
				}
			}
			if pending == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d detached run(s) still had not exited after 30s", pending)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

// holdFirstRunStart makes the first run start on s stop at its first user exec
// until release is closed; later execs pass straight through. It returns once
// the start is in flight. The run that start launches stays active until the
// test ends (heldRunCommand).
func holdFirstRunStart(t *testing.T, s *ContainerServer, runName string) (release chan struct{}, started chan error) {
	t.Helper()
	settleDetachedRuns(t, s.boxRunLogDir)
	// Registered after settleDetachedRuns, so it runs first: the held run
	// exits, then the settle wait sees its exit sidecar.
	endRun := filepath.Join(t.TempDir(), "end-held-run")
	t.Cleanup(func() {
		if err := os.WriteFile(endRun, nil, 0o600); err != nil {
			t.Errorf("end the held run: %v", err)
		}
	})
	inStart, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	user := s.boxRunStartExec
	s.boxRunStartExec = func(box, username, script string) (string, error) {
		held := false
		once.Do(func() { held = true; close(inStart) })
		if held {
			<-release
		}
		return user(box, username, script)
	}
	started = make(chan error, 1)
	go func() {
		_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Command: heldRunCommand(endRun), RunName: runName})
		started <- err
	}()
	select {
	case <-inStart:
	case err := <-started:
		t.Fatalf("run start returned before its first exec: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("run start never reached the box")
	}
	return release, started
}

func shortGateWait(t *testing.T, wait time.Duration) {
	t.Helper()
	oldWait, oldPoll := boxSkillSetsGateWait, boxSkillSetsGatePoll
	boxSkillSetsGateWait, boxSkillSetsGatePoll = wait, 5*time.Millisecond
	t.Cleanup(func() { boxSkillSetsGateWait, boxSkillSetsGatePoll = oldWait, oldPoll })
}

func TestApplyBoxSkillSets_RefusesAHeldRunStartPastTheCap(t *testing.T) {
	shortGateWait(t, 100*time.Millisecond)
	s, _, installs := skillSetServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	release, started := holdFirstRunStart(t, s, "stuck-start")

	begin := time.Now()
	_, err := apply(t, s, "qa")
	reason, subject := skillSetRefusalOf(t, err)
	if status.Code(err) != codes.FailedPrecondition || reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS || subject != "alice-container" {
		t.Fatalf("err = %v (reason %v, subject %q), want FAILED_PRECONDITION RUN_IN_PROGRESS on alice-container", err, reason, subject)
	}
	if msg := status.Convert(err).Message(); !strings.Contains(msg, `"stuck-start"`) {
		t.Errorf("message %q does not name the run start holding the gate", msg)
	}
	if d := time.Since(begin); d < 100*time.Millisecond || d > 5*time.Second {
		t.Errorf("apply took %v, want about the 100ms cap", d)
	}
	if *installs != 0 {
		t.Errorf("installer ran %d times; the refused apply must change nothing", *installs)
	}
	close(release)
	if err := <-started; err != nil {
		t.Fatalf("the held run start must complete: %v", err)
	}
	// The refused apply did not leak the gate.
	unlock, err := s.lockBoxSkillSetGate(context.Background(), "alice-container")
	if err != nil {
		t.Fatalf("gate still held after the refused apply: %v", err)
	}
	unlock()
}

func TestApplyBoxSkillSets_StopsWaitingWhenTheContextIsCancelled(t *testing.T) {
	shortGateWait(t, time.Minute)
	s, _, installs := skillSetServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	release, started := holdFirstRunStart(t, s, "stuck-start")

	ctx, cancel := context.WithCancel(tenantCtx("alice"))
	applied := make(chan error, 1)
	go func() {
		_, err := s.ApplyBoxSkillSets(ctx, &pb.ApplyBoxSkillSetsRequest{Username: "alice", SkillSets: []string{"qa"}, Release: "v9.9.9"})
		applied <- err
	}()
	select {
	case err := <-applied:
		t.Fatalf("apply returned while the start was held and its context live: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-applied:
		if status.Code(err) != codes.Canceled {
			t.Fatalf("err = %v, want CANCELED", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("apply kept waiting after its context was cancelled")
	}
	close(release)
	if err := <-started; err != nil {
		t.Fatalf("run start: %v", err)
	}
	if *installs != 0 {
		t.Errorf("installer ran %d times after the caller gave up", *installs)
	}
}

func TestStartBoxRun_NotRefusedWhileAnApplyOnlyWaits(t *testing.T) {
	shortGateWait(t, time.Minute)
	s, _, installs := skillSetServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	release, started := holdFirstRunStart(t, s, "first-start")

	applied := make(chan error, 1)
	go func() {
		_, err := apply(t, s, "qa")
		applied <- err
	}()
	select {
	case err := <-applied:
		t.Fatalf("apply returned while a start was held: %v", err)
	case <-time.After(150 * time.Millisecond): // the apply is queued on the gate
	}

	_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Command: "true", RunName: "second-start"})
	if err != nil {
		if status.Code(err) == codes.FailedPrecondition && strings.Contains(status.Convert(err).Message(), "applying skill sets") {
			t.Fatalf("a run was refused as if an apply were installing while it only waits: %v", err)
		}
		t.Fatalf("second run start: %v", err)
	}
	close(release)
	if err := <-started; err != nil {
		t.Fatalf("first run start: %v", err)
	}
	reason, _ := skillSetRefusalOf(t, <-applied)
	if reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS {
		t.Errorf("reason = %v, want RUN_IN_PROGRESS", reason)
	}
	if *installs != 0 {
		t.Errorf("installer ran %d times", *installs)
	}
}

// #3537: an apply that cannot take the gate because ANOTHER APPLY holds it is
// refused as APPLY_IN_PROGRESS, not as a run start that never finished.
func TestApplyBoxSkillSets_RefusesAsApplyInProgressWhileAnotherApplyHoldsTheGate(t *testing.T) {
	shortGateWait(t, 100*time.Millisecond)
	s, _, _ := skillSetServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	inInstall, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	realInstall := s.boxSkillSetsInstall
	s.boxSkillSetsInstall = func(box, user, rel string, sets sdlcskills.SkillSets) (string, error) {
		once.Do(func() { close(inInstall) })
		<-release
		return realInstall(box, user, rel, sets)
	}
	first := make(chan error, 1)
	go func() {
		_, err := apply(t, s, "qa")
		first <- err
	}()
	select {
	case <-inInstall:
	case err := <-first:
		t.Fatalf("first apply returned before its install: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("first apply never reached its install")
	}

	_, err := apply(t, s, "qa")
	reason, subject := skillSetRefusalOf(t, err)
	if status.Code(err) != codes.FailedPrecondition || reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_APPLY_IN_PROGRESS || subject != "alice-container" {
		t.Fatalf("err = %v (reason %v, subject %q), want FAILED_PRECONDITION APPLY_IN_PROGRESS on alice-container", err, reason, subject)
	}
	if msg := status.Convert(err).Message(); strings.Contains(msg, "()") || strings.Contains(msg, "run start") {
		t.Errorf("message %q talks about run starts although none is involved", msg)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// Once the first apply returns, the gate is free and no apply is recorded:
	// a stale flag would make every later cap refusal say APPLY_IN_PROGRESS.
	if s.boxGateHolders.applyHeld("alice-container") {
		t.Error("apply flag still set after the first apply returned")
	}
	unlock, err := s.lockBoxSkillSetGate(context.Background(), "alice-container")
	if err != nil {
		t.Fatalf("gate still held after both applies: %v", err)
	}
	unlock()
}

// The cap message does not claim the named starts "did not finish" and never
// prints an empty parenthesis.
func TestApplyBoxSkillSets_CapMessageIsTruthfulAboutRunStarts(t *testing.T) {
	shortGateWait(t, 100*time.Millisecond)
	s, _, _ := skillSetServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	release, started := holdFirstRunStart(t, s, "stuck-start")
	_, err := apply(t, s, "qa")
	msg := status.Convert(err).Message()
	if strings.Contains(msg, "did not finish") || strings.Contains(msg, "()") {
		t.Errorf("message %q makes a claim the holder snapshot cannot support", msg)
	}
	if !strings.Contains(msg, `"stuck-start"`) {
		t.Errorf("message %q does not name the start still in flight", msg)
	}
	close(release)
	<-started
}

// #3541: when the gate is held by something that is not a recorded run start
// (here: its read side taken directly), the cap message names no starts and
// must not print an empty list.
func TestApplyBoxSkillSets_CapMessageWithNoRecordedHolderNamesNoStarts(t *testing.T) {
	shortGateWait(t, 100*time.Millisecond)
	s, _, installs := skillSetServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	gate := s.boxSkillSetGate("alice-container")
	gate.RLock()
	defer gate.RUnlock()

	_, err := apply(t, s, "qa")
	reason, _ := skillSetRefusalOf(t, err)
	if status.Code(err) != codes.FailedPrecondition || reason != pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS {
		t.Fatalf("err = %v (reason %v), want FAILED_PRECONDITION RUN_IN_PROGRESS", err, reason)
	}
	msg := status.Convert(err).Message()
	if strings.Contains(msg, "now:") || strings.Contains(msg, "()") || strings.Contains(msg, ": .") {
		t.Errorf("message %q prints an empty holder list", msg)
	}
	if !strings.Contains(msg, "No run start is recorded in flight") {
		t.Errorf("message %q does not say no run start is recorded", msg)
	}
	// #3557: an apply can hold the gate unrecorded for an instant too, so the
	// message must not promise that a retry finds the box free.
	if strings.Contains(msg, "should find it free") {
		t.Errorf("message %q promises a free box on retry", msg)
	}
	if *installs != 0 {
		t.Errorf("installer ran %d times; the refused apply must change nothing", *installs)
	}
}

// #3541: a holder that released between the last poll and the cap must not get
// the apply refused. The poll interval is longer than the cap, so only the
// final TryLock at the cap can see the gate free.
func TestApplyBoxSkillSets_TakesTheGateIfItIsFreeWhenTheCapFires(t *testing.T) {
	shortGateWait(t, 200*time.Millisecond)
	boxSkillSetsGatePoll = time.Hour // set after shortGateWait; its cleanup restores it
	s, _, installs := skillSetServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	gate := s.boxSkillSetGate("alice-container")
	gate.RLock()
	go func() {
		time.Sleep(50 * time.Millisecond)
		gate.RUnlock()
	}()

	if _, err := apply(t, s, "qa"); err != nil {
		t.Fatalf("apply refused although the gate was free when the cap fired: %v", err)
	}
	if *installs != 1 {
		t.Errorf("installer ran %d times, want 1", *installs)
	}
}

// A run start that returns is no longer a holder, and its box leaves no empty
// entry behind.
func TestEnterBoxRunStart_ReleaseRemovesTheHolder(t *testing.T) {
	s, _, _ := skillSetServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	release, err := s.enterBoxRunStart("alice-container", "r1")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.boxGateHolders.names("alice-container"); len(got) != 1 || got[0] != "r1" {
		t.Fatalf("holders while held = %v, want [r1]", got)
	}
	release()
	if got := s.boxGateHolders.names("alice-container"); len(got) != 0 {
		t.Errorf("holders after release = %v, want none", got)
	}
	s.boxGateHolders.mu.Lock()
	defer s.boxGateHolders.mu.Unlock()
	if _, ok := s.boxGateHolders.byBox["alice-container"]; ok {
		t.Errorf("empty per-box holder map left behind")
	}
}
