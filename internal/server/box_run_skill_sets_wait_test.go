//go:build !containarium_client

package server

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3530: ApplyBoxSkillSets' wait for the per-box gate is bounded and honours
// the caller's cancellation, and an apply that only waits does not make runs
// fail with the "installing" refusal.

// holdFirstRunStart makes the first run start on s stop at its first user exec
// until release is closed; later execs pass straight through. It returns once
// the start is in flight.
func holdFirstRunStart(t *testing.T, s *ContainerServer, runName string) (release chan struct{}, started chan error) {
	t.Helper()
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
		_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Command: "sleep 5", RunName: runName})
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
	// Once the first apply returns, the gate is free and no apply is recorded.
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

// A run start that returns is no longer a holder, and its box leaves no empty
// entry behind.
func TestEnterBoxRunStart_ReleaseRemovesTheHolder(t *testing.T) {
	s, _, _ := skillSetServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	release, err := s.enterBoxRunStart("alice-container", "r1")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.boxRunStarts.names("alice-container"); len(got) != 1 || got[0] != "r1" {
		t.Fatalf("holders while held = %v, want [r1]", got)
	}
	release()
	if got := s.boxRunStarts.names("alice-container"); len(got) != 0 {
		t.Errorf("holders after release = %v, want none", got)
	}
	s.boxRunStarts.mu.Lock()
	defer s.boxRunStarts.mu.Unlock()
	if _, ok := s.boxRunStarts.byBox["alice-container"]; ok {
		t.Errorf("empty per-box holder map left behind")
	}
}
