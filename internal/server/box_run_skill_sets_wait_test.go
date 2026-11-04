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
	if err := s.lockBoxSkillSetGate(context.Background(), "alice-container"); err != nil {
		t.Fatalf("gate still held after the refused apply: %v", err)
	}
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
