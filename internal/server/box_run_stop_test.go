//go:build !containarium_client

package server

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// stopTestUser is the OS user the tests run as: StopBoxRun refuses to signal a
// process the box user does not own, and the test processes belong to us.
func stopTestUser(t *testing.T) string {
	t.Helper()
	hostBootID(t) // skips where there is no /proc
	u, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	return u.Username
}

// newFakeEngine is a fake ~/.local/bin/claude running body.
func newFakeEngine(t *testing.T, body string) *fakeBoxUser {
	t.Helper()
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return &fakeBoxUser{home: home}
}

// startLongRun starts a run whose fake engine runs body. A body containing the token
// {{READY}} says where the engine marks itself ready (after any trap it installs); the
// helper then waits for that mark, because the run wrapper probes the toolchain before
// it starts the engine and a stop that lands first would kill the wrapper before the
// engine exists.
func startLongRun(t *testing.T, body string) (*ContainerServer, string, *pb.BoxRun) {
	t.Helper()
	owner := stopTestUser(t)
	ready := filepath.Join(t.TempDir(), "engine-ready")
	body = strings.ReplaceAll(body, "{{READY}}", "touch '"+ready+"'")
	s, _, _ := boxRunStartServer(t, newFakeEngine(t, body))
	resp, err := s.StartBoxRun(tenantCtx(owner), &pb.StartBoxRunRequest{Username: owner, Prompt: "work"})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if strings.Contains(body, ready) {
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the fake engine never reported ready")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Cleanup(func() {
		// Never leave a sleeping run behind if a test failed early.
		_, _ = s.StopBoxRun(tenantCtx(owner), &pb.StopBoxRunRequest{Username: owner, RunName: resp.GetRun().GetRunName(), Force: true})
	})
	return s, owner, resp.GetRun()
}

func TestStopBoxRun_StopsARunningRun_AndIsIdempotent(t *testing.T) {
	s, owner, run := startLongRun(t, "sleep 60")

	resp, err := s.StopBoxRun(tenantCtx(owner), &pb.StopBoxRunRequest{Username: owner, RunName: run.GetRunName()})
	if err != nil {
		t.Fatalf("StopBoxRun: %v", err)
	}
	if resp.GetSignal() != pb.BoxRunStopSignal_BOX_RUN_STOP_SIGNAL_SIGTERM || !resp.GetExited() {
		t.Fatalf("signal=%v exited=%v, want SIGTERM and exited", resp.GetSignal(), resp.GetExited())
	}
	if got := resp.GetRun().GetOutcome(); got != pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED {
		t.Errorf("outcome = %v, want EXITED (the stop leaves the exit sidecar the killed wrapper could not)", got)
	}
	if resp.GetRun().ExitCode == nil || resp.GetRun().GetExitCode() != 143 {
		t.Errorf("exit_code = %v, want 143", resp.GetRun().ExitCode)
	}

	again, err := s.StopBoxRun(tenantCtx(owner), &pb.StopBoxRunRequest{Username: owner, RunName: run.GetRunName()})
	if err != nil {
		t.Fatalf("second StopBoxRun: %v", err)
	}
	if again.GetSignal() != pb.BoxRunStopSignal_BOX_RUN_STOP_SIGNAL_NONE || !again.GetExited() {
		t.Errorf("second stop signal=%v exited=%v, want NONE and exited (idempotent)", again.GetSignal(), again.GetExited())
	}
}

func TestStopBoxRun_ForceKillsARunThatIgnoresSIGTERM(t *testing.T) {
	s, owner, run := startLongRun(t, "trap '' TERM\n{{READY}}\nwhile :; do sleep 1; done")

	soft, err := s.StopBoxRun(tenantCtx(owner), &pb.StopBoxRunRequest{Username: owner, RunName: run.GetRunName()})
	if err != nil {
		t.Fatalf("StopBoxRun: %v", err)
	}
	if soft.GetExited() {
		t.Fatalf("a run ignoring SIGTERM was reported exited")
	}
	if soft.GetRun().GetOutcome() == pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED {
		t.Errorf("a run whose engine is still going was reported EXITED")
	}

	hard, err := s.StopBoxRun(tenantCtx(owner), &pb.StopBoxRunRequest{Username: owner, RunName: run.GetRunName(), Force: true})
	if err != nil {
		t.Fatalf("forced StopBoxRun: %v", err)
	}
	if hard.GetSignal() != pb.BoxRunStopSignal_BOX_RUN_STOP_SIGNAL_SIGKILL || !hard.GetExited() {
		t.Fatalf("signal=%v exited=%v, want SIGKILL and exited", hard.GetSignal(), hard.GetExited())
	}
	if hard.GetRun().GetExitCode() != 137 {
		t.Errorf("exit_code = %v, want 137", hard.GetRun().GetExitCode())
	}
}

func TestStopBoxRun_AnAlreadyFinishedRunIsNotSignaled(t *testing.T) {
	owner := stopTestUser(t)
	b := &shBox{}
	s, dir := boxRunServer(t, b)
	writeRecord(t, dir, recordSpec{name: "done", pid: os.Getpid(), boot: hostBootID(t), started: time.Now(), exitCode: exitWith(0)})

	resp, err := s.StopBoxRun(adminCtx(), &pb.StopBoxRunRequest{Username: owner, RunName: "done"})
	if err != nil {
		t.Fatalf("StopBoxRun: %v", err)
	}
	if resp.GetSignal() != pb.BoxRunStopSignal_BOX_RUN_STOP_SIGNAL_NONE || !resp.GetExited() {
		t.Errorf("signal=%v exited=%v, want NONE and exited", resp.GetSignal(), resp.GetExited())
	}
	if err := syscall.Kill(os.Getpid(), 0); err != nil {
		t.Fatalf("the test process was signaled: %v", err)
	}
}

func TestStopBoxRun_RefusesAnUnknownOutcome_NeverSignals(t *testing.T) {
	owner := stopTestUser(t)
	b := &shBox{}
	s, dir := boxRunServer(t, b)
	// A record from another boot: its PID may now belong to anything.
	writeRecord(t, dir, recordSpec{name: "old", pid: os.Getpid(), boot: "00000000-0000-0000-0000-000000000000", started: time.Now()})

	_, err := s.StopBoxRun(adminCtx(), &pb.StopBoxRunRequest{Username: owner, RunName: "old", Force: true})

	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	if err := syscall.Kill(os.Getpid(), 0); err != nil {
		t.Fatalf("the test process was signaled: %v", err)
	}
}

func TestStopBoxRun_RefusesAProcessTheBoxUserDoesNotOwn(t *testing.T) {
	owner := stopTestUser(t)
	b := &shBox{}
	s, dir := boxRunServer(t, b)
	// A forged record naming PID 1 on this boot: the box user can write it.
	writeRecord(t, dir, recordSpec{name: "forged", pid: 1, boot: hostBootID(t), started: time.Now()})

	_, err := s.StopBoxRun(adminCtx(), &pb.StopBoxRunRequest{Username: owner, RunName: "forged", Force: true})

	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

func TestStopBoxRun_NotFoundValidationAndAuthz(t *testing.T) {
	boot := hostBootID(t)
	b := &shBox{}
	s, dir := boxRunServer(t, b)
	writeRecord(t, dir, recordSpec{name: "task", pid: os.Getpid(), boot: boot, started: time.Now(), exitCode: exitWith(0)})

	if _, err := s.StopBoxRun(tenantCtx("alice"), &pb.StopBoxRunRequest{Username: "alice", RunName: "nope"}); status.Code(err) != codes.NotFound {
		t.Errorf("missing run: err = %v, want NotFound", err)
	}
	for _, name := range []string{"", "..", "a/b"} {
		before := b.calls()
		if _, err := s.StopBoxRun(tenantCtx("alice"), &pb.StopBoxRunRequest{Username: "alice", RunName: name}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("run_name %q: err = %v, want InvalidArgument", name, err)
		}
		if b.calls() != before {
			t.Errorf("run_name %q reached the box", name)
		}
	}
	before := b.calls()
	if _, err := s.StopBoxRun(tenantCtx("mallory"), &pb.StopBoxRunRequest{Username: "alice", RunName: "task"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("stranger: err = %v, want PermissionDenied", err)
	}
	if _, err := s.StopBoxRun(scopedCtx("alice", "containers:read"), &pb.StopBoxRunRequest{Username: "alice", RunName: "task"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("owner without ssh:write: err = %v, want PermissionDenied", err)
	}
	if b.calls() != before {
		t.Errorf("a refused caller reached the box")
	}
}
