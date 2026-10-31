//go:build !containarium_client

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/agentbox"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// StartBoxRun's command mode (#3322): a shell command under a timeout runs in
// the engine's place, with the same record, log, listing and exit-code contract
// as an engine run, no engine started and no sign-in required.

func TestStartBoxRun_CommandMode_RunsTheCommandAndReportsItsExitCode(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0) // the fake engine exists but must never run
	s, dir, _ := boxRunStartServer(t, u)

	resp, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Command: "echo verify-ran; exit 3", RunName: "verify-1",
	})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if resp.GetRun().GetRunName() != "verify-1" {
		t.Fatalf("run name = %q, want verify-1", resp.GetRun().GetRunName())
	}
	if resp.GetRun().GetSessionId() != "" {
		t.Errorf("a command run has no engine session; got session id %q", resp.GetRun().GetSessionId())
	}
	run := waitForOutcome(t, s, "alice", "verify-1", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 10*time.Second)
	if run.ExitCode == nil || *run.ExitCode != 3 {
		t.Fatalf("exit code = %v, want 3", run.ExitCode)
	}
	tail, err := s.TailBoxRunLog(tenantCtx("alice"), &pb.TailBoxRunLogRequest{Username: "alice", RunName: "verify-1", MaxBytes: 1 << 16})
	if err != nil {
		t.Fatalf("TailBoxRunLog: %v", err)
	}
	log := string(tail.GetChunk())
	if !strings.Contains(log, "verify-ran") {
		t.Errorf("log lacks the command's output: %q", log)
	}
	if strings.Contains(log, "fake claude output") {
		t.Errorf("the engine ran during a command run: %q", log)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "verify-1.json"))
	if err != nil {
		t.Fatalf("read the run record: %v", err)
	}
	rec, err := agentbox.DecodeRunRecord(raw)
	if err != nil {
		t.Fatalf("decode the run record: %v", err)
	}
	if !strings.Contains(rec.Command, "timeout -k 5 900 sh -c") || !strings.Contains(rec.Command, "verify-ran") {
		t.Errorf("record command = %q, want the shell command under the default timeout", rec.Command)
	}
	if rec.Model != "" {
		t.Errorf("a command run records no model, got %q", rec.Model)
	}
}

func TestStartBoxRun_CommandMode_TimeoutEndsTheCommandWith124(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	s, _, _ := boxRunStartServer(t, u)
	start := time.Now()
	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Command: "sleep 30", RunName: "verify-slow", TimeoutSeconds: 1,
	}); err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	run := waitForOutcome(t, s, "alice", "verify-slow", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 15*time.Second)
	if run.ExitCode == nil || *run.ExitCode != 124 {
		t.Fatalf("exit code = %v, want 124 (timed out)", run.ExitCode)
	}
	if took := time.Since(start); took > 12*time.Second {
		t.Errorf("the timeout took %s to end a 1s command", took)
	}
}

// A box with a recorded level runs the command as the run user, provisioned and
// granted as for an engine run, and never probes the engine sign-in: nothing is
// signed in for a command.
func TestStartBoxRun_CommandMode_RunsAsTheRunUserWithoutASignIn(t *testing.T) {
	var rootCalls, probeCalls int
	var spawnUser, spawnScript, recordUser string
	s := &ContainerServer{
		boxRunLogDir:          t.TempDir(),
		boxRunCollaborator:    func(owner, subject string) (bool, error) { return false, nil },
		boxRunToolAccess:      func(ctx context.Context, username string) (string, error) { return "build_tools", nil },
		boxRunEnsureToolchain: func(string) error { return nil },
		boxRunExec: func(box, script string) (string, error) {
			rootCalls++
			if strings.Contains(script, "useradd") {
				return "/home/ctn-run\n", nil
			}
			return "", nil
		},
		boxRunStartExec: func(box, username, script string) (string, error) {
			switch {
			case script == boxRunHomeAndConfigScript():
				return "/home/alice\n", nil // no code.json at all: a command needs no engine
			case script == signInProbeScript(t):
				probeCalls++
				return "none\n", nil // would refuse an engine run
			case strings.Contains(script, "setsid"):
				spawnUser, spawnScript = username, script
				return "4242 boot-1\n", nil
			case strings.Contains(script, ".start.tmp"):
				recordUser = username
			}
			return "", nil
		},
	}
	resp, err := s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Command: "make verify", RunName: "verify-2", TimeoutSeconds: 120})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if probeCalls != 0 {
		t.Errorf("the engine sign-in was probed %d time(s); a command needs none", probeCalls)
	}
	if rootCalls == 0 {
		t.Error("the run user was not provisioned as root")
	}
	if spawnUser != boxRunUnprivilegedUser || recordUser != boxRunUnprivilegedUser {
		t.Errorf("spawned as %q and recorded as %q, want both %q", spawnUser, recordUser, boxRunUnprivilegedUser)
	}
	// The spawn script quotes the inner command once more, so the two halves are checked apart.
	if !strings.Contains(spawnScript, "timeout -k 5 120 sh -c ") || !strings.Contains(spawnScript, "make verify") {
		t.Errorf("spawn script lacks the timed command: %s", spawnScript)
	}
	if strings.Contains(spawnScript, "claude") || strings.Contains(spawnScript, "--allowedTools") {
		t.Errorf("an engine or its policy flags leaked into a command run: %s", spawnScript)
	}
	if resp.GetRun().GetRunName() != "verify-2" {
		t.Errorf("run name = %q", resp.GetRun().GetRunName())
	}
}

// A gateway-credentialed box, refused for an engine run, takes a command run:
// no token is minted for a command.
func TestStartBoxRun_CommandMode_IgnoresTheEngineConfiguration(t *testing.T) {
	var spawned bool
	s := &ContainerServer{
		boxRunLogDir:       t.TempDir(),
		boxRunCollaborator: func(owner, subject string) (bool, error) { return false, nil },
		boxRunExec:         func(box, script string) (string, error) { return "", nil },
		boxRunStartExec: func(box, username, script string) (string, error) {
			switch {
			case script == boxRunHomeAndConfigScript():
				return "/home/alice\n" + `{"version":1,"engine":"pi","credential":"gateway","provider":"kafeido"}`, nil
			case strings.Contains(script, "setsid"):
				spawned = true
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
	}
	if _, err := s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Command: "go test ./...", RunName: "verify-3"}); err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if !spawned {
		t.Error("the command was not spawned")
	}
	// The same box refuses an engine run, as before.
	_, err := s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi", RunName: "code-3"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("an engine run on a gateway box = %v, want FailedPrecondition", err)
	}
}
