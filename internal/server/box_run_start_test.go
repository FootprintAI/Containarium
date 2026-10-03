package server

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeBoxUser is the stand-in $HOME for StartBoxRun's tests: a real
// directory this test process can read/write/exec against, standing in for
// the box user's home directory that `su - <username> -c` would land in on
// a real box. A tiny executable at .local/bin/claude stands in for the real
// Claude Code binary so eng.RunCommand's own, unmodified output actually
// runs something deterministic and controllable.
type fakeBoxUser struct {
	home string
}

// newFakeBoxUser writes a fake ~/.local/bin/claude that sleeps briefly, then
// echoes to stdout and exits with exitCode — enough for a test to observe
// RUNNING, then EXITED with a specific code, without a real engine install.
func newFakeBoxUser(t *testing.T, exitCode int, sleep time.Duration) *fakeBoxUser {
	t.Helper()
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nsleep %g\necho fake claude output\nexit %d\n", sleep.Seconds(), exitCode)
	path := filepath.Join(bin, "claude")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return &fakeBoxUser{home: home}
}

// boxRunStartServer wires a ContainerServer whose two exec seams both run
// locally via a real shell, the same pattern box_run_log_test.go's shBox
// uses for List/Tail: boxRunStartExec stands in for `su - <username> -c`,
// ignoring username (a test sandbox has no real box user to drop into) but
// running with HOME pointed at u.home, so the SAME eng.RunCommand output
// production would spawn actually runs the fake claude binary above.
func boxRunStartServer(t *testing.T, u *fakeBoxUser) (*ContainerServer, string, *shBox) {
	t.Helper()
	dir := t.TempDir()
	list := &shBox{}
	s := &ContainerServer{
		boxRunExec:   list.exec,
		boxRunLogDir: dir,
		boxRunPoll:   time.Millisecond,
		boxRunCollaborator: func(owner, subject string) (bool, error) {
			return false, nil
		},
		boxRunStartExec: func(box, username, script string) (string, error) {
			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(), "HOME="+u.home)
			out, err := cmd.CombinedOutput()
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					return "", fmt.Errorf("%v: %s", err, ee.Stderr)
				}
				return "", fmt.Errorf("%w: %s", err, out)
			}
			return string(out), nil
		},
	}
	return s, dir, list
}

// waitForOutcome polls ListBoxRuns until name's outcome matches want (or the
// deadline passes, in which case the test fails with what it last saw).
func waitForOutcome(t *testing.T, s *ContainerServer, username, name string, want pb.BoxRunOutcome, timeout time.Duration) *pb.BoxRun {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last *pb.BoxRun
	for time.Now().Before(deadline) {
		resp, err := s.ListBoxRuns(tenantCtx(username), &pb.ListBoxRunsRequest{Username: username})
		if err != nil {
			t.Fatalf("ListBoxRuns: %v", err)
		}
		for _, r := range resp.Runs {
			if r.GetRunName() == name {
				last = r
				if r.GetOutcome() == want {
					return r
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("run %q never reached outcome %v; last seen: %v", name, want, last)
	return nil
}

// TestStartBoxRun_ProducesARecordListAndTailCanRead is #2193's own required
// test: StartBoxRun must produce exactly what ListBoxRuns returns and
// TailBoxRunLog reads — a daemon-started run indistinguishable, to those two
// existing readers, from one `code run` started over SSH.
func TestStartBoxRun_ProducesARecordListAndTailCanRead(t *testing.T) {
	u := newFakeBoxUser(t, 7, 150*time.Millisecond)
	s, _, _ := boxRunStartServer(t, u)

	resp, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice",
		Prompt:   "create hello.txt",
	})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	run := resp.GetRun()
	if run.GetRunName() != "code" {
		t.Errorf("run_name = %q, want %q (the shared default, no session_id given)", run.GetRunName(), "code")
	}
	if run.GetOutcome() != pb.BoxRunOutcome_BOX_RUN_OUTCOME_RUNNING {
		t.Errorf("outcome = %v, want RUNNING immediately after spawn", run.GetOutcome())
	}
	if run.GetCaptureMode() != pb.CaptureMode_CAPTURE_MODE_COMBINED {
		t.Errorf("capture_mode = %v, want COMBINED", run.GetCaptureMode())
	}
	if run.GetSessionId() != "" {
		t.Errorf("session_id = %q, want empty immediately (no engine session exists yet for a fresh run)", run.GetSessionId())
	}

	// ListBoxRuns must see exactly this run.
	listResp, err := s.ListBoxRuns(tenantCtx("alice"), &pb.ListBoxRunsRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("ListBoxRuns: %v", err)
	}
	if len(listResp.Runs) != 1 || listResp.Runs[0].GetRunName() != "code" {
		t.Fatalf("ListBoxRuns = %v, want exactly one run named %q", listResp.Runs, "code")
	}

	// TailBoxRunLog must be able to read the fake claude's output — follow a
	// couple seconds since the fake engine sleeps briefly before writing it.
	tailResp, err := s.TailBoxRunLog(tenantCtx("alice"), &pb.TailBoxRunLogRequest{Username: "alice", RunName: "code", FollowSeconds: 2})
	if err != nil {
		t.Fatalf("TailBoxRunLog: %v", err)
	}
	if !strings.Contains(string(tailResp.Chunk), "fake claude output") {
		t.Errorf("TailBoxRunLog chunk = %q, want it to contain the fake engine's output", tailResp.Chunk)
	}

	// Once the detached child exits, both readers see EXITED with the exact
	// code the fake engine returned.
	done := waitForOutcome(t, s, "alice", "code", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 3*time.Second)
	if done.GetExitCode() != 7 {
		t.Errorf("exit_code = %v, want 7", done.GetExitCode())
	}
}

// TestStartBoxRun_SessionIDDoublesAsRunName is the accepted default from the
// issue thread: resuming via session_id uses it as the run name too, so the
// existing name-keyed collision machinery doubles as the per-session check.
func TestStartBoxRun_SessionIDDoublesAsRunName(t *testing.T) {
	u := newFakeBoxUser(t, 0, 50*time.Millisecond)
	s, _, _ := boxRunStartServer(t, u)

	resp, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username:  "alice",
		Prompt:    "continue",
		SessionId: "sess-123",
	})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if resp.GetRun().GetRunName() != "sess-123" {
		t.Errorf("run_name = %q, want the session id %q", resp.GetRun().GetRunName(), "sess-123")
	}
	if resp.GetRun().GetSessionId() != "sess-123" {
		t.Errorf("session_id = %q, want %q (already known from the request)", resp.GetRun().GetSessionId(), "sess-123")
	}
}

// TestStartBoxRun_CollisionOnAStillRunningSession is the issue's explicit AC:
// StartBoxRun on a box whose previous run for the same session is still
// running is FAILED_PRECONDITION naming the run; no queueing.
func TestStartBoxRun_CollisionOnAStillRunningSession(t *testing.T) {
	u := newFakeBoxUser(t, 0, 2*time.Second) // long enough to still be running
	s, _, _ := boxRunStartServer(t, u)

	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Prompt: "first", SessionId: "sess-1",
	}); err != nil {
		t.Fatalf("first StartBoxRun: %v", err)
	}

	_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Prompt: "second", SessionId: "sess-1",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("second StartBoxRun err = %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "sess-1") {
		t.Errorf("error should name the colliding run %q: %v", "sess-1", err)
	}
}

// TestStartBoxRun_RotatesAFinishedRunUnderTheSameName proves a finished run
// never blocks reuse of its name, consistent with agentbox's own collision
// rule (running/unknown reject, exited rotate) — StartBoxRun must not
// reinvent a stricter or looser rule than the one `code run` already has.
func TestStartBoxRun_RotatesAFinishedRunUnderTheSameName(t *testing.T) {
	u := newFakeBoxUser(t, 0, 50*time.Millisecond)
	s, dir, _ := boxRunStartServer(t, u)

	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Prompt: "first", SessionId: "sess-1",
	}); err != nil {
		t.Fatalf("first StartBoxRun: %v", err)
	}
	waitForOutcome(t, s, "alice", "sess-1", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 3*time.Second)

	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Prompt: "second", SessionId: "sess-1",
	}); err != nil {
		t.Fatalf("second StartBoxRun after the first exited: %v", err)
	}

	// Exactly one CURRENT run named sess-1 — the first's record/log were
	// rotated aside, not overwritten in place or left colliding.
	resp, err := s.ListBoxRuns(tenantCtx("alice"), &pb.ListBoxRunsRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("ListBoxRuns: %v", err)
	}
	var current int
	for _, r := range resp.Runs {
		if r.GetRunName() == "sess-1" {
			current++
		}
	}
	if current != 1 {
		t.Errorf("found %d current runs named sess-1, want exactly 1 (the rotated-aside one must not still be CURRENT)", current)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var rotated int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "sess-1.") && strings.HasSuffix(e.Name(), ".json") && e.Name() != "sess-1.json" {
			rotated++
		}
	}
	if rotated != 1 {
		t.Errorf("found %d rotated-aside records, want exactly 1 (the first run's)", rotated)
	}
}

// TestStartBoxRun_Validation pins validation ordering: every rejected
// request fails before any box exec, exactly like ListBoxRuns/TailBoxRunLog.
func TestStartBoxRun_Validation(t *testing.T) {
	cases := []struct {
		name string
		req  *pb.StartBoxRunRequest
	}{
		{"empty username", &pb.StartBoxRunRequest{Prompt: "hi"}},
		{"empty prompt", &pb.StartBoxRunRequest{Username: "alice"}},
		{"session_id and continue_session both set", &pb.StartBoxRunRequest{
			Username: "alice", Prompt: "hi", SessionId: "s", ContinueSession: true,
		}},
		{"session_id with a slash", &pb.StartBoxRunRequest{
			Username: "alice", Prompt: "hi", SessionId: "a/b",
		}},
		{"session_id is dot-dot", &pb.StartBoxRunRequest{
			Username: "alice", Prompt: "hi", SessionId: "..",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var execCalls int
			s := &ContainerServer{
				boxRunExec: func(box, script string) (string, error) { execCalls++; return "", nil },
				boxRunStartExec: func(box, username, script string) (string, error) {
					execCalls++
					return "", nil
				},
			}
			_, err := s.StartBoxRun(adminCtx(), tc.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if execCalls != 0 {
				t.Errorf("ran %d box execs before validation passed; want none", execCalls)
			}
		})
	}
}

// TestStartBoxRun_Authz reuses the same ssh:write + owner/collaborator rule
// List/Tail already enforce (authorizeBoxRuns) — a stranger never reaches the
// box, and a refusal happens before any exec.
func TestStartBoxRun_Authz(t *testing.T) {
	var execCalls int
	s := &ContainerServer{
		boxRunExec: func(box, script string) (string, error) { execCalls++; return "", nil },
		boxRunStartExec: func(box, username, script string) (string, error) {
			execCalls++
			return "", nil
		},
		boxRunCollaborator: func(owner, subject string) (bool, error) { return false, nil },
	}
	_, err := s.StartBoxRun(tenantCtx("mallory"), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if execCalls != 0 {
		t.Errorf("ran %d box execs for a refused caller; want none", execCalls)
	}

	_, err = s.StartBoxRun(scopedCtx("alice", auth.ScopeContainersRead), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("owner without ssh:write: err = %v, want PermissionDenied", err)
	}
}

// TestStartBoxRun_GatewayCredentialIsRefused pins #2193's documented scope
// boundary: StartBoxRun does not mint a gateway token in-process, so a box
// installed with --credential gateway gets a clear, actionable refusal
// instead of silently running with no credential at all.
func TestStartBoxRun_GatewayCredentialIsRefused(t *testing.T) {
	home := t.TempDir()
	mustWriteFile(t, filepath.Join(home, ".containarium"), "", true)
	mustWriteFile(t, filepath.Join(home, ".containarium", "code.json"),
		`{"version":1,"engine":"claude","credential":"gateway","provider":"anthropic"}`, false)

	dir := t.TempDir()
	s := &ContainerServer{
		boxRunExec:   (&shBox{}).exec,
		boxRunLogDir: dir,
		boxRunStartExec: func(box, username, script string) (string, error) {
			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(), "HOME="+home)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("%w: %s", err, out)
			}
			return string(out), nil
		},
	}
	_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "code run") {
		t.Errorf("error should point at the SSH fallback path: %v", err)
	}
}

func mustWriteFile(t *testing.T, path, content string, dir bool) {
	t.Helper()
	if dir {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
