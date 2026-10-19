package server

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/agentbox"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/coderun"
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
	// The spawn script detaches the run with setsid and the stop script reads
	// process groups with ps -eo; both are what runs inside a (Linux) box, and
	// neither exists on macOS, where every test using this helper used to fail
	// with "exit status 1". CI runs on Linux, so nothing is lost there (#2677).
	if runtime.GOOS != "linux" {
		t.Skip("box-run scripts need Linux (setsid, ps -eo); they run inside Linux boxes")
	}
	dir := t.TempDir()
	list := &shBox{}
	// No `setsid` shim here: StopBoxRun signals the run's PROCESS GROUP and
	// its ownership check looks for pgid == pid, which only the real
	// util-linux setsid (a new session per run) provides. A pass-through
	// shim leaves the run in this test process's group, so every stop would
	// report the run "gone". Hosts without setsid are skipped above.
	var startedMu sync.Mutex
	started := map[string]bool{}
	s := &ContainerServer{
		boxRunExec:   list.exec,
		boxRunLogDir: dir,
		boxRunPoll:   time.Millisecond,
		boxRunCollaborator: func(owner, subject string) (bool, error) {
			return false, nil
		},
		boxRunStartExec: func(box, username, script string) (string, error) {
			startedMu.Lock()
			started[username] = true
			startedMu.Unlock()
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
	// #2677: a run started by the test keeps writing its log and exit sidecar
	// into dir after the test body returns, so t.TempDir's RemoveAll could race
	// it ("directory not empty"). Cleanups run last-in-first-out and TempDir's
	// was registered first, so this one runs before the directory is removed:
	// wait for every run the test started to leave RUNNING.
	t.Cleanup(func() {
		startedMu.Lock()
		users := make([]string, 0, len(started))
		for name := range started {
			users = append(users, name)
		}
		startedMu.Unlock()
		for _, name := range users {
			drainBoxRuns(t, s, name, 10*time.Second)
		}
	})
	return s, dir, list
}

// drainBoxRuns polls ListBoxRuns until none of username's runs is RUNNING (or
// the deadline passes, which is logged, not failed: a cleanup cannot fix a run
// that never ends, and the test body already had its say).
func drainBoxRuns(t *testing.T, s *ContainerServer, username string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := s.ListBoxRuns(tenantCtx(username), &pb.ListBoxRunsRequest{Username: username})
		if err != nil {
			return // the log dir is already gone: nothing is left to race
		}
		running := false
		for _, r := range resp.Runs {
			if r.GetOutcome() == pb.BoxRunOutcome_BOX_RUN_OUTCOME_RUNNING {
				running = true
				break
			}
		}
		if !running {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("a run for %q was still RUNNING after %s; cleanup may race it", username, timeout)
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

// TestStartBoxRun_PreconditionFailureDoesNotRotateAside is the #2260 review's
// blocking finding: checkBoxRunCollision's rotate-aside of a finished prior
// run under the target name must never execute before every
// precondition/authz/validation check (including the gateway-credential
// refusal) has passed. Before the fix, a finished run's .json/.log got
// renamed aside on disk even though StartBoxRun went on to refuse the
// request — ListBoxRuns/code attach/code status could no longer find it
// under its original name, for a request that was refused anyway. Each case
// below fails for a DIFFERENT precondition (gateway credential; malformed
// code.json) to show the bug generalizes to any later precondition failure,
// not just the gateway one the reviewer's repro used.
func TestStartBoxRun_PreconditionFailureDoesNotRotateAside(t *testing.T) {
	boot := hostBootID(t)
	cases := []struct {
		name       string
		codeConfig string
		wantErrSub string
	}{
		{
			name:       "gateway credential",
			codeConfig: `{"version":1,"engine":"claude","credential":"gateway","provider":"anthropic"}`,
			wantErrSub: "code run",
		},
		{
			name:       "malformed code.json",
			codeConfig: `{not valid json`,
			wantErrSub: "code.json",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			mustWriteFile(t, filepath.Join(home, ".containarium"), "", true)
			mustWriteFile(t, filepath.Join(home, ".containarium", "code.json"), tc.codeConfig, false)

			dir := t.TempDir()
			// Seed a FINISHED run under the target name ("code", the shared
			// default — no session_id given below) — exactly the collision
			// checkBoxRunCollision resolves to rotate=true for.
			t0 := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
			writeRecord(t, dir, recordSpec{name: "code", pid: 1 << 22, boot: boot, started: t0, exitCode: exitWith(0)})
			writeFile(t, filepath.Join(dir, "code.log"), "finished run's own output\n")

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
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantErrSub)
			}

			// The whole point: the finished run's files must be UNTOUCHED —
			// still at their original path, never rotated aside, since the
			// request was refused before any mutation should have happened.
			if _, err := os.Stat(filepath.Join(dir, "code.json")); err != nil {
				t.Errorf("code.json no longer at its original path: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "code.log")); err != nil {
				t.Errorf("code.log no longer at its original path: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "code.") && e.Name() != "code.json" && e.Name() != "code.log" {
					t.Errorf("found unexpected rotated-aside file %q — a refused request must not mutate the filesystem", e.Name())
				}
			}
		})
	}
}

// TestStartBoxRun_ConcurrentSameNameOneWinsCleanly is the #2260 review's
// should-fix: two concurrent StartBoxRun calls racing for the same
// not-yet-existing session name must not both pass the collision check and
// clobber each other's log truncate / record write. With the per-(box,name)
// mutex in place, exactly one call must succeed and the other must see a
// clean FailedPrecondition collision — never corruption (a truncated log out
// from under a running child, or an orphaned PID with no record naming it).
func TestStartBoxRun_ConcurrentSameNameOneWinsCleanly(t *testing.T) {
	u := newFakeBoxUser(t, 0, 300*time.Millisecond)
	s, dir, _ := boxRunStartServer(t, u)

	const n = 8
	type result struct {
		err error
	}
	results := make(chan result, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
				Username: "alice", Prompt: fmt.Sprintf("race %d", i), SessionId: "race-1",
			})
			results <- result{err: err}
		}(i)
	}

	var ok, collided int
	for i := 0; i < n; i++ {
		r := <-results
		switch {
		case r.err == nil:
			ok++
		case status.Code(r.err) == codes.FailedPrecondition && strings.Contains(r.err.Error(), "race-1"):
			collided++
		default:
			t.Errorf("unexpected error from concurrent StartBoxRun: %v", r.err)
		}
	}
	if ok != 1 {
		t.Errorf("%d concurrent calls succeeded, want exactly 1", ok)
	}
	if collided != n-1 {
		t.Errorf("%d concurrent calls got a clean collision refusal, want %d", collided, n-1)
	}

	// Exactly one current record under the name, and it decodes cleanly —
	// no half-written/corrupted record from a lost race.
	waitForOutcome(t, s, "alice", "race-1", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 3*time.Second)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var current int
	for _, e := range entries {
		if e.Name() == "race-1.json" {
			current++
		}
	}
	if current != 1 {
		t.Errorf("found %d current records named race-1.json, want exactly 1", current)
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

// TestRunLogDirMirrorsAgentBox pins coderun.RunLogDir (used by the CLI and
// MCP, which cannot import agentbox) to the directory process_start uses.
func TestRunLogDirMirrorsAgentBox(t *testing.T) {
	if coderun.RunLogDir != agentbox.DefaultLogDir {
		t.Errorf("coderun.RunLogDir = %q, agentbox.DefaultLogDir = %q", coderun.RunLogDir, agentbox.DefaultLogDir)
	}
}

// writeFakeClaude replaces the fake engine binary with body.
func (u *fakeBoxUser) writeFakeClaude(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(u.home, ".local", "bin", "claude")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
}

// TestStartBoxRun_RunNameNamesTheRun: an explicit run_name is the run's name
// (over the default and over a session id), and the run is readable by it.
func TestStartBoxRun_RunNameNamesTheRun(t *testing.T) {
	u := newFakeBoxUser(t, 0, 50*time.Millisecond)
	s, dir, _ := boxRunStartServer(t, u)

	resp, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi", RunName: "run-1.a_b"})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if got := resp.GetRun().GetRunName(); got != "run-1.a_b" {
		t.Errorf("run_name = %q, want run-1.a_b", got)
	}
	for _, ext := range []string{".json", ".log"} {
		if _, err := os.Stat(filepath.Join(dir, "run-1.a_b"+ext)); err != nil {
			t.Errorf("expected run-1.a_b%s on disk: %v", ext, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "code.json")); err == nil {
		t.Error("an explicitly named run must not create the default `code` record")
	}
	tail, err := s.TailBoxRunLog(tenantCtx("alice"), &pb.TailBoxRunLogRequest{Username: "alice", RunName: "run-1.a_b", FollowSeconds: 2})
	if err != nil || !strings.Contains(string(tail.Chunk), "fake claude output") {
		t.Errorf("TailBoxRunLog by run_name = %q, %v", tail.GetChunk(), err)
	}

	// run_name wins over session_id; the resumed id is still reported.
	resp, err = s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi", RunName: "run-2", SessionId: "sess-9"})
	if err != nil {
		t.Fatalf("StartBoxRun with both: %v", err)
	}
	if resp.GetRun().GetRunName() != "run-2" || resp.GetRun().GetSessionId() != "sess-9" {
		t.Errorf("run = %v, want run_name run-2 and session_id sess-9", resp.GetRun())
	}
}

// TestStartBoxRun_RunNameNeverCollidesWithTheDefault: a still-running
// `code` run does not block a differently named run, and the same explicit
// name is refused while running, then rotates once finished.
func TestStartBoxRun_RunNameNeverCollidesWithTheDefault(t *testing.T) {
	u := newFakeBoxUser(t, 0, 2*time.Second)
	s, _, _ := boxRunStartServer(t, u)
	ctx := tenantCtx("alice")

	if _, err := s.StartBoxRun(ctx, &pb.StartBoxRunRequest{Username: "alice", Prompt: "own"}); err != nil {
		t.Fatalf("default run: %v", err)
	}
	if _, err := s.StartBoxRun(ctx, &pb.StartBoxRunRequest{Username: "alice", Prompt: "platform", RunName: "platform-1"}); err != nil {
		t.Fatalf("named run beside a running default run: %v", err)
	}
	_, err := s.StartBoxRun(ctx, &pb.StartBoxRunRequest{Username: "alice", Prompt: "again", RunName: "platform-1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "platform-1") {
		t.Errorf("same run_name while running: err = %v, want FailedPrecondition naming it", err)
	}
}

func TestStartBoxRun_RunNameRotatesAFinishedRunOfThatName(t *testing.T) {
	u := newFakeBoxUser(t, 0, 50*time.Millisecond)
	s, dir, _ := boxRunStartServer(t, u)
	ctx := tenantCtx("alice")
	if _, err := s.StartBoxRun(ctx, &pb.StartBoxRunRequest{Username: "alice", Prompt: "1", RunName: "r"}); err != nil {
		t.Fatal(err)
	}
	waitForOutcome(t, s, "alice", "r", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 3*time.Second)
	if _, err := s.StartBoxRun(ctx, &pb.StartBoxRunRequest{Username: "alice", Prompt: "2", RunName: "r"}); err != nil {
		t.Fatalf("second run under the same finished name: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	var rotated int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "r.") && strings.HasSuffix(e.Name(), ".json") && e.Name() != "r.json" {
			rotated++
		}
	}
	if rotated != 1 {
		t.Errorf("rotated records = %d, want 1", rotated)
	}
}

func TestStartBoxRun_InvalidRunNameIsRefusedBeforeAnyExec(t *testing.T) {
	for _, bad := range []string{"a/b", "..", ".", "has space", "x;rm", strings.Repeat("a", 129), "a\nb"} {
		var execCalls int
		s := &ContainerServer{
			boxRunExec:      func(box, script string) (string, error) { execCalls++; return "", nil },
			boxRunStartExec: func(box, username, script string) (string, error) { execCalls++; return "", nil },
		}
		_, err := s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi", RunName: bad})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("run_name %q: err = %v, want InvalidArgument", bad, err)
		}
		if execCalls != 0 {
			t.Errorf("run_name %q: %d box execs before validation", bad, execCalls)
		}
	}
}

// TestStartBoxRun_StructuredOutput: the engine runs with --output-format json,
// the main log is exactly the JSON object, stderr goes to its own file, and
// the session id comes from the object (readable via ListBoxRuns).
func TestStartBoxRun_StructuredOutput(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	u.writeFakeClaude(t, `case " $* " in *" --output-format json "*) ;; *) echo "missing flag: $*" >&2; exit 9;; esac
echo "a warning" >&2
printf '%s' '{"type":"result","subtype":"success","is_error":false,"permission_denials":[{"tool_input":{"session_id":"nested-evil"}}],"result":"say \"session_id\":\"evil\" ok","session_id":"7b0d2e5c-1111-4222-8333-444455556666","usage":{"input_tokens":1}}'
`)
	s, dir, _ := boxRunStartServer(t, u)
	ctx := tenantCtx("alice")

	resp, err := s.StartBoxRun(ctx, &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi", RunName: "s1", StructuredOutput: true})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if resp.GetRun().GetCaptureMode() != pb.CaptureMode_CAPTURE_MODE_COMBINED {
		t.Errorf("capture_mode = %v, want COMBINED", resp.GetRun().GetCaptureMode())
	}
	done := waitForOutcome(t, s, "alice", "s1", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 5*time.Second)
	if done.GetExitCode() != 0 {
		t.Fatalf("exit_code = %d; the engine did not receive --output-format json", done.GetExitCode())
	}
	if done.GetSessionId() != "7b0d2e5c-1111-4222-8333-444455556666" {
		t.Errorf("session_id = %q, want the one in the JSON result (not the one quoted inside result text)", done.GetSessionId())
	}
	logBytes, _ := os.ReadFile(filepath.Join(dir, "s1.log"))
	var obj struct {
		Type      string `json:"type"`
		Subtype   string `json:"subtype"`
		IsError   bool   `json:"is_error"`
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(logBytes, &obj); err != nil {
		t.Fatalf("main log is not exactly one JSON object: %v\n%s", err, logBytes)
	}
	if obj.Type != "result" || obj.Subtype != "success" || obj.IsError {
		t.Errorf("unexpected result object %+v", obj)
	}
	errBytes, _ := os.ReadFile(filepath.Join(dir, "s1.stderr.log"))
	if !strings.Contains(string(errBytes), "a warning") {
		t.Errorf("stderr log = %q, want the warning", errBytes)
	}
	// The opaque readers handle the structured log.
	tail, err := s.TailBoxRunLog(ctx, &pb.TailBoxRunLogRequest{Username: "alice", RunName: "s1"})
	if err != nil || string(tail.Chunk) != string(logBytes) {
		t.Errorf("TailBoxRunLog = %q, %v; want the JSON object verbatim", tail.GetChunk(), err)
	}
	// stderr.log is not mistaken for a run.
	list, _ := s.ListBoxRuns(ctx, &pb.ListBoxRunsRequest{Username: "alice"})
	if len(list.Runs) != 1 {
		t.Errorf("ListBoxRuns = %d runs, want 1", len(list.Runs))
	}
}

// TestStartBoxRun_PlainTextPathIsUnchangedWhenStructuredIsFalse pins the
// default: no --output-format flag, stderr merged into the one log, no
// .stderr.log, and the record's command is exactly the engine's own.
func TestStartBoxRun_PlainTextPathIsUnchangedWhenStructuredIsFalse(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	u.writeFakeClaude(t, "echo out; echo err >&2\n")
	s, dir, _ := boxRunStartServer(t, u)
	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi", RunName: "p"}); err != nil {
		t.Fatal(err)
	}
	waitForOutcome(t, s, "alice", "p", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 5*time.Second)
	logBytes, _ := os.ReadFile(filepath.Join(dir, "p.log"))
	if !strings.Contains(string(logBytes), "out") || !strings.Contains(string(logBytes), "err") {
		t.Errorf("plain log = %q, want stdout and stderr interleaved", logBytes)
	}
	if _, err := os.Stat(filepath.Join(dir, "p.stderr.log")); err == nil {
		t.Error("plain-text run must not create a .stderr.log")
	}
	rec, _ := os.ReadFile(filepath.Join(dir, "p.json"))
	if strings.Contains(string(rec), "output-format") {
		t.Errorf("record command carries an output-format flag: %s", rec)
	}
}

func TestStartBoxRun_StructuredOutputRefusedForOtherEngines(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	mustWriteFile(t, filepath.Join(u.home, ".containarium"), "", true)
	mustWriteFile(t, filepath.Join(u.home, ".containarium", "code.json"),
		`{"version":1,"engine":"pi","credential":"secret"}`, false)
	s, _, _ := boxRunStartServer(t, u)
	_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi", StructuredOutput: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err = %v, want FailedPrecondition", err)
	}
}

// TestBoxRunSpawnScript_FreshRunSnapshotsBeforeLaunch: the discovery snapshot
// is taken before the engine is launched, never after.
func TestBoxRunSpawnScript_FreshRunSnapshotsBeforeLaunch(t *testing.T) {
	script := boxRunSpawnScript(boxRunSpawn{dir: "/d", name: "n", command: "true", home: "/h", prelaunch: "SNAPSHOT", sessionTrailer: "POLL"})
	snap, launch, poll := strings.Index(script, "SNAPSHOT"), strings.Index(script, "setsid"), strings.Index(script, "POLL")
	if snap < 0 || snap >= launch || launch >= poll {
		t.Errorf("want snapshot < launch < poll, got %d %d %d in:\n%s", snap, launch, poll, script)
	}
}

func TestDaemonCapabilities(t *testing.T) {
	got := daemonCapabilities()
	want := map[string]bool{"box_run_name": true, "box_run_structured_output": true}
	for _, c := range got {
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("capabilities %v missing %v", got, want)
	}
}

// #2677: drainBoxRuns is what keeps a test's still-running run from writing into
// the temp dir while it is being removed. It must return only once the run has
// left RUNNING, and must not wait at all when nothing is running.
func TestDrainBoxRuns_WaitsForARunningRunToExit(t *testing.T) {
	u := newFakeBoxUser(t, 0, 300*time.Millisecond)
	s, _, _ := boxRunStartServer(t, u)

	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Prompt: "p", SessionId: "sess-drain",
	}); err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if got := waitForOutcome(t, s, "alice", "sess-drain", pb.BoxRunOutcome_BOX_RUN_OUTCOME_RUNNING, 3*time.Second); got == nil {
		t.Fatal("run never showed as RUNNING")
	}

	drainBoxRuns(t, s, "alice", 5*time.Second)

	resp, err := s.ListBoxRuns(tenantCtx("alice"), &pb.ListBoxRunsRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("ListBoxRuns: %v", err)
	}
	for _, r := range resp.Runs {
		if r.GetOutcome() == pb.BoxRunOutcome_BOX_RUN_OUTCOME_RUNNING {
			t.Fatalf("drainBoxRuns returned while %q was still RUNNING", r.GetRunName())
		}
	}

	start := time.Now()
	drainBoxRuns(t, s, "alice", 5*time.Second)
	if time.Since(start) > time.Second {
		t.Errorf("drain with nothing running took %s, want ~immediate", time.Since(start))
	}
}

// The cleanup registered by boxRunStartServer drains every user that started a
// run, so a test that returns with a run in flight leaves no writer behind: the
// subtest below returns straight after starting a 300 ms run, and the run must
// have exited by the time t.Run returns (the cleanup ran).
func TestBoxRunStartServer_CleanupWaitsForRunsTheTestStarted(t *testing.T) {
	if runtime.GOOS != "linux" {
		// boxRunStartServer skips there, which would leave dir unset and make the
		// assertion below pass vacuously.
		t.Skip("box-run scripts need Linux (setsid, ps -eo)")
	}
	u := newFakeBoxUser(t, 0, 300*time.Millisecond)
	var dir string
	t.Run("starts a run and returns immediately", func(t *testing.T) {
		var s *ContainerServer
		s, dir, _ = boxRunStartServer(t, u)
		if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
			Username: "alice", Prompt: "p", SessionId: "sess-cleanup",
		}); err != nil {
			t.Fatalf("StartBoxRun: %v", err)
		}
	})
	// The subtest's TempDir is gone only if its cleanup (drain, then RemoveAll)
	// completed without the "directory not empty" race.
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the subtest's temp dir should have been removed cleanly, stat err = %v", err)
	}
}
