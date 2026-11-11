//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/agentbox"
	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3551: StartBoxRunRequest.workdir starts a run in a directory under the run's
// home instead of the home itself, for prompt and command runs alike, and the
// run reports it.

func readRunRecord(t *testing.T, dir, name string) agentbox.RunRecord {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if err != nil {
		t.Fatalf("read the run record: %v", err)
	}
	rec, err := agentbox.DecodeRunRecord(raw)
	if err != nil {
		t.Fatalf("decode the run record: %v", err)
	}
	return rec
}

func TestStartBoxRun_Workdir_CommandRunStartsThere(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	mustWriteFile(t, filepath.Join(u.home, "project"), "", true)
	s, dir, _ := boxRunStartServer(t, u)

	resp, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Command: "pwd", RunName: "wd-cmd", Workdir: "project",
	})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if got := resp.GetRun().GetWorkdir(); got != "project" {
		t.Errorf("StartBoxRun run.workdir = %q, want project", got)
	}
	run := waitForOutcome(t, s, "alice", "wd-cmd", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 10*time.Second)
	if run.GetWorkdir() != "project" {
		t.Errorf("ListBoxRuns run.workdir = %q, want project", run.GetWorkdir())
	}
	tail, err := s.TailBoxRunLog(tenantCtx("alice"), &pb.TailBoxRunLogRequest{Username: "alice", RunName: "wd-cmd", MaxBytes: 1 << 16})
	if err != nil {
		t.Fatalf("TailBoxRunLog: %v", err)
	}
	want := filepath.Join(u.home, "project")
	if got := strings.TrimSpace(string(tail.GetChunk())); got != want {
		t.Errorf("pwd = %q, want %q", got, want)
	}
	if rec := readRunRecord(t, dir, "wd-cmd"); rec.Cwd != want || rec.Workdir != "project" {
		t.Errorf("record cwd/workdir = %q/%q, want %q/project", rec.Cwd, rec.Workdir, want)
	}
}

// An engine run starts in the workdir too, so the engine's session lands in
// that directory's session folder and is the one discovery finds.
func TestStartBoxRun_Workdir_EngineRunStartsThereAndItsSessionIsFound(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	mustWriteFile(t, filepath.Join(u.home, "project", "slides"), "", true)
	u.writeFakeClaude(t, `pwd
d="$HOME/.claude/projects/$(pwd | tr / -)"
mkdir -p "$d"
: > "$d/sess-wd-1.jsonl"
sleep 0.3
`)
	s, dir, _ := boxRunStartServer(t, u)

	resp, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Prompt: "hi", RunName: "wd-eng", Workdir: "project/slides",
	})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if got := resp.GetRun().GetWorkdir(); got != "project/slides" {
		t.Errorf("run.workdir = %q, want project/slides", got)
	}
	run := waitForOutcome(t, s, "alice", "wd-eng", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 10*time.Second)
	want := filepath.Join(u.home, "project", "slides")
	tail, err := s.TailBoxRunLog(tenantCtx("alice"), &pb.TailBoxRunLogRequest{Username: "alice", RunName: "wd-eng", MaxBytes: 1 << 16})
	if err != nil {
		t.Fatalf("TailBoxRunLog: %v", err)
	}
	if got := strings.TrimSpace(string(tail.GetChunk())); got != want {
		t.Errorf("engine pwd = %q, want %q", got, want)
	}
	deadline := time.Now().Add(10 * time.Second)
	for run.GetSessionId() == "" && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		run = waitForOutcome(t, s, "alice", "wd-eng", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, time.Second)
	}
	if run.GetSessionId() != "sess-wd-1" {
		t.Errorf("session_id = %q, want sess-wd-1 (discovery must look in the workdir's session folder)", run.GetSessionId())
	}
	if rec := readRunRecord(t, dir, "wd-eng"); rec.Cwd != want {
		t.Errorf("record cwd = %q, want %q", rec.Cwd, want)
	}
}

// No workdir keeps today's behaviour: the run starts in the home, and the run
// reports no workdir.
func TestStartBoxRun_Workdir_EmptyKeepsHome(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	s, dir, _ := boxRunStartServer(t, u)

	resp, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Command: "pwd", RunName: "wd-none"})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if resp.GetRun().GetWorkdir() != "" {
		t.Errorf("run.workdir = %q, want empty", resp.GetRun().GetWorkdir())
	}
	waitForOutcome(t, s, "alice", "wd-none", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 10*time.Second)
	if rec := readRunRecord(t, dir, "wd-none"); rec.Cwd != u.home || rec.Workdir != "" {
		t.Errorf("record cwd/workdir = %q/%q, want %q/empty", rec.Cwd, rec.Workdir, u.home)
	}
}

// A workdir that is missing or is not a directory is FAILED_PRECONDITION naming
// it, before the run starts: no record, no rotation of the finished run under
// the same name, for prompt and command runs alike. No directory is created.
func TestStartBoxRun_Workdir_MissingOrNotADirectoryRefusedBeforeTheRun(t *testing.T) {
	for _, tc := range []struct {
		name, workdir string
		command       bool
	}{
		{"missing, command", "nope", true},
		{"missing, prompt", "nope", false},
		{"nested missing, command", "project/nope", true},
		{"a file, command", "afile", true},
		{"a file, prompt", "afile", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newFakeBoxUser(t, 0, 0)
			mustWriteFile(t, filepath.Join(u.home, "project"), "", true)
			mustWriteFile(t, filepath.Join(u.home, "afile"), "x", false)
			s, dir, _ := boxRunStartServer(t, u)

			// A finished run under the name: a refused start must leave it alone.
			if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Command: "echo earlier", RunName: "wd-bad"}); err != nil {
				t.Fatalf("first StartBoxRun: %v", err)
			}
			earlier := waitForOutcome(t, s, "alice", "wd-bad", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 10*time.Second)

			req := &pb.StartBoxRunRequest{Username: "alice", RunName: "wd-bad", Workdir: tc.workdir}
			if tc.command {
				req.Command = "pwd"
			} else {
				req.Prompt = "hi"
			}
			_, err := s.StartBoxRun(tenantCtx("alice"), req)
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("err = %v, want FailedPrecondition", err)
			}
			if !strings.Contains(status.Convert(err).Message(), tc.workdir) {
				t.Errorf("message %q does not name the workdir %q", status.Convert(err).Message(), tc.workdir)
			}
			if _, statErr := os.Stat(filepath.Join(u.home, "nope")); statErr == nil {
				t.Error("the missing workdir was created")
			}
			matches, _ := filepath.Glob(filepath.Join(dir, "wd-bad.*.json"))
			if len(matches) != 0 {
				t.Errorf("the finished run was rotated aside by a refused start: %v", matches)
			}
			if rec := readRunRecord(t, dir, "wd-bad"); !rec.StartedAt.Equal(earlier.GetStartedAt().AsTime()) {
				t.Errorf("the run record changed: started_at %v, want %v", rec.StartedAt, earlier.GetStartedAt().AsTime())
			}
		})
	}
}

// A workdir outside the canonical relative form WriteBoxFile's path follows is
// INVALID_ARGUMENT before anything on the box is touched.
func TestStartBoxRun_Workdir_NonCanonicalRefusedUpFront(t *testing.T) {
	for _, bad := range []string{"/etc", "..", "../bob", "project/../..", "a/./b", "a//b", "a/", ".", "a\nb", "x\x7f", ".ssh", ".containarium/x"} {
		touched := false
		s := &ContainerServer{
			boxRunLogDir:       t.TempDir(),
			boxRunCollaborator: func(owner, subject string) (bool, error) { return false, nil },
			boxRunExec:         func(box, script string) (string, error) { touched = true; return "", nil },
			boxRunStartExec:    func(box, username, script string) (string, error) { touched = true; return "", nil },
		}
		for _, req := range []*pb.StartBoxRunRequest{
			{Username: "alice", Command: "pwd", Workdir: bad},
			{Username: "alice", Prompt: "hi", Workdir: bad},
		} {
			_, err := s.StartBoxRun(tenantCtx("alice"), req)
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("workdir %q: err = %v, want InvalidArgument", bad, err)
			} else if !strings.Contains(status.Convert(err).Message(), "workdir") {
				t.Errorf("workdir %q: message %q does not name the field", bad, status.Convert(err).Message())
			}
		}
		if touched {
			t.Errorf("workdir %q: the box was touched before the refusal", bad)
		}
	}
}

// On a box with a recorded tool-access level the run starts in the run user's
// home, so the workdir is under that home and is checked as the run user.
func TestStartBoxRun_Workdir_LevelChecksUnderTheRunUsersHome(t *testing.T) {
	var checkUser, checkScript, spawnScript string
	s := &ContainerServer{
		boxRunLogDir:          t.TempDir(),
		boxRunCollaborator:    func(owner, subject string) (bool, error) { return false, nil },
		boxRunToolAccess:      func(ctx context.Context, username string) (string, error) { return "none", nil },
		boxRunEnsureToolchain: func(string) error { return nil },
		boxRunTokenInstall:    func(string, string, string, string) error { return nil },
		boxRunExec: func(box, script string) (string, error) {
			if strings.Contains(script, "useradd") {
				return "/home/ctn-run\n", nil
			}
			return "", nil
		},
		boxRunStartExec: func(box, username, script string) (string, error) {
			switch {
			case script == boxRunHomeAndConfigScript():
				return "/home/alice\n", nil
			case strings.Contains(script, coderun.WorkdirMarkerOK):
				checkUser, checkScript = username, script
				return coderun.WorkdirMarkerOK + "\n", nil
			case strings.Contains(script, "setsid"):
				spawnScript = script
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
	}
	resp, err := s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Command: "pwd", RunName: "lvl-wd", Workdir: "project", RunToken: "synthetic-run-token"})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if checkUser != boxRunUnprivilegedUser {
		t.Errorf("workdir checked as %q, want the run user %q", checkUser, boxRunUnprivilegedUser)
	}
	if !strings.Contains(checkScript, "/home/ctn-run/project") {
		t.Errorf("workdir check does not name the run user's home: %s", checkScript)
	}
	if !strings.Contains(spawnScript, "cd '/home/ctn-run/project'") {
		t.Errorf("the run does not start in the workdir: %s", spawnScript)
	}
	if resp.GetRun().GetWorkdir() != "project" {
		t.Errorf("run.workdir = %q, want project", resp.GetRun().GetWorkdir())
	}
}

// The prompt (engine) path on a leveled box: after the run user's sign-in is
// checked, the workdir is checked as the run user under the run user's home, not
// as the owner under the owner's home, and the engine starts there.
func TestStartBoxRun_Workdir_LevelPromptRunChecksUnderTheRunUsersHome(t *testing.T) {
	var checkUser, checkScript, spawnUser, spawnScript string
	s := &ContainerServer{
		boxRunLogDir:          t.TempDir(),
		boxRunCollaborator:    func(owner, subject string) (bool, error) { return false, nil },
		boxRunToolAccess:      func(ctx context.Context, username string) (string, error) { return "none", nil },
		boxRunEnsureToolchain: func(string) error { return nil },
		boxRunTokenInstall:    func(string, string, string, string) error { return nil },
		boxRunExec: func(box, script string) (string, error) {
			if strings.Contains(script, "useradd") {
				return "/home/ctn-run\n", nil
			}
			return "", nil
		},
		boxRunStartExec: func(box, username, script string) (string, error) {
			switch {
			case script == boxRunHomeAndConfigScript():
				return "/home/alice\n" + `{"version":1,"engine":"claude","credential":"secret","provider":"anthropic"}`, nil
			case script == signInProbeScript(t):
				return "interactive\n", nil
			case strings.Contains(script, coderun.WorkdirMarkerOK):
				checkUser, checkScript = username, script
				return coderun.WorkdirMarkerOK + "\n", nil
			case strings.Contains(script, "setsid"):
				spawnUser, spawnScript = username, script
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
	}
	resp, err := s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Prompt: "do it", RunName: "lvl-wd-eng", Workdir: "project", RunToken: "synthetic-run-token"})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if checkUser != boxRunUnprivilegedUser {
		t.Errorf("workdir checked as %q, want the run user %q", checkUser, boxRunUnprivilegedUser)
	}
	if !strings.Contains(checkScript, "'/home/ctn-run/project'") || strings.Contains(checkScript, "/home/alice") {
		t.Errorf("workdir check is not under the run user's home: %s", checkScript)
	}
	if spawnUser != boxRunUnprivilegedUser {
		t.Errorf("engine spawned as %q, want %q", spawnUser, boxRunUnprivilegedUser)
	}
	if !strings.Contains(spawnScript, "cd '/home/ctn-run/project'") {
		t.Errorf("the engine does not start in the workdir: %s", spawnScript)
	}
	if resp.GetRun().GetWorkdir() != "project" {
		t.Errorf("run.workdir = %q, want project", resp.GetRun().GetWorkdir())
	}
}

// The spawn enters a workdir strictly: one that vanished after the check fails
// the start and never silently falls back to the home. The home itself is still
// entered best-effort, as before #3551.
func TestBoxRunSpawnPrepareScript_WorkdirCdIsStrict(t *testing.T) {
	home := t.TempDir()
	work := filepath.Join(home, "project")
	mustWriteFile(t, work, "", true)
	run := func(cwd string) (string, error) {
		sp := boxRunSpawn{dir: filepath.Join(home, "runs"), name: "n", command: "true", home: home, cwd: cwd, prelaunch: "pwd"}
		out, err := exec.Command("sh", "-c", boxRunSpawnPrepareScript(sp)).Output()
		return strings.TrimSpace(string(out)), err
	}

	if got, err := run(work); err != nil || got != work {
		t.Fatalf("existing workdir: pwd = %q, err = %v; want %q, nil", got, err, work)
	}
	got, err := run(filepath.Join(home, "gone"))
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("vanished workdir: err = %v (pwd %q), want the script to exit non-zero", err, got)
	}
	if got == home {
		t.Errorf("vanished workdir fell back to the home")
	}
	if got, err := run(""); err != nil || got != home {
		t.Errorf("no workdir: pwd = %q, err = %v; want %q, nil", got, err, home)
	}
}

// Each marker the workdir check prints maps to its own outcome; in particular a
// directory the run user cannot enter is refused, never accepted.
func TestResolveBoxRunWorkdir_MapsEachMarker(t *testing.T) {
	for _, tc := range []struct {
		name     string
		out      string
		execErr  error
		wantCode codes.Code
		wantDir  string
		wantMsg  string
	}{
		{name: "ok", out: coderun.WorkdirMarkerOK + "\n", wantCode: codes.OK, wantDir: "/home/ctn-run/project"},
		{name: "missing", out: coderun.WorkdirMarkerMissing + "\n", wantCode: codes.FailedPrecondition, wantMsg: "does not exist"},
		{name: "not a directory", out: coderun.WorkdirMarkerNotDir + "\n", wantCode: codes.FailedPrecondition, wantMsg: "not a directory"},
		{name: "cannot be entered", out: coderun.WorkdirMarkerNoEnter + "\n", wantCode: codes.FailedPrecondition, wantMsg: "cannot be entered by ctn-run"},
		{name: "unexpected output", out: "garbage\n", wantCode: codes.Unavailable, wantMsg: "unexpected output"},
		{name: "exec error", execErr: errors.New("exec down"), wantCode: codes.Unavailable, wantMsg: "exec down"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asUser string
			fake := func(box, username, script string) (string, error) {
				asUser = username
				return tc.out, tc.execErr
			}
			dir, err := resolveBoxRunWorkdir(fake, "box-1", "ctn-run", "/home/ctn-run", "project")
			if asUser != "ctn-run" {
				t.Errorf("checked as %q, want ctn-run", asUser)
			}
			if status.Code(err) != tc.wantCode {
				t.Fatalf("err = %v, want code %v", err, tc.wantCode)
			}
			if dir != tc.wantDir {
				t.Errorf("dir = %q, want %q", dir, tc.wantDir)
			}
			if err != nil {
				msg := status.Convert(err).Message()
				if !strings.Contains(msg, tc.wantMsg) || !strings.Contains(msg, "project") {
					t.Errorf("message %q does not name the workdir and %q", msg, tc.wantMsg)
				}
			}
		})
	}
}

func TestDaemonCapabilities_IncludesBoxRunWorkdir(t *testing.T) {
	for _, c := range daemonCapabilities() {
		if c == DaemonCapBoxRunWorkdir {
			return
		}
	}
	t.Errorf("capabilities %v missing %q", daemonCapabilities(), DaemonCapBoxRunWorkdir)
}

// A run under a command policy is launched by the root supervisor, which takes
// the run's directory as --dir: the workdir, not the home.
func TestBoxRunSupervisedLaunchScript_UsesTheWorkdir(t *testing.T) {
	sp := boxRunSpawn{dir: "/d", name: "n", command: "true", home: "/home/ctn-run", cwd: "/home/ctn-run/project"}
	if got := boxRunSupervisedLaunchScript(sp, "ctn-run"); !strings.Contains(got, "--dir '/home/ctn-run/project'") {
		t.Errorf("supervisor not started in the workdir: %s", got)
	}
	sp.cwd = ""
	if got := boxRunSupervisedLaunchScript(sp, "ctn-run"); !strings.Contains(got, "--dir '/home/ctn-run' ") {
		t.Errorf("supervisor without a workdir not started in the home: %s", got)
	}
}
