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
			case strings.Contains(script, boxRunWorkdirMarkerOK):
				checkUser, checkScript = username, script
				return boxRunWorkdirMarkerOK + "\n", nil
			case strings.Contains(script, "setsid"):
				spawnScript = script
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
	}
	resp, err := s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Command: "pwd", RunName: "lvl-wd", Workdir: "project"})
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
