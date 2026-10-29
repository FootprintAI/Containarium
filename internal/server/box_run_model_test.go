package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3259: StartBoxRunRequest.model passes a model id to the Claude Code run as
// --model, and the id that ran is reported back on the run and on ListBoxRuns.
func TestStartBoxRun_Model(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	u.writeFakeClaude(t, `case " $* " in *" --model some-model-id "*) ;; *) echo "missing flag: $*" >&2; exit 9;; esac
echo ok
`)
	s, _, _ := boxRunStartServer(t, u)
	ctx := tenantCtx("alice")

	resp, err := s.StartBoxRun(ctx, &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi", RunName: "m1", Model: "some-model-id"})
	if err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	if got := resp.GetRun().GetModel(); got != "some-model-id" {
		t.Errorf("StartBoxRun run.model = %q, want some-model-id", got)
	}
	done := waitForOutcome(t, s, "alice", "m1", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 5*time.Second)
	if done.GetExitCode() != 0 {
		t.Fatalf("exit_code = %d; the engine did not receive --model some-model-id", done.GetExitCode())
	}
	if done.GetModel() != "some-model-id" {
		t.Errorf("ListBoxRuns run.model = %q, want the id the run was started with", done.GetModel())
	}
}

// An absent model keeps today's command and reports no model: the engine's own
// default ran and the daemon does not claim to know which.
func TestStartBoxRun_NoModelAddsNoFlag(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	u.writeFakeClaude(t, "echo ok\n")
	s, dir, _ := boxRunStartServer(t, u)

	resp, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi", RunName: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetRun().GetModel() != "" {
		t.Errorf("run.model = %q, want empty", resp.GetRun().GetModel())
	}
	waitForOutcome(t, s, "alice", "n1", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 5*time.Second)
	rec, _ := os.ReadFile(filepath.Join(dir, "n1.json"))
	if strings.Contains(string(rec), "--model") {
		t.Errorf("record command carries --model without a request: %s", rec)
	}
}

// An id that is not a plain model id is refused before anything runs; it is
// interpolated into a shell command, so the rule is strict, not "whatever the
// engine accepts".
func TestStartBoxRun_InvalidModelRefusedUpFront(t *testing.T) {
	for _, bad := range []string{"two words", "x;touch /tmp/pwn", "$(id)", "a`id`", "-flag", "quo'te", "new\nline", strings.Repeat("a", 129)} {
		u := newFakeBoxUser(t, 0, 0)
		u.writeFakeClaude(t, "echo ok\n")
		s, dir, _ := boxRunStartServer(t, u)
		_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi", RunName: "bad", Model: bad})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("model %q: err = %v, want InvalidArgument", bad, err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "bad.json")); statErr == nil {
			t.Errorf("model %q: a run record was written", bad)
		}
	}
}

func TestStartBoxRun_ModelAcceptsRealisticIDs(t *testing.T) {
	for _, ok := range []string{"sonnet", "claude-opus-4-8", "claude-sonnet-4-5-20250929", "claude-opus-4-8[1m]", "vendor/model:tag.1_2"} {
		if !validBoxRunModel(ok) {
			t.Errorf("validBoxRunModel(%q) = false, want true", ok)
		}
	}
}

func TestStartBoxRun_ModelRefusedForOtherEngines(t *testing.T) {
	u := newFakeBoxUser(t, 0, 0)
	mustWriteFile(t, filepath.Join(u.home, ".containarium"), "", true)
	mustWriteFile(t, filepath.Join(u.home, ".containarium", "code.json"),
		`{"version":1,"engine":"pi","credential":"secret"}`, false)
	s, _, _ := boxRunStartServer(t, u)
	_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Prompt: "hi", Model: "some-model-id"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err = %v, want FailedPrecondition", err)
	}
}

func TestDaemonCapabilities_IncludesBoxRunModel(t *testing.T) {
	for _, c := range daemonCapabilities() {
		if c == DaemonCapBoxRunModel {
			return
		}
	}
	t.Errorf("capabilities %v missing %q", daemonCapabilities(), DaemonCapBoxRunModel)
}
