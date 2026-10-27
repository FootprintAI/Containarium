//go:build linux

package agentbox

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/coderun/engine"
)

// approvalE2EEnv opts into TestApprovalEndToEnd. It runs the real Claude Code
// against a real model three times, so it needs a signed-in ~/.local/bin/claude
// and costs a few model calls; CI does not set it.
const approvalE2EEnv = "CONTAINARIUM_APPROVAL_E2E"

// TestApprovalEndToEnd runs the exact command `code run --approvals ask`
// dispatches, with this tree's agent-box on PATH, on a prompt that needs one
// gated command (touch outside the working directory):
//   - allow → exit 0 and the file exists
//   - deny  → the file is absent
//   - no answer → the request expires and the journal records it
func TestApprovalEndToEnd(t *testing.T) {
	if os.Getenv(approvalE2EEnv) != "1" {
		t.Skipf("set %s=1 to run against a real model (needs a signed-in ~/.local/bin/claude)", approvalE2EEnv)
	}
	home, _ := os.UserHomeDir()
	if _, err := os.Stat(filepath.Join(home, ".local/bin/claude")); err != nil {
		t.Skipf("no ~/.local/bin/claude: %v", err)
	}
	// The approval server's PATH puts these first; an installed agent-box there
	// would shadow the one built from this tree.
	for _, p := range []string{filepath.Join(home, ".local/bin/agent-box"), "/usr/local/bin/agent-box"} {
		if _, err := os.Stat(p); err == nil {
			t.Skipf("%s would shadow the agent-box built from this tree", p)
		}
	}

	bin := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(bin, "agent-box"), "github.com/footprintai/containarium/cmd/agent-box")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agent-box: %v\n%s", err, out)
	}
	if err := os.MkdirAll(DefaultLogDir, 0o755); err != nil {
		t.Fatal(err)
	}

	eng, err := engine.For(engine.NameClaude, engine.Options{Credential: engine.SecretCredential{}})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		answer  coderun.Answer // "" = never answer
		timeout time.Duration
	}{
		{"allow", coderun.AnswerAllow, 5 * time.Minute},
		{"deny", coderun.AnswerDeny, 5 * time.Minute},
		{"expire", "", 20 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := fmt.Sprintf("e2e-%s-%d", c.name, os.Getpid())
			t.Cleanup(func() {
				for _, p := range []string{coderun.ApprovalJournalPath(run), coderun.ApprovalAnswersDir(run)} {
					_ = os.RemoveAll(p)
				}
			})
			work := t.TempDir()
			target := filepath.Join(t.TempDir(), "approved-marker")

			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(coderun.ApprovalAnswersDir(run), 0o700); err != nil {
				t.Fatal(err)
			}

			prompt := "Run exactly this bash command and nothing else: touch " + target +
				"  If the command is denied, do not try any other way; reply DENIED. Otherwise reply DONE."
			command, ok := engine.WithApprovals(eng, eng.RunCommand(prompt, false, false, ""), run, pub, c.timeout)
			if !ok {
				t.Fatal("Claude reported no hook")
			}
			// Keep the developer's own hooks out of the run; flags trail, so this
			// does not touch the command under test.
			command += ` --settings '{"disableAllHooks":true}'`

			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
			defer cancel()
			if c.answer != "" {
				go answerEveryRequest(ctx, priv, run, c.answer)
			}
			cmd := exec.CommandContext(ctx, "sh", "-c", command)
			cmd.Dir = work
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
			out, runErr := cmd.CombinedOutput()
			t.Logf("claude output:\n%s", out)

			journal, _ := os.ReadFile(coderun.ApprovalJournalPath(run))
			t.Logf("journal:\n%s", journal)
			s := coderun.SummarizeApprovals(coderun.ParseInputJournal(journal))
			if s.Requests < 1 {
				t.Fatalf("no permission request was journaled")
			}
			_, statErr := os.Stat(target)
			switch c.name {
			case "allow":
				if runErr != nil {
					t.Errorf("run failed: %v", runErr)
				}
				if statErr != nil || s.Allowed < 1 {
					t.Errorf("allowed run: marker stat err %v, summary %+v", statErr, s)
				}
			case "deny":
				if statErr == nil || s.Denied < 1 || s.Allowed != 0 {
					t.Errorf("denied run: marker exists=%v, summary %+v", statErr == nil, s)
				}
			case "expire":
				if statErr == nil || s.Expired < 1 {
					t.Errorf("unanswered run: marker exists=%v, summary %+v", statErr == nil, s)
				}
			}
		})
	}
}

// answerEveryRequest answers each request in run's journal with a, signed
// with priv, until ctx ends.
func answerEveryRequest(ctx context.Context, priv ed25519.PrivateKey, run string, a coderun.Answer) {
	answered := map[string]bool{}
	for ctx.Err() == nil {
		b, _ := os.ReadFile(coderun.ApprovalJournalPath(run))
		for _, e := range coderun.ParseInputJournal(b) {
			if e.Kind != coderun.KindInputRequest || answered[e.RequestID] {
				continue
			}
			answered[e.RequestID] = true
			path := filepath.Join(coderun.ApprovalAnswersDir(run), e.RequestID)
			tmp := path + ".tmp"
			if os.WriteFile(tmp, []byte(coderun.FormatAnswer(priv, run, e.RequestID, coderun.RequestDigest(e.Tool, e.Input), a)), 0o600) == nil {
				_ = os.Rename(tmp, path)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
}
