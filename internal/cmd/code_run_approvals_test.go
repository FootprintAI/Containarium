package cmd

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/coderun/engine"
)

// fakeApprovalSession records what the approval setup does to the box.
type fakeApprovalSession struct {
	probe  string // what the probe prints
	execs  []string
	writes map[string]struct{ content, mode string }
}

func (f *fakeApprovalSession) ShellExec(_ context.Context, command string) (string, error) {
	f.execs = append(f.execs, command)
	if strings.Contains(command, "approval-mcp --probe") {
		return f.probe, nil
	}
	return "", nil
}

func (f *fakeApprovalSession) WriteFile(_ context.Context, path, content, mode string) error {
	if f.writes == nil {
		f.writes = map[string]struct{ content, mode string }{}
	}
	f.writes[path] = struct{ content, mode string }{content, mode}
	return nil
}

func TestPrepareApprovalsClaudeWiresCommandWithAFreshPublicKey(t *testing.T) {
	sess := &fakeApprovalSession{probe: engine.ApprovalProbeOK + "\n"}
	eng := mustEngine(t, engine.NameClaude, engine.SecretCredential{})
	base := eng.RunCommand("p", false, false, "")
	var diag bytes.Buffer

	got, note, err := prepareApprovals(context.Background(), sess, eng, "code", base, 30*time.Minute, &diag)
	if err != nil {
		t.Fatal(err)
	}
	if note != "" {
		t.Errorf("a Claude run got a hookless note %q", note)
	}
	m := regexp.MustCompile(`--public-key ([0-9a-f]+) `).FindStringSubmatch(got)
	if m == nil {
		t.Fatalf("no --public-key in the command:\n%s", got)
	}
	pub, err := coderun.ParseApprovalPublicKey(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := engine.WithApprovals(eng, base, "code", pub, 30*time.Minute); got != want {
		t.Errorf("command = %q, want engine.WithApprovals' %q", got, want)
	}
	// The box holds no secret, and setup changes nothing on it: the only
	// command sent is the read-only probe.
	if len(sess.writes) != 0 || len(sess.execs) != 1 || !strings.Contains(sess.execs[0], "--probe") {
		t.Errorf("setup touched the box: execs=%v writes=%v", sess.execs, sess.writes)
	}
	// A second run gets a different key.
	again, _, _ := prepareApprovals(context.Background(), &fakeApprovalSession{probe: engine.ApprovalProbeOK}, eng, "code", base, 30*time.Minute, &bytes.Buffer{})
	if again == got {
		t.Error("two runs got the same public key")
	}
	if !strings.Contains(diag.String(), "expires into a deny") {
		t.Errorf("diag does not say unanswered prompts expire into a deny: %q", diag.String())
	}
}

// A name whose approval files would not sit plainly next to the run log is
// refused before anything on the box is touched, for every engine.
func TestPrepareApprovalsRefusesUnsafeRunNamesFirst(t *testing.T) {
	for _, n := range []engine.Name{engine.NameClaude, engine.NamePi} {
		for _, name := range []string{"sub/task", "../victim", ".."} {
			sess := &fakeApprovalSession{probe: engine.ApprovalProbeOK}
			_, _, err := prepareApprovals(context.Background(), sess, mustEngine(t, n, engine.SecretCredential{}), name, "cmd", time.Minute, &bytes.Buffer{})
			if err == nil {
				t.Errorf("%s/%q: accepted", n, name)
			}
			if len(sess.execs) != 0 || len(sess.writes) != 0 {
				t.Errorf("%s/%q: touched the box: execs=%v writes=%v", n, name, sess.execs, sess.writes)
			}
		}
	}
}

func TestPrepareApprovalsRefusesAnAgentBoxWithoutTheMode(t *testing.T) {
	sess := &fakeApprovalSession{probe: ""}
	eng := mustEngine(t, engine.NameClaude, engine.SecretCredential{})
	_, _, err := prepareApprovals(context.Background(), sess, eng, "code", "cmd", time.Minute, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "newer agent-box") {
		t.Fatalf("err = %v, want the newer-agent-box error", err)
	}
}

// pi has no permission hook: the run starts unchanged, the CLI warns, and the
// note the caller journals after process_start records why nothing will pause.
func TestPrepareApprovalsHooklessEngineWarnsAndJournals(t *testing.T) {
	sess := &fakeApprovalSession{}
	eng := mustEngine(t, engine.NamePi, engine.SecretCredential{})
	base := eng.RunCommand("p", false, false, "")
	var diag bytes.Buffer

	got, note, err := prepareApprovals(context.Background(), sess, eng, "code", base, time.Minute, &diag)
	if err != nil {
		t.Fatal(err)
	}
	if got != base {
		t.Errorf("command changed for a hookless engine:\n%s", got)
	}
	if !strings.HasPrefix(diag.String(), "warning: engine pi has no permission hook") || strings.Count(diag.String(), "\n") != 1 {
		t.Errorf("diag = %q, want one warning line", diag.String())
	}
	if len(sess.execs) != 0 || len(sess.writes) != 0 {
		t.Errorf("setup touched the box before process_start: execs=%v writes=%v", sess.execs, sess.writes)
	}

	journalApprovalNote(context.Background(), sess, "code", note, &diag)
	w, ok := sess.writes[coderun.ApprovalJournalPath("code")]
	if !ok {
		t.Fatal("nothing journaled")
	}
	ev := coderun.ParseInputJournal([]byte(w.content))
	if len(ev) != 1 || ev[0].Kind != coderun.KindInputStatus || !strings.Contains(ev[0].Text, "engine pi has no permission hook") {
		t.Errorf("journal = %+v", ev)
	}
}

func TestValidateApprovalFlags(t *testing.T) {
	defer func(a string, d time.Duration) { codeRunApprovals, codeRunApprovalTimeout = a, d }(codeRunApprovals, codeRunApprovalTimeout)

	codeRunApprovals, codeRunApprovalTimeout = "ask", time.Minute
	if m, err := validateApprovalFlags(); err != nil || m != coderun.ApprovalsAsk {
		t.Errorf("ask = %q, %v", m, err)
	}
	codeRunApprovals = "yes"
	if _, err := validateApprovalFlags(); err == nil {
		t.Error("--approvals yes accepted")
	}
	codeRunApprovals, codeRunApprovalTimeout = "ask", 0
	if _, err := validateApprovalFlags(); err == nil {
		t.Error("--approval-timeout 0 accepted")
	}
}

// --approvals defaults to deny, today's behaviour.
func TestApprovalsFlagDefaultsToDeny(t *testing.T) {
	f := codeRunCmd.Flags().Lookup("approvals")
	if f == nil || f.DefValue != string(coderun.ApprovalsDeny) {
		t.Fatalf("--approvals default = %v, want deny", f)
	}
	if f := codeRunCmd.Flags().Lookup("approval-timeout"); f == nil || f.DefValue != "30m0s" {
		t.Fatalf("--approval-timeout default = %v, want 30m0s", f)
	}
}
