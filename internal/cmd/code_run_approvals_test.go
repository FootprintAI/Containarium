package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/coderun/engine"
)

// fakeApprovalSession records what prepareApprovals does to the box.
type fakeApprovalSession struct {
	listing string
	probe   string // what the probe prints
	execs   []string
	writes  map[string]struct{ content, mode string }
}

func (f *fakeApprovalSession) ProcessList(context.Context) (string, error) { return f.listing, nil }

func (f *fakeApprovalSession) ShellExec(_ context.Context, command string) (string, error) {
	f.execs = append(f.execs, command)
	if strings.Contains(command, "approval-mcp --probe") {
		return f.probe, nil
	}
	return "reset-ok\n", nil
}

func (f *fakeApprovalSession) WriteFile(_ context.Context, path, content, mode string) error {
	if f.writes == nil {
		f.writes = map[string]struct{ content, mode string }{}
	}
	f.writes[path] = struct{ content, mode string }{content, mode}
	return nil
}

func TestPrepareApprovalsClaudeDeliversKeyAndWiresCommand(t *testing.T) {
	sess := &fakeApprovalSession{probe: engine.ApprovalProbeOK + "\n"}
	eng := mustEngine(t, engine.NameClaude, engine.SecretCredential{})
	base := eng.RunCommand("p", false, false, "")
	var diag bytes.Buffer

	got, err := prepareApprovals(context.Background(), sess, eng, "code", base, 30*time.Minute, &diag)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := engine.WithApprovals(eng, base, "code", 30*time.Minute); got != want {
		t.Errorf("command = %q, want engine.WithApprovals' %q", got, want)
	}

	w, ok := sess.writes[coderun.ApprovalKeyPath("code")]
	if !ok {
		t.Fatalf("no key written; writes = %v", sess.writes)
	}
	if w.mode != "0600" {
		t.Errorf("key written with mode %s, want 0600", w.mode)
	}
	if k, err := hex.DecodeString(w.content); err != nil || len(k) != coderun.ApprovalKeyBytes {
		t.Errorf("key content %q is not %d hex bytes", w.content, coderun.ApprovalKeyBytes)
	}
	// The key is file content only: never in a command sent to the box.
	for _, c := range append(sess.execs, got) {
		if strings.Contains(c, w.content) {
			t.Errorf("the key appears in a command: %q", c)
		}
	}
	if len(sess.execs) == 0 || !strings.Contains(sess.execs[0], "rm -rf '/tmp/agent-box/code.input.jsonl' '/tmp/agent-box/code.answers' '/tmp/agent-box/code.approval-key'") {
		t.Errorf("first exec does not clear the previous run's approval files: %v", sess.execs)
	}
	if !strings.Contains(diag.String(), "expires into a deny") {
		t.Errorf("diag does not say unanswered prompts expire into a deny: %q", diag.String())
	}
}

func TestPrepareApprovalsRefusesAnAgentBoxWithoutTheMode(t *testing.T) {
	sess := &fakeApprovalSession{probe: ""}
	eng := mustEngine(t, engine.NameClaude, engine.SecretCredential{})
	_, err := prepareApprovals(context.Background(), sess, eng, "code", "cmd", time.Minute, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "newer agent-box") {
		t.Fatalf("err = %v, want the newer-agent-box error", err)
	}
	if _, wrote := sess.writes[coderun.ApprovalKeyPath("code")]; wrote {
		t.Error("a key was delivered to a box that cannot consume it")
	}
}

// A same-name run that is still alive keeps its journal: nothing on the box is
// touched.
func TestPrepareApprovalsLeavesALiveRunAlone(t *testing.T) {
	sess := &fakeApprovalSession{
		listing: "▶ code  (pid 42, running)\n",
		probe:   engine.ApprovalProbeOK,
	}
	_, err := prepareApprovals(context.Background(), sess, mustEngine(t, engine.NameClaude, engine.SecretCredential{}), "code", "cmd", time.Minute, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("err = %v, want already running", err)
	}
	if len(sess.execs) != 0 || len(sess.writes) != 0 {
		t.Errorf("touched the box: execs=%v writes=%v", sess.execs, sess.writes)
	}
}

// pi has no permission hook: the run starts unchanged, the CLI warns, and the
// journal records why nothing will pause.
func TestPrepareApprovalsHooklessEngineWarnsAndJournals(t *testing.T) {
	sess := &fakeApprovalSession{}
	eng := mustEngine(t, engine.NamePi, engine.SecretCredential{})
	base := eng.RunCommand("p", false, false, "")
	var diag bytes.Buffer

	got, err := prepareApprovals(context.Background(), sess, eng, "code", base, time.Minute, &diag)
	if err != nil {
		t.Fatal(err)
	}
	if got != base {
		t.Errorf("command changed for a hookless engine:\n%s", got)
	}
	if !strings.HasPrefix(diag.String(), "warning: engine pi has no permission hook") || strings.Count(diag.String(), "\n") != 1 {
		t.Errorf("diag = %q, want one warning line", diag.String())
	}
	w, ok := sess.writes[coderun.ApprovalJournalPath("code")]
	if !ok {
		t.Fatal("nothing journaled")
	}
	ev := coderun.ParseInputJournal([]byte(w.content))
	if len(ev) != 1 || ev[0].Kind != coderun.KindInputStatus || !strings.Contains(ev[0].Text, "engine pi has no permission hook") {
		t.Errorf("journal = %+v", ev)
	}
	if _, wrote := sess.writes[coderun.ApprovalKeyPath("code")]; wrote {
		t.Error("a key was delivered for a run that cannot use it")
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
