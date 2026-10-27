package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/coderun/engine"
)

// `code run --approvals ask` (#2183): the client half. The box half is
// `agent-box approval-mcp` (internal/agentbox/approval.go).

var (
	codeRunApprovals       string
	codeRunApprovalTimeout time.Duration
)

// approvalSession is the part of coderun.Session the approval setup uses.
type approvalSession interface {
	ProcessList(ctx context.Context) (string, error)
	ShellExec(ctx context.Context, command string) (string, error)
	WriteFile(ctx context.Context, absPath, content, mode string) error
}

// prepareApprovals rewires command for --approvals ask and leaves the box ready
// for it: the previous same-name run's request files cleared, and this run's
// answer key delivered for the approval server to consume. It runs after
// prepareCodeRun and before process_start.
//
// The key is not kept on this machine: who holds it to sign answers (this CLI,
// the daemon for a phone answer) is decided with the answer command, not here.
// Until then requests can be seen in `code status` but expire into a deny.
func prepareApprovals(ctx context.Context, sess approvalSession, eng engine.Engine, name, command string,
	timeout time.Duration, diag io.Writer) (string, error) {

	// Never clear a live run's journal: process_start would refuse the name
	// anyway, but only after the files were gone.
	listing, err := sess.ProcessList(ctx)
	if err != nil {
		return "", fmt.Errorf("process_list: %w", err)
	}
	if _, running := coderun.RunOutcomeLine(listing, name); running {
		return "", fmt.Errorf("a run named %q is already running; stop it first or pick a different --name", name)
	}

	journal := coderun.ShellQuoteSingle(coderun.ApprovalJournalPath(name))
	answers := coderun.ShellQuoteSingle(coderun.ApprovalAnswersDir(name))
	key := coderun.ShellQuoteSingle(coderun.ApprovalKeyPath(name))
	reset := "mkdir -p " + coderun.ShellQuoteSingle(coderun.RunLogDir) + " && rm -rf " + journal + " " + answers + " " + key +
		" && mkdir -m 700 " + answers + " && echo reset-ok"
	if out, err := sess.ShellExec(ctx, reset); err != nil || !strings.Contains(out, "reset-ok") {
		return "", fmt.Errorf("prepare this run's approval files: %v %s", err, strings.TrimSpace(out))
	}

	if !engine.SupportsApprovals(eng.Name()) {
		fmt.Fprintf(diag, "warning: engine %s has no permission hook; --approvals ask cannot pause this run, gated actions follow the engine's own behaviour\n", eng.Name())
		line, err := coderun.InputEvent{
			Kind: coderun.KindInputStatus,
			T:    time.Now().UTC(),
			Text: fmt.Sprintf("--approvals ask requested, but engine %s has no permission hook; gated actions follow the engine's own behaviour", eng.Name()),
		}.MarshalLine()
		if err == nil {
			err = sess.WriteFile(ctx, coderun.ApprovalJournalPath(name), string(line), "0600")
		}
		if err != nil {
			fmt.Fprintf(diag, "note: could not journal that (non-fatal): %v\n", err)
		}
		return command, nil
	}

	if out, err := sess.ShellExec(ctx, engine.ApprovalProbeCommand()); err != nil || !strings.Contains(out, engine.ApprovalProbeOK) {
		return "", errors.New("--approvals ask needs a newer agent-box on the box (it has no approval-mcp mode); update agent-box and retry, or run without --approvals ask")
	}

	k := make([]byte, coderun.ApprovalKeyBytes)
	if _, err := rand.Read(k); err != nil {
		return "", fmt.Errorf("generate this run's approval key: %w", err)
	}
	// write_file creates the file 0600 from the start (temp file + rename), and
	// the key travels as file content over the MCP channel, never in a command
	// line where /proc/<pid>/cmdline would show it.
	if err := sess.WriteFile(ctx, coderun.ApprovalKeyPath(name), hex.EncodeToString(k), coderun.ApprovalKeyFileMode); err != nil {
		return "", err
	}

	wired, _ := engine.WithApprovals(eng, command, name, timeout)
	fmt.Fprintf(diag, "• --approvals ask: a permission prompt pauses the run for up to %s; see it with 'containarium code status %s'. No answer command ships yet, so an unanswered prompt expires into a deny.\n",
		timeout, codeRunBoxHint(name))
	return wired, nil
}

// codeRunBoxHint is the status hint's argument tail: the box is the user's own
// argument, so only a non-default --name needs repeating.
func codeRunBoxHint(name string) string {
	if name == defaultCodeRunName {
		return "<box>"
	}
	return "<box> --name " + name
}

// validateApprovalFlags checks --approvals / --approval-timeout before anything
// touches the box.
func validateApprovalFlags() (coderun.ApprovalMode, error) {
	mode, err := coderun.ParseApprovalMode(codeRunApprovals)
	if err != nil {
		return "", err
	}
	if codeRunApprovalTimeout <= 0 {
		return "", fmt.Errorf("--approval-timeout must be positive, got %s", codeRunApprovalTimeout)
	}
	return mode, nil
}
