package cmd

import (
	"context"
	"crypto/ed25519"
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
	ShellExec(ctx context.Context, command string) (string, error)
	WriteFile(ctx context.Context, absPath, content, mode string) error
}

// prepareApprovals rewires command for --approvals ask. It runs after
// prepareCodeRun and before process_start, and changes nothing on the box: a
// previous same-name run's approval files are rotated aside by process_start
// itself, with that run's log, and only once the new run actually starts.
//
// pub is the box's approval public key from the daemon (GetRunApprovalKey,
// #2184). Only the public key goes to the box (on the approval server's
// command line); the daemon holds the private key and signs answers to this
// run's requests (`code answer`, `code attach`), so the box holds no secret.
//
// For an engine with no permission hook the command is returned unchanged with
// a non-empty note, which the caller journals once the run has started.
func prepareApprovals(ctx context.Context, sess approvalSession, eng engine.Engine, name, command string,
	pub ed25519.PublicKey, timeout time.Duration, diag io.Writer) (wired, note string, err error) {

	// The approval files are named after the run.
	if err := coderun.ValidApprovalRunName(name); err != nil {
		return "", "", err
	}

	if !engine.SupportsApprovals(eng.Name()) {
		fmt.Fprintf(diag, "warning: engine %s has no permission hook; --approvals ask cannot pause this run, gated actions follow the engine's own behaviour\n", eng.Name())
		return command, fmt.Sprintf("--approvals ask requested, but engine %s has no permission hook; gated actions follow the engine's own behaviour", eng.Name()), nil
	}

	if out, err := sess.ShellExec(ctx, engine.ApprovalProbeCommand()); err != nil || !strings.Contains(out, engine.ApprovalProbeOK) {
		return "", "", errors.New("--approvals ask needs a newer agent-box on the box (its approval-mcp mode is missing or older than this CLI); update agent-box and retry, or run without --approvals ask")
	}

	wired, _ = engine.WithApprovals(eng, command, name, pub, timeout)
	fmt.Fprintf(diag, "• --approvals ask: a permission prompt pauses the run for up to %s; answer it here (a / d + Enter), or with 'containarium code pending %s' and 'containarium code answer'.\n",
		timeout, codeRunBoxHint(name))
	return wired, "", nil
}

// fetchApprovalKey gets the box's approval public key from the daemon, before
// anything touches the box.
func fetchApprovalKey(newClient func() (runInputsAPI, error), box string) (ed25519.PublicKey, error) {
	c, err := newClient()
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.GetRunApprovalKey(box)
	if err != nil {
		return nil, fmt.Errorf("get the box's approval key from the daemon (it needs a daemon with permission-request answers): %w", err)
	}
	return coderun.ParseApprovalPublicKey(resp.GetPublicKey())
}

// journalApprovalNote writes note as the run's approval journal. Called right
// after process_start, so it lands after the previous run's journal was
// rotated aside. Best-effort: the run is already going.
func journalApprovalNote(ctx context.Context, sess approvalSession, name, note string, diag io.Writer) {
	line, err := coderun.InputEvent{Kind: coderun.KindInputStatus, T: time.Now().UTC(), Text: note}.MarshalLine()
	if err == nil {
		err = sess.WriteFile(ctx, coderun.ApprovalJournalPath(name), string(line), "0600")
	}
	if err != nil {
		fmt.Fprintf(diag, "note: could not journal that (non-fatal): %v\n", err)
	}
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
