package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/connectcore"
	"github.com/footprintai/containarium/internal/sshkey"
)

// Platform-MCP wrappers for `containarium code` (#1698). Every operation here
// is the SAME internal/coderun function the CLI handler calls — CLAUDE.md's
// CLI-first rule, which had been running one-directional: the verb shipped in
// #1673/#1674 with no MCP counterpart, so an agent could create a box and
// expose a port but could not start a coding run on one or reattach to it.
//
// The streaming shape differs by necessity. The CLI streams to a terminal
// until interrupted; MCP is request/response, so `code_run` and `code_attach`
// return a BOUNDED window plus the offset to resume from, mirroring tail_log's
// existing contract. An agent that carries `next_offset` across calls gets
// exactly the disconnect-tolerant behavior a human gets from the CLI.

// codeReadWindow bounds how long one code_run/code_attach call waits for new
// output. Long enough that a caller polling in a loop sees steady progress,
// short enough that no single MCP call looks hung.
const codeReadWindow = 5 * time.Second

// mcpCodeSession resolves box and opens an MCP session to its agent-box over
// SSH — the same transport `connect` uses, so key/certificate handling stays
// in one place rather than being reimplemented per tool.
func mcpCodeSession(client API, box string) (*coderun.Session, func(), error) {
	target, privPath, cleanup, err := mcpCodeTarget(client, box)
	if err != nil {
		return nil, nil, err
	}
	// No remote command — Connect appends "agent-box" itself.
	sess, err := coderun.Connect(context.Background(), connectcore.BuildSSHArgs(target, privPath, ""))
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("connect to agent-box on %q: %w", box, err)
	}
	return sess, func() { _ = sess.Close(); cleanup() }, nil
}

// mcpCodeTarget resolves the SSH target and an identity for box, preferring a
// short-lived certificate and falling back to the managed key — the same
// preference order handleConnect uses, and for the same reason: a certificate
// leaves nothing installed on the box.
func mcpCodeTarget(client API, box string) (connectcore.Target, string, func(), error) {
	target, err := mcpWaitConnectable(client, box, "", "")
	if err != nil {
		return connectcore.Target{}, "", nil, err
	}

	cert, err := issueCertForBox(client, target.User)
	switch {
	case err == nil:
		return target, cert.PrivateKeyPath, cert.Cleanup, nil
	case errors.Is(err, errCertUnsupported):
		pubPath, pub, _, kerr := sshkey.LocateOrGenerate(sshkey.LocateOpts{})
		if kerr != nil {
			return connectcore.Target{}, "", nil, fmt.Errorf("locate or generate managed key: %w", kerr)
		}
		if aerr := mcpAuthorizeKey(client, box, pub); aerr != nil {
			return connectcore.Target{}, "", nil, fmt.Errorf("authorize key on %q: %w", box, aerr)
		}
		return target, strings.TrimSuffix(pubPath, ".pub"), func() {}, nil
	default:
		// The server COULD sign and something went wrong. Falling back would
		// install a long-lived key to paper over a control-plane fault and
		// never mention it — surface it instead.
		return connectcore.Target{}, "", nil, fmt.Errorf("issue certificate for %q: %w", box, err)
	}
}

func codeRunNameArg(args map[string]interface{}) string {
	if n := strings.TrimSpace(getStringArg(args, "name", "")); n != "" {
		return n
	}
	return coderun.DefaultRunName
}

// handleCodeRun starts a detached coding run and returns the first window of
// its output. The run outlives this call — that is the entire point — so the
// response carries what a caller needs to follow it: the run name and the
// offset to resume from.
func handleCodeRun(client API, args map[string]interface{}) (string, error) {
	box := strings.TrimSpace(getStringArg(args, "box", ""))
	if box == "" {
		return "", fmt.Errorf("`box` is required")
	}
	prompt := strings.TrimSpace(getStringArg(args, "prompt", ""))
	if prompt == "" {
		return "", fmt.Errorf("`prompt` is required")
	}
	streamJSON := getBoolArg(args, "stream_json", false)
	name := codeRunNameArg(args)

	sess, done, err := mcpCodeSession(client, box)
	if err != nil {
		return "", err
	}
	defer done()

	ctx := context.Background()
	started, err := sess.ProcessStart(ctx,
		name,
		coderun.BuildClaudeRunCommand(prompt, streamJSON),
		"",
		coderun.CaptureModeFor(streamJSON),
	)
	if err != nil {
		return "", fmt.Errorf("start run on %q: %w", box, err)
	}

	out, next := readCodeWindow(ctx, sess, started.LogPath, 0, streamJSON)
	return fmt.Sprintf(
		"✓ started %q (pid %d) on %s\n\nlog_path: %s\nnext_offset: %d\n\n--- output so far ---\n%s\n"+
			"(the run continues on the box — call code_attach with name=%q and offset=%d for more)",
		started.Name, started.PID, box, started.LogPath, next, out, started.Name, next), nil
}

// handleCodeAttach resumes a run's output from a byte offset. Passing back the
// previous call's next_offset is what makes reconnection lossless: the reader
// never re-derives a position, so nothing is skipped and nothing repeats.
func handleCodeAttach(client API, args map[string]interface{}) (string, error) {
	box := strings.TrimSpace(getStringArg(args, "box", ""))
	if box == "" {
		return "", fmt.Errorf("`box` is required")
	}
	name := codeRunNameArg(args)
	var offset int64
	if v, ok := getIntArg(args, "offset"); ok && v > 0 {
		offset = int64(v)
	}
	streamJSON := getBoolArg(args, "stream_json", false)

	sess, done, err := mcpCodeSession(client, box)
	if err != nil {
		return "", err
	}
	defer done()

	ctx := context.Background()
	listing, err := sess.ProcessList(ctx)
	if err != nil {
		return "", fmt.Errorf("process_list on %q: %w", box, err)
	}
	line, running := coderun.RunOutcomeLine(listing, name)
	if line == "" {
		return "", fmt.Errorf("no run named %q on %q — start one with code_run", name, box)
	}
	logPath, err := coderun.LogPathFromListing(listing, name)
	if err != nil {
		return "", err
	}

	out, next := readCodeWindow(ctx, sess, logPath, offset, streamJSON)
	tail := fmt.Sprintf("(still running — call again with offset=%d)", next)
	if !running {
		// Say so explicitly: an agent polling a finished run would otherwise
		// keep asking forever for output that will never arrive.
		tail = "(run has finished; this is the end of its output)"
	}
	return fmt.Sprintf("%s\n\nnext_offset: %d\n\n--- output ---\n%s\n%s", line, next, out, tail), nil
}

// handleCodeStatus reports liveness and, once finished, the exit code.
func handleCodeStatus(client API, args map[string]interface{}) (string, error) {
	box := strings.TrimSpace(getStringArg(args, "box", ""))
	if box == "" {
		return "", fmt.Errorf("`box` is required")
	}
	name := codeRunNameArg(args)

	sess, done, err := mcpCodeSession(client, box)
	if err != nil {
		return "", err
	}
	defer done()

	listing, err := sess.ProcessList(context.Background())
	if err != nil {
		return "", fmt.Errorf("process_list on %q: %w", box, err)
	}
	line, _ := coderun.RunOutcomeLine(listing, name)
	if line == "" {
		return fmt.Sprintf("no run named %q on %s", name, box), nil
	}
	return line, nil
}

// handleCodeStop reaps a run. The log is deliberately left readable so its
// output can still be collected afterwards.
func handleCodeStop(client API, args map[string]interface{}) (string, error) {
	box := strings.TrimSpace(getStringArg(args, "box", ""))
	if box == "" {
		return "", fmt.Errorf("`box` is required")
	}
	name := codeRunNameArg(args)

	sess, done, err := mcpCodeSession(client, box)
	if err != nil {
		return "", err
	}
	defer done()

	res, err := sess.ProcessKill(context.Background(), name, getBoolArg(args, "force", false))
	if err != nil {
		return "", fmt.Errorf("stop run %q on %q: %w", name, box, err)
	}
	return fmt.Sprintf("✓ stopped %q on %s (pid %d)\nlog kept at %s", name, box, res.PID, res.LogPath), nil
}

// readCodeWindow reads one bounded window from a run's log, returning the text
// and the offset to resume from. Framed output is demultiplexed so a caller
// sees the run's own stdout/stderr rather than the wire format.
func readCodeWindow(ctx context.Context, sess *coderun.Session, logPath string, offset int64, streamJSON bool) (string, int64) {
	var sb strings.Builder
	var w interface{ Write([]byte) (int, error) } = &sb
	if streamJSON {
		w = coderun.NewDemuxWriter(&sb, &sb)
	}
	next, err := coderun.StreamOutput(ctx, sess, w, logPath, offset, codeReadWindow, nil)
	if err != nil && sb.Len() == 0 {
		return fmt.Sprintf("(no output read: %v)", err), offset
	}
	return sb.String(), next
}
