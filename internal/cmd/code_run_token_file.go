package cmd

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/runlog"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium code run --run-token-file` (#3610): the opt-in daemon-API
// path. The run is started through StartBoxRun with the caller's per-run token
// instead of through an SSH session, then followed through TailBoxRunLog and
// ListBoxRuns, the reads `code logs` and `code runs` make. Without the flag
// nothing here runs.

// codeRunTokenFile is --run-token-file: a file holding the per-run token. The
// token is never taken as an argument (argv is world-readable on a shared
// host), never minted here, and never printed or logged.
var codeRunTokenFile string

func init() {
	codeRunCmd.Flags().StringVar(&codeRunTokenFile, "run-token-file", "",
		"start the run through the daemon API (StartBoxRun, needs --server) with the per-run token in this file, instead of over SSH; the daemon must advertise the box_run_token capability. The file holds the token on one line and is read, never printed. Not with --approvals ask, --output-format-stream-json or --token-ttl")
}

// codeRunDaemonAPI is what the daemon-API path needs from a daemon client.
// Both client.GRPCClient and client.HTTPClient satisfy it.
type codeRunDaemonAPI interface {
	client.CodeRunDaemonStarter
	runlog.BoxLister
	runlog.BoxTailer
	Close() error
}

// newCodeRunDaemonClient opens the daemon client; a variable so tests supply a
// fake.
var newCodeRunDaemonClient = func() (codeRunDaemonAPI, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--run-token-file starts the run through the daemon API: --server is required")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

// readRunTokenFile returns the token in path, without surrounding whitespace.
// The file must hold exactly one non-empty line. No error from here holds any
// of the file's content.
func readRunTokenFile(path string) (string, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the caller names its own token file
	if err != nil {
		return "", fmt.Errorf("--run-token-file: read the run token file: %w", err)
	}
	token := bytes.TrimSpace(raw)
	switch {
	case len(token) == 0:
		return "", fmt.Errorf("--run-token-file: %s is empty", path)
	case bytes.ContainsAny(token, "\n\r\x00"):
		return "", fmt.Errorf("--run-token-file: %s must hold the token on one line, and nothing else", path)
	}
	return string(token), nil
}

// codeRunDaemonRequest builds the StartBoxRun request from `code run`'s flags,
// without the token. Flags that only mean something on the SSH path are
// refused, except connection flags (--key, --host, ...), which are ignored.
func codeRunDaemonRequest(box string) (*pb.StartBoxRunRequest, error) {
	if err := validateBoxName(box); err != nil {
		return nil, err
	}
	switch {
	case codeRunApprovals != string(coderun.ApprovalsDeny):
		return nil, fmt.Errorf("--approvals %s is not available with --run-token-file (the daemon API has no permission-request hook for a run it starts)", codeRunApprovals)
	case codeRunStreamJSON:
		return nil, fmt.Errorf("--output-format-stream-json is not available with --run-token-file (it selects the SSH path's framed capture)")
	case codeRunTokenTTL != "":
		return nil, fmt.Errorf("--token-ttl is not available with --run-token-file (it bounds the gateway token the SSH path mints)")
	}
	if err := validateCodeRunWorkdir(); err != nil {
		return nil, err
	}
	// #3613: the daemon checks the directory under the home the run starts in.
	req := &pb.StartBoxRunRequest{Username: box, RunName: codeName, Workdir: codeRunWorkdir}
	if strings.TrimSpace(codeRunCommand) != "" {
		if strings.TrimSpace(codeRunPrompt) != "" || codeRunSession != "" || codeRunContinue {
			return nil, fmt.Errorf("--command is mutually exclusive with --prompt, --session and --continue")
		}
		secs, err := coderun.CommandTimeoutSeconds(codeRunTimeout)
		if err != nil {
			return nil, fmt.Errorf("--timeout: %w", err)
		}
		// #nosec G115 -- CommandTimeoutSeconds caps the value at one hour.
		req.Command, req.TimeoutSeconds = codeRunCommand, int32(secs)
		return req, nil
	}
	switch {
	case codeRunTimeout != 0:
		return nil, fmt.Errorf("--timeout applies to --command only")
	case strings.TrimSpace(codeRunPrompt) == "":
		return nil, fmt.Errorf("--prompt is required (or --command, to run a shell command instead of the agent)")
	case codeRunSession != "" && codeRunContinue:
		return nil, fmt.Errorf("--session and --continue are mutually exclusive (--session resumes one specific session; --continue resumes whichever the engine considers most recent)")
	}
	req.Prompt, req.SessionId, req.ContinueSession = codeRunPrompt, codeRunSession, codeRunContinue
	return req, nil
}

// runCodeRunWithToken is `code run --run-token-file`. Everything that can be
// refused locally (flags, the token file) is refused before a daemon client is
// opened.
func runCodeRunWithToken(cmd *cobra.Command, box string) error {
	req, err := codeRunDaemonRequest(box)
	if err != nil {
		return err
	}
	token, err := readRunTokenFile(codeRunTokenFile)
	if err != nil {
		return err
	}
	c, err := newCodeRunDaemonClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	started, err := client.StartCodeRun(cmd.Context(), client.CodeRunStart{RunToken: token, Daemon: c, Request: req})
	if err != nil {
		return fmt.Errorf("start run on %q: %w", box, err)
	}
	name := started.Run.GetRunName()
	if name == "" {
		// An older daemon that does not echo the name: the same default it applied.
		name = codeRunName()
	}
	diag := cmd.ErrOrStderr()
	fmt.Fprintf(diag, "✓ started %q on %s through the daemon API\n", name, box)

	if err := codeLogs(cmd, c, box, name, true, cmd.OutOrStdout(), diag); err != nil {
		return err
	}
	runs, err := c.ListBoxRuns(box)
	if err != nil {
		return fmt.Errorf("read the exit code of run %q on %s: %w", name, box, err)
	}
	return boxRunExitErr(runs, name)
}

// boxRunExitErr is codeRunExitErr for the daemon-API path: a non-zero recorded
// exit code is an error, and a run with none recorded is not reported as a
// failure.
func boxRunExitErr(runs []*pb.BoxRun, name string) error {
	for _, r := range runs {
		if r.GetRunName() != name {
			continue
		}
		if r.ExitCode != nil && r.GetExitCode() != 0 {
			return fmt.Errorf("run %q exited with code %d", name, r.GetExitCode())
		}
		return nil
	}
	return nil
}
