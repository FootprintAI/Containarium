package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// A synthetic value, odd enough that finding it in output is never a coincidence.
const testRunTokenValue = "synthetic-run-token-5e2a.not-a-credential"

// fakeCodeRunDaemon is the daemon client `code run --run-token-file` talks to.
type fakeCodeRunDaemon struct {
	startErr error
	exitCode *int32
	log      string

	starts []*pb.StartBoxRunRequest
	tails  []*pb.TailBoxRunLogRequest
	lists  int
	closed bool
}

func (f *fakeCodeRunDaemon) StartBoxRun(req *pb.StartBoxRunRequest) (*pb.StartBoxRunResponse, error) {
	f.starts = append(f.starts, req)
	if f.startErr != nil {
		return nil, f.startErr
	}
	name := req.GetRunName()
	if name == "" {
		name = "code"
	}
	return &pb.StartBoxRunResponse{Run: &pb.BoxRun{RunName: name, LogPath: "/tmp/agent-box/" + name + ".log"}}, nil
}

func (f *fakeCodeRunDaemon) TailBoxRunLog(req *pb.TailBoxRunLogRequest) (*pb.TailBoxRunLogResponse, error) {
	f.tails = append(f.tails, req)
	chunk := []byte(f.log)[req.GetStartOffset():]
	return &pb.TailBoxRunLogResponse{Chunk: chunk, EndOffset: int64(len(f.log)), Ended: true}, nil
}

func (f *fakeCodeRunDaemon) ListBoxRuns(string) ([]*pb.BoxRun, error) {
	f.lists++
	name := "code"
	if len(f.starts) > 0 && f.starts[0].GetRunName() != "" {
		name = f.starts[0].GetRunName()
	}
	return []*pb.BoxRun{{RunName: "another"}, {RunName: name, ExitCode: f.exitCode, Outcome: pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED}}, nil
}

func (f *fakeCodeRunDaemon) Close() error { f.closed = true; return nil }

// codeRunTokenFixture sets up one `code run --run-token-file` call: clean
// flags, a fake daemon client, and a count of how often a client was asked for.
type codeRunTokenFixture struct {
	daemon      *fakeCodeRunDaemon
	clientCalls int
	out, diag   bytes.Buffer
}

func newCodeRunTokenFixture(t *testing.T) *codeRunTokenFixture {
	t.Helper()
	saved := struct {
		prompt, session, name, command, tokenTTL, approvals, tokenFile string
		cont, streamJSON                                               bool
		timeout                                                        time.Duration
		newClient                                                      func() (codeRunDaemonAPI, error)
	}{codeRunPrompt, codeRunSession, codeName, codeRunCommand, codeRunTokenTTL, codeRunApprovals, codeRunTokenFile,
		codeRunContinue, codeRunStreamJSON, codeRunTimeout, newCodeRunDaemonClient}
	t.Cleanup(func() {
		codeRunPrompt, codeRunSession, codeName, codeRunCommand = saved.prompt, saved.session, saved.name, saved.command
		codeRunTokenTTL, codeRunApprovals, codeRunTokenFile = saved.tokenTTL, saved.approvals, saved.tokenFile
		codeRunContinue, codeRunStreamJSON, codeRunTimeout = saved.cont, saved.streamJSON, saved.timeout
		newCodeRunDaemonClient = saved.newClient
	})
	codeRunPrompt, codeRunSession, codeName, codeRunCommand, codeRunTokenTTL, codeRunTokenFile = "", "", "", "", "", ""
	codeRunApprovals = string(coderun.ApprovalsDeny)
	codeRunContinue, codeRunStreamJSON, codeRunTimeout = false, false, 0

	f := &codeRunTokenFixture{daemon: &fakeCodeRunDaemon{log: "agent output\n"}}
	newCodeRunDaemonClient = func() (codeRunDaemonAPI, error) {
		f.clientCalls++
		return f.daemon, nil
	}
	return f
}

// run calls runCodeRun, the handler behind `containarium code run <box>`.
func (f *codeRunTokenFixture) run(box string) error {
	cmd := &cobra.Command{}
	cmd.SetOut(&f.out)
	cmd.SetErr(&f.diag)
	cmd.SetContext(context.Background())
	return runCodeRun(cmd, []string{box})
}

// noTokenAnywhere fails if the token shows up in anything a person or a log
// would see.
func (f *codeRunTokenFixture) noTokenAnywhere(t *testing.T, err error) {
	t.Helper()
	for what, s := range map[string]string{"stdout": f.out.String(), "stderr": f.diag.String()} {
		if strings.Contains(s, testRunTokenValue) {
			t.Errorf("the token was written to %s: %q", what, s)
		}
	}
	if err != nil && strings.Contains(err.Error(), testRunTokenValue) {
		t.Errorf("the token is in the error: %q", err)
	}
}

func writeRunTokenFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "run-token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// #3610: --run-token-file starts the run through StartBoxRun with the file's
// token. No SSH session is resolved: this test has no server and no SSH fake,
// so a run that took the SSH path would fail before reaching the fake daemon.
func TestCodeRunTokenFile_StartsThroughStartBoxRun(t *testing.T) {
	f := newCodeRunTokenFixture(t)
	codeRunPrompt, codeName = "fix the bug", "issue-1"
	codeRunTokenFile = writeRunTokenFile(t, testRunTokenValue+"\n")

	err := f.run("alice")
	if err != nil {
		t.Fatalf("code run --run-token-file: %v", err)
	}
	if len(f.daemon.starts) != 1 {
		t.Fatalf("StartBoxRun was called %d time(s), want 1", len(f.daemon.starts))
	}
	got := f.daemon.starts[0]
	if got.GetRunToken() != testRunTokenValue {
		t.Errorf("run_token sent = %q, want the file's token without its trailing newline", got.GetRunToken())
	}
	if got.GetUsername() != "alice" || got.GetPrompt() != "fix the bug" || got.GetRunName() != "issue-1" || got.GetCommand() != "" {
		t.Errorf("request = %v", got)
	}
	if !strings.Contains(f.diag.String(), `started "issue-1" on alice`) {
		t.Errorf("stderr = %q, want the started line", f.diag.String())
	}
	// The run's output is streamed, as on the SSH path.
	if f.out.String() != "agent output\n" {
		t.Errorf("stdout = %q, want the run's log", f.out.String())
	}
	if len(f.daemon.tails) == 0 || f.daemon.tails[0].GetRunName() != "issue-1" || f.daemon.tails[0].GetUsername() != "alice" {
		t.Errorf("TailBoxRunLog calls = %v", f.daemon.tails)
	}
	if !f.daemon.closed {
		t.Error("the daemon client was not closed")
	}
	f.noTokenAnywhere(t, err)
}

func TestCodeRunTokenFile_RequestFromFlags(t *testing.T) {
	t.Run("--session and the default name", func(t *testing.T) {
		f := newCodeRunTokenFixture(t)
		codeRunPrompt, codeRunSession = "go on", "sess-42"
		codeRunTokenFile = writeRunTokenFile(t, testRunTokenValue)
		if err := f.run("alice"); err != nil {
			t.Fatal(err)
		}
		got := f.daemon.starts[0]
		// No --name: the daemon applies its own default (the session id).
		if got.GetSessionId() != "sess-42" || got.GetContinueSession() || got.GetRunName() != "" || got.GetRunToken() != testRunTokenValue {
			t.Errorf("request = %v", got)
		}
	})
	t.Run("--continue", func(t *testing.T) {
		f := newCodeRunTokenFixture(t)
		codeRunPrompt, codeRunContinue = "go on", true
		codeRunTokenFile = writeRunTokenFile(t, testRunTokenValue)
		if err := f.run("alice"); err != nil {
			t.Fatal(err)
		}
		if got := f.daemon.starts[0]; !got.GetContinueSession() || got.GetSessionId() != "" {
			t.Errorf("request = %v", got)
		}
	})
	t.Run("--command with --timeout", func(t *testing.T) {
		f := newCodeRunTokenFixture(t)
		codeRunCommand, codeRunTimeout = "make test", 90*time.Second
		codeRunTokenFile = writeRunTokenFile(t, testRunTokenValue)
		if err := f.run("alice"); err != nil {
			t.Fatal(err)
		}
		got := f.daemon.starts[0]
		if got.GetCommand() != "make test" || got.GetTimeoutSeconds() != 90 || got.GetPrompt() != "" || got.GetRunToken() != testRunTokenValue {
			t.Errorf("request = %v", got)
		}
	})
}

// An unreadable, empty or malformed token file is an error before any call:
// no daemon client is even opened.
func TestCodeRunTokenFile_BadFileIsRefusedBeforeAnyCall(t *testing.T) {
	tests := []struct {
		name string
		path func(t *testing.T) string
		want string
	}{
		{"a file that does not exist", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent") }, "read the run token file"},
		{"a directory", func(t *testing.T) string { return t.TempDir() }, "read the run token file"},
		{"an empty file", func(t *testing.T) string { return writeRunTokenFile(t, "") }, "is empty"},
		{"a file of whitespace", func(t *testing.T) string { return writeRunTokenFile(t, " \n\t\n") }, "is empty"},
		{"two lines", func(t *testing.T) string { return writeRunTokenFile(t, testRunTokenValue+"\nsecond-line\n") }, "one line"},
		{"a NUL byte", func(t *testing.T) string { return writeRunTokenFile(t, testRunTokenValue+"\x00tail") }, "one line"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newCodeRunTokenFixture(t)
			codeRunPrompt = "fix the bug"
			codeRunTokenFile = tc.path(t)
			err := f.run("alice")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "--run-token-file") {
				t.Errorf("err = %q, want it to name --run-token-file", err)
			}
			if f.clientCalls != 0 || len(f.daemon.starts) != 0 {
				t.Errorf("a call was made: client opened %d time(s), StartBoxRun %d time(s)", f.clientCalls, len(f.daemon.starts))
			}
			f.noTokenAnywhere(t, err)
		})
	}
}

// Flags that only mean something on the SSH path are refused, not ignored,
// and before any call.
func TestCodeRunTokenFile_FlagsOfTheSSHPathAreRefused(t *testing.T) {
	tests := []struct {
		name string
		set  func()
		want string
	}{
		{"--approvals ask", func() { codeRunPrompt, codeRunApprovals = "p", string(coderun.ApprovalsAsk) }, "--approvals"},
		{"--output-format-stream-json", func() { codeRunPrompt, codeRunStreamJSON = "p", true }, "--output-format-stream-json"},
		{"--token-ttl", func() { codeRunPrompt, codeRunTokenTTL = "p", "2h" }, "--token-ttl"},
		{"--session with --continue", func() { codeRunPrompt, codeRunSession, codeRunContinue = "p", "s", true }, "--continue"},
		{"--command with --prompt", func() { codeRunPrompt, codeRunCommand = "p", "ls" }, "--command"},
		{"--timeout without --command", func() { codeRunPrompt, codeRunTimeout = "p", time.Minute }, "--timeout"},
		{"neither --prompt nor --command", func() {}, "--prompt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newCodeRunTokenFixture(t)
			codeRunTokenFile = writeRunTokenFile(t, testRunTokenValue)
			tc.set()
			err := f.run("alice")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want a refusal naming %s", err, tc.want)
			}
			if f.clientCalls != 0 {
				t.Errorf("a daemon client was opened %d time(s) for a refused call", f.clientCalls)
			}
			f.noTokenAnywhere(t, err)
		})
	}
}

// The command's exit status follows the run's, as on the SSH path.
func TestCodeRunTokenFile_ExitStatusFollowsTheRun(t *testing.T) {
	code := func(c int32) *int32 { return &c }
	tests := []struct {
		name     string
		exitCode *int32
		wantErr  string
	}{
		{"exit 0", code(0), ""},
		{"exit 3", code(3), `run "code" exited with code 3`},
		{"no exit code recorded", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newCodeRunTokenFixture(t)
			f.daemon.exitCode = tc.exitCode
			codeRunPrompt = "fix the bug"
			codeRunTokenFile = writeRunTokenFile(t, testRunTokenValue)
			err := f.run("alice")
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("err = %v, want none", err)
			case tc.wantErr != "" && (err == nil || err.Error() != tc.wantErr):
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if f.daemon.lists == 0 {
				t.Error("the run's exit code was never read")
			}
		})
	}
}

// A refused start is reported and nothing is streamed; the token stays out of
// the report.
func TestCodeRunTokenFile_StartRefused(t *testing.T) {
	f := newCodeRunTokenFixture(t)
	f.daemon.startErr = errors.New("this daemon does not take a per-run token")
	codeRunPrompt = "fix the bug"
	codeRunTokenFile = writeRunTokenFile(t, testRunTokenValue)
	err := f.run("alice")
	if err == nil || !strings.Contains(err.Error(), "does not take a per-run token") || !strings.Contains(err.Error(), `"alice"`) {
		t.Fatalf("err = %v", err)
	}
	if len(f.daemon.tails) != 0 || f.out.Len() != 0 {
		t.Errorf("output was streamed after a refused start: tails=%d stdout=%q", len(f.daemon.tails), f.out.String())
	}
	if !f.daemon.closed {
		t.Error("the daemon client was not closed")
	}
	f.noTokenAnywhere(t, err)
}

// Without --run-token-file the handler is the SSH path's. The input is one
// only the SSH path accepts (--approvals ask; the daemon path refuses it before
// any client), so the test asserts the SSH path's next step was reached: it
// fetches the daemon's approval key through newRunInputsClient. A tokenless run
// sent down the daemon path never makes that call, and opening the daemon-API
// client at all fails the test.
func TestCodeRun_WithoutTokenFileNeverOpensTheDaemonPath(t *testing.T) {
	f := newCodeRunTokenFixture(t)
	newCodeRunDaemonClient = func() (codeRunDaemonAPI, error) {
		t.Error("the daemon-API client was opened without --run-token-file")
		return f.daemon, nil
	}
	savedInputs := newRunInputsClient
	t.Cleanup(func() { newRunInputsClient = savedInputs })
	sshPathStep := errors.New("ssh path: approval key fetched")
	inputsCalls := 0
	newRunInputsClient = func() (runInputsAPI, error) {
		inputsCalls++
		return nil, sshPathStep
	}
	codeRunPrompt, codeRunApprovals = "fix the bug", string(coderun.ApprovalsAsk)

	err := f.run("alice")
	if !errors.Is(err, sshPathStep) {
		t.Fatalf("err = %v, want the SSH path's approval-key step to be reached", err)
	}
	if inputsCalls != 1 {
		t.Errorf("the SSH path's approval-key client was asked for %d time(s), want 1", inputsCalls)
	}
}
