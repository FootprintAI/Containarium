package client

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeCodeRunSession is the agent-box session of the SSH path.
type fakeCodeRunSession struct {
	result *coderun.ProcessStartResult
	err    error
	calls  [][]string
}

func (f *fakeCodeRunSession) ProcessStart(_ context.Context, name, command, cwd, captureMode string) (*coderun.ProcessStartResult, error) {
	f.calls = append(f.calls, []string{name, command, cwd, captureMode})
	return f.result, f.err
}

// fakeCodeRunDaemon is the daemon API of the token path.
type fakeCodeRunDaemon struct {
	err   error
	calls []*pb.StartBoxRunRequest
}

func (f *fakeCodeRunDaemon) StartBoxRun(req *pb.StartBoxRunRequest) (*pb.StartBoxRunResponse, error) {
	f.calls = append(f.calls, req)
	if f.err != nil {
		return nil, f.err
	}
	return &pb.StartBoxRunResponse{Run: &pb.BoxRun{RunName: req.GetRunName(), LogPath: "/tmp/agent-box/" + req.GetRunName() + ".log"}}, nil
}

// With a token the run starts through the daemon API, carrying the token, and
// the SSH session is never used, even when the caller has one.
func TestStartCodeRun_TokenGoesThroughTheDaemonAPI(t *testing.T) {
	sess := &fakeCodeRunSession{result: &coderun.ProcessStartResult{Name: "issue-1"}}
	daemon := &fakeCodeRunDaemon{}
	req := &pb.StartBoxRunRequest{Username: "alice", Prompt: "fix the bug", RunName: "issue-1"}

	started, err := StartCodeRun(context.Background(), CodeRunStart{
		Session: sess, Name: "issue-1", Command: "claude -p", CaptureMode: "combined",
		Daemon: daemon, Request: req, RunToken: testRunToken,
	})
	if err != nil {
		t.Fatalf("StartCodeRun: %v", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("the SSH session was used for a run with a token: %v", sess.calls)
	}
	if len(daemon.calls) != 1 {
		t.Fatalf("StartBoxRun was called %d time(s), want 1", len(daemon.calls))
	}
	got := daemon.calls[0]
	if got.GetRunToken() != testRunToken {
		t.Errorf("run_token sent = %q, want %q", got.GetRunToken(), testRunToken)
	}
	if got.GetUsername() != "alice" || got.GetPrompt() != "fix the bug" || got.GetRunName() != "issue-1" {
		t.Errorf("request sent = %v", got)
	}
	if req.GetRunToken() != "" {
		t.Error("the caller's request was given the token; StartCodeRun must send a copy")
	}
	if started.Process != nil || started.Run.GetRunName() != "issue-1" || started.Run.GetLogPath() != "/tmp/agent-box/issue-1.log" {
		t.Errorf("started = %+v", started)
	}
}

// Without a token nothing changes: the run starts through the SSH session,
// and the daemon API is not called even when the caller has a client.
func TestStartCodeRun_NoTokenStaysOnTheSSHSession(t *testing.T) {
	want := &coderun.ProcessStartResult{Name: "code", PID: 7, LogPath: "/tmp/agent-box/code.log"}
	sess := &fakeCodeRunSession{result: want}
	daemon := &fakeCodeRunDaemon{}

	started, err := StartCodeRun(context.Background(), CodeRunStart{
		Session: sess, Name: "code", Command: "claude -p", CaptureMode: "framed",
		Daemon: daemon, Request: &pb.StartBoxRunRequest{Username: "alice", Prompt: "fix the bug"},
	})
	if err != nil {
		t.Fatalf("StartCodeRun: %v", err)
	}
	if len(daemon.calls) != 0 {
		t.Fatalf("the daemon API was called for a run without a token: %v", daemon.calls)
	}
	if len(sess.calls) != 1 || strings.Join(sess.calls[0], "|") != "code|claude -p||framed" {
		t.Fatalf("ProcessStart calls = %v", sess.calls)
	}
	if started.Process != want || started.Run != nil {
		t.Errorf("started = %+v", started)
	}
}

// #3613: the SSH path starts the run in the directory the caller resolved
// with coderun.Session.ResolveWorkdir.
func TestStartCodeRun_SSHPathStartsInCwd(t *testing.T) {
	sess := &fakeCodeRunSession{result: &coderun.ProcessStartResult{Name: "code"}}
	if _, err := StartCodeRun(context.Background(), CodeRunStart{
		Session: sess, Name: "code", Command: "pwd", CaptureMode: "combined", Cwd: "/home/alice/project",
	}); err != nil {
		t.Fatalf("StartCodeRun: %v", err)
	}
	if len(sess.calls) != 1 || strings.Join(sess.calls[0], "|") != "code|pwd|/home/alice/project|combined" {
		t.Fatalf("ProcessStart calls = %v", sess.calls)
	}
}

func TestStartCodeRun_Refusals(t *testing.T) {
	sess := &fakeCodeRunSession{result: &coderun.ProcessStartResult{Name: "code"}}
	req := &pb.StartBoxRunRequest{Username: "alice", Prompt: "fix the bug"}

	tests := []struct {
		name  string
		start CodeRunStart
		want  string
	}{
		{
			name:  "a token with no daemon client never falls back to the SSH session",
			start: CodeRunStart{Session: sess, Name: "code", Command: "c", Request: req, RunToken: testRunToken},
			want:  "daemon API",
		},
		{
			name:  "a token with no request",
			start: CodeRunStart{Session: sess, Name: "code", Command: "c", Daemon: &fakeCodeRunDaemon{}, RunToken: testRunToken},
			want:  "daemon API",
		},
		{
			name:  "no token and no session",
			start: CodeRunStart{Name: "code", Command: "c", Daemon: &fakeCodeRunDaemon{}, Request: req},
			want:  "session",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sess.calls = nil
			started, err := StartCodeRun(context.Background(), tc.start)
			if err == nil || started != nil {
				t.Fatalf("started = %+v, err = %v; want a refusal", started, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to name %q", err, tc.want)
			}
			if strings.Contains(err.Error(), testRunToken) {
				t.Errorf("the refusal carries the token: %q", err)
			}
			if len(sess.calls) != 0 {
				t.Errorf("the SSH session was used: %v", sess.calls)
			}
			if d, ok := tc.start.Daemon.(*fakeCodeRunDaemon); ok && len(d.calls) != 0 {
				t.Errorf("the daemon API was called: %v", d.calls)
			}
		})
	}
}

// Each path's own error comes back as is: the daemon's keeps its gRPC code.
func TestStartCodeRun_ErrorsAreReturnedUnwrapped(t *testing.T) {
	daemonErr := status.Error(codes.FailedPrecondition, "run \"code\" is still running")
	_, err := StartCodeRun(context.Background(), CodeRunStart{
		Daemon: &fakeCodeRunDaemon{err: daemonErr}, Request: &pb.StartBoxRunRequest{Username: "alice"}, RunToken: testRunToken,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("daemon path err = %v, want FAILED_PRECONDITION", err)
	}
	sessErr := errors.New("skill sets are being applied on this box")
	_, err = StartCodeRun(context.Background(), CodeRunStart{Session: &fakeCodeRunSession{err: sessErr}, Name: "code"})
	if !errors.Is(err, sessErr) {
		t.Errorf("session path err = %v, want %v", err, sessErr)
	}
}
