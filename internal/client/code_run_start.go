package client

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Starting a code run (#3610): `containarium code run` and the platform MCP
// tool code_run both start their run through StartCodeRun, so the two cannot
// drift on which path a run takes.
//
// There are two paths. Without a per-run token the run starts through the
// box's agent-box session over SSH, as the box's own user: what every run did
// before. With a per-run token it starts through the daemon API (StartBoxRun),
// which is the only path that can carry the token to the box.

// CodeRunSessionStarter is the SSH path: the part of a box's agent-box session
// a run starts through (*coderun.Session).
type CodeRunSessionStarter interface {
	ProcessStart(ctx context.Context, name, command, cwd, captureMode string) (*coderun.ProcessStartResult, error)
}

// CodeRunDaemonStarter is the daemon-API path. Both GRPCClient and HTTPClient
// satisfy it, and both gate the token on BoxRunTokenCapability.
type CodeRunDaemonStarter interface {
	StartBoxRun(req *pb.StartBoxRunRequest) (*pb.StartBoxRunResponse, error)
}

var (
	_ CodeRunDaemonStarter = (*GRPCClient)(nil)
	_ CodeRunDaemonStarter = (*HTTPClient)(nil)
)

// CodeRunStart is one run to start.
type CodeRunStart struct {
	// The SSH path, used when RunToken is empty: the run called Name starts
	// Command through Session with CaptureMode, in Cwd. Cwd is the absolute
	// directory coderun.Session.ResolveWorkdir returned for the run's workdir
	// (#3613); empty is process_start's default.
	Session     CodeRunSessionStarter
	Name        string
	Command     string
	CaptureMode string
	Cwd         string

	// RunToken is the caller's per-run token. Non-empty selects the daemon-API
	// path: Request is sent through Daemon with run_token set to it.
	RunToken string
	Daemon   CodeRunDaemonStarter
	// Request is the run to start, without the token. It is not modified.
	Request *pb.StartBoxRunRequest
}

// CodeRunStarted is a started run: Process on the SSH path, Run on the
// daemon-API path. Exactly one is set.
type CodeRunStarted struct {
	Process *coderun.ProcessStartResult
	Run     *pb.BoxRun
}

// StartCodeRun starts one run. A run with a token goes through the daemon API
// and never through the SSH session (which cannot carry it); a run without one
// goes through the SSH session and never calls the daemon API. Neither falls
// back to the other. Each path's error is returned unwrapped, and no error
// made here holds the token.
func StartCodeRun(ctx context.Context, s CodeRunStart) (*CodeRunStarted, error) {
	if s.RunToken == "" {
		if s.Session == nil {
			return nil, errors.New("no agent-box session to start the run through")
		}
		started, err := s.Session.ProcessStart(ctx, s.Name, s.Command, s.Cwd, s.CaptureMode)
		if err != nil {
			return nil, err
		}
		return &CodeRunStarted{Process: started}, nil
	}
	if s.Daemon == nil || s.Request == nil {
		return nil, errors.New("a run with a per-run token starts through the daemon API (StartBoxRun), and none was given")
	}
	req, ok := proto.Clone(s.Request).(*pb.StartBoxRunRequest)
	if !ok {
		return nil, errors.New("copy the StartBoxRun request")
	}
	req.RunToken = s.RunToken
	resp, err := s.Daemon.StartBoxRun(req)
	if err != nil {
		return nil, err
	}
	return &CodeRunStarted{Run: resp.GetRun()}, nil
}
