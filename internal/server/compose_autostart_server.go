package server

import (
	"context"
	"encoding/json"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ComposeAutostartServer implements ComposeAutostartService — the
// outside-the-LXC entry point for the compose-autostart ops that
// already live as MCP tools + a CLI dispatch inside agent-box.
//
// Each handler:
//   1. validates the request
//   2. SSH-execs `agent-box compose <verb> [flags]` into the tenant's
//      LXC via the IncusExecer seam
//   3. parses the uniform JSON envelope agent-box prints to stdout
//      ({"ok":bool,"result":...} or {"ok":false,"error":"..."})
//   4. maps the envelope onto the typed proto response or a gRPC
//      status error
//
// The IncusExecer interface is the testability seam — production code
// wires `pkg/core/incus.Client` (which implements ExecWithOutput);
// unit tests pass a fake that returns canned stdout/stderr/error.
//
// Tenancy: every RPC takes username + execs into "<username>-container"
// (the convention the rest of the daemon uses; see container.Manager).
// Auth on these endpoints is delegated to the gRPC interceptors that
// wrap the daemon's services — same posture as ContainerService.
type ComposeAutostartServer struct {
	pb.UnimplementedComposeAutostartServiceServer

	incus IncusExecer
}

// IncusExecer is the narrow seam this handler needs from the Incus
// client. Matches the signature of *incus.Client.ExecWithOutput.
type IncusExecer interface {
	ExecWithOutput(containerName string, command []string) (stdout, stderr string, err error)
}

func NewComposeAutostartServer(execer IncusExecer) *ComposeAutostartServer {
	return &ComposeAutostartServer{incus: execer}
}

// composeEnvelope is the wire format agent-box's CLI emits on stdout
// (see internal/agentbox/compose_cli.go writeOK / writeErr). Result is
// json.RawMessage so handlers can unmarshal into per-verb shapes
// without re-encoding through map[string]any.
type composeEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// execAgentBoxCompose runs `agent-box compose <verb> args...` in the
// tenant's LXC, parses the envelope, and returns the typed Result
// payload OR a ready-to-return gRPC status error.
//
// Errors map:
//   - transport (exec failure, LXC missing) → codes.Internal
//   - envelope.OK == false                  → codes.FailedPrecondition with the daemon's error
//   - malformed envelope                    → codes.Internal
func (s *ComposeAutostartServer) execAgentBoxCompose(username, verb string, args []string) (json.RawMessage, error) {
	if username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	containerName := username + "-container"
	cmd := append([]string{"agent-box", "compose", verb}, args...)

	stdout, stderr, err := s.incus.ExecWithOutput(containerName, cmd)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "exec agent-box compose %s in %s: %v\nstderr: %s", verb, containerName, err, stderr)
	}

	var env composeEnvelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		return nil, status.Errorf(codes.Internal, "parse agent-box envelope (stdout=%q stderr=%q): %v", stdout, stderr, err)
	}
	if !env.OK {
		// agent-box reported a structured failure — bubble up as
		// FailedPrecondition since the call shape was valid but the
		// in-LXC operation refused (e.g., dir doesn't exist, no
		// compose runtime on PATH).
		msg := env.Error
		if msg == "" {
			msg = "agent-box compose " + verb + ": unspecified failure"
		}
		return nil, status.Error(codes.FailedPrecondition, msg)
	}
	return env.Result, nil
}

// ---- Discover ------------------------------------------------------

func (s *ComposeAutostartServer) Discover(_ context.Context, req *pb.DiscoverRequest) (*pb.DiscoverResponse, error) {
	args := []string{}
	if req.GetRoot() != "" {
		args = append(args, "--root", req.GetRoot())
	}
	if d := req.GetMaxDepth(); d > 0 {
		args = append(args, "--max-depth", strconv.Itoa(int(d)))
	}
	for _, sk := range req.GetSkip() {
		args = append(args, "--skip", sk)
	}
	if req.GetNoSkip() {
		args = append(args, "--no-skip")
	}

	raw, err := s.execAgentBoxCompose(req.GetUsername(), "discover", args)
	if err != nil {
		return nil, err
	}

	var result struct {
		Stacks []discoveredStack `json:"stacks"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, status.Errorf(codes.Internal, "parse discover result: %v", err)
	}

	stacks := make([]*pb.ComposeStack, 0, len(result.Stacks))
	for i := range result.Stacks {
		stacks = append(stacks, result.Stacks[i].toProto())
	}
	return &pb.DiscoverResponse{Stacks: stacks}, nil
}

// ---- Enable --------------------------------------------------------

func (s *ComposeAutostartServer) Enable(_ context.Context, req *pb.EnableRequest) (*pb.EnableResponse, error) {
	if req.GetDir() == "" {
		return nil, status.Error(codes.InvalidArgument, "dir is required")
	}
	args := []string{"--dir", req.GetDir()}
	if req.GetForce() {
		args = append(args, "--force")
	}

	raw, err := s.execAgentBoxCompose(req.GetUsername(), "enable", args)
	if err != nil {
		return nil, err
	}

	var result struct {
		Unit       string `json:"unit"`
		Dir        string `json:"dir"`
		ComposeBin string `json:"compose_bin"`
		Already    bool   `json:"already"`
		Message    string `json:"message"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, status.Errorf(codes.Internal, "parse enable result: %v", err)
	}
	return &pb.EnableResponse{
		Unit:       result.Unit,
		Dir:        result.Dir,
		ComposeBin: result.ComposeBin,
		Already:    result.Already,
		Message:    result.Message,
	}, nil
}

// ---- Disable -------------------------------------------------------

func (s *ComposeAutostartServer) Disable(_ context.Context, req *pb.DisableRequest) (*pb.DisableResponse, error) {
	if req.GetDir() == "" {
		return nil, status.Error(codes.InvalidArgument, "dir is required")
	}
	args := []string{"--dir", req.GetDir()}

	raw, err := s.execAgentBoxCompose(req.GetUsername(), "disable", args)
	if err != nil {
		return nil, err
	}

	var result struct {
		Unit    string `json:"unit"`
		Dir     string `json:"dir"`
		Already bool   `json:"already"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, status.Errorf(codes.Internal, "parse disable result: %v", err)
	}
	return &pb.DisableResponse{
		Unit:    result.Unit,
		Dir:     result.Dir,
		Already: result.Already,
		Message: result.Message,
	}, nil
}

// ---- Status --------------------------------------------------------

func (s *ComposeAutostartServer) Status(_ context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	if req.GetDir() == "" {
		return nil, status.Error(codes.InvalidArgument, "dir is required")
	}
	args := []string{"--dir", req.GetDir()}

	raw, err := s.execAgentBoxCompose(req.GetUsername(), "status", args)
	if err != nil {
		return nil, err
	}

	var ds discoveredStack
	if err := json.Unmarshal(raw, &ds); err != nil {
		return nil, status.Errorf(codes.Internal, "parse status result: %v", err)
	}
	return &pb.StatusResponse{Stack: ds.toProto()}, nil
}

// ---- helpers -------------------------------------------------------

// discoveredStack is the wire-shape from agent-box's compose CLI
// (matches the json tags on agentbox.ComposeStack — see
// internal/agentbox/compose.go). We don't import agentbox.ComposeStack
// directly because:
//   - it would couple internal/server to internal/agentbox at
//     compile time
//   - the agent-box struct evolves with the in-box surface; the proto
//     evolves with the platform contract; explicit mapping keeps the
//     two from drifting silently.
//
// If a future agent-box field needs surfacing, add it here AND in the
// proto, both in the same PR.
type discoveredStack struct {
	ComposeDir        string `json:"compose_dir"`
	ComposeFile       string `json:"compose_file"`
	ComposeBin        string `json:"compose_bin"`
	ComposeModifiedAt string `json:"compose_modified_at"`
	RunningCount      int    `json:"running_count"`
	TotalCount        int    `json:"total_count"`
	AutostartEnabled  bool   `json:"autostart_enabled"`
	UnitModifiedAt    string `json:"unit_modified_at"`
}

func (d discoveredStack) toProto() *pb.ComposeStack {
	return &pb.ComposeStack{
		ComposeDir:        d.ComposeDir,
		ComposeFile:       d.ComposeFile,
		ComposeBin:        d.ComposeBin,
		ComposeModifiedAt: d.ComposeModifiedAt,
		RunningCount:      int32(d.RunningCount),
		TotalCount:        int32(d.TotalCount),
		AutostartEnabled:  d.AutostartEnabled,
		UnitModifiedAt:    d.UnitModifiedAt,
	}
}

// The real *incus.Client implements the IncusExecer seam. We don't
// import pkg/core/incus here to avoid the dep cycle; the real wiring
// happens in dual_server.go (or whatever wires gRPC services) where
// the daemon already holds an *incus.Client and just passes it to
// NewComposeAutostartServer.
