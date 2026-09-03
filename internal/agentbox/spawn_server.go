package agentbox

import (
	"context"
	"errors"
	"time"

	"github.com/footprintai/containarium/internal/safecast"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SpawnServer implements pb.SpawnServiceServer — agent-box's resident,
// low-latency counterpart to the daemon's per-call Incus round-trips
// (#1488 Phase 2). Both RPCs delegate to the same functions the
// process_start/shell_exec MCP tools use (spawnBackgroundProcess,
// runShellCommand): one implementation of spawn/exec/reap semantics,
// reached over two transports (stdio MCP, this gRPC service), not two
// parallel copies that could drift.
type SpawnServer struct {
	pb.UnimplementedSpawnServiceServer
}

// NewSpawnServer constructs a SpawnServer.
func NewSpawnServer() *SpawnServer {
	return &SpawnServer{}
}

// Spawn starts a long-running background process and returns its pid.
func (s *SpawnServer) Spawn(_ context.Context, req *pb.SpawnRequest) (*pb.SpawnResponse, error) {
	if req.Command == "" {
		return nil, status.Error(codes.InvalidArgument, "command is required")
	}

	mp, err := spawnBackgroundProcess(req.Name, req.Command, req.Cwd, captureModeFromProto(req.CaptureMode))
	if err != nil {
		if errors.Is(err, ErrProcessNameInUse) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "spawn failed: %v", err)
	}

	return &pb.SpawnResponse{
		Name:    mp.Name,
		Pid:     int64(mp.PID),
		LogPath: mp.LogPath,
	}, nil
}

// Exec runs one command to completion and returns its stdout, stderr, and
// exit code.
func (s *SpawnServer) Exec(ctx context.Context, req *pb.AgentExecRequest) (*pb.AgentExecResponse, error) {
	if req.Command == "" {
		return nil, status.Error(codes.InvalidArgument, "command is required")
	}

	timeout := shellExecDefaultTimeout
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
		if timeout > shellExecMaxTimeout {
			timeout = shellExecMaxTimeout
		}
	}

	res := runShellCommand(ctx, req.Command, req.Cwd, timeout)

	return &pb.AgentExecResponse{
		Stdout:   res.Stdout,
		Stderr:   res.Stderr,
		ExitCode: safecast.I32(res.ExitCode),
	}, nil
}
