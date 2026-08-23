package agentbox

import (
	"fmt"
	"log"
	"net"
	"os"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
)

// SpawnSocketEnv names the environment variable that enables agent-box's
// second transport: a SpawnService gRPC listener on a unix socket (#1488
// Phase 2). Unset — the default, and every box today — means agent-box
// serves MCP over stdio only, unchanged from before this feature existed.
// A pool member's provisioning sets this once the bind-mounted socket
// device (Phase 3) makes the path meaningful; nothing sets it yet.
const SpawnSocketEnv = "AGENTBOX_SPAWN_SOCKET"

// StartSpawnListener starts a SpawnService gRPC server listening on a unix
// socket at socketPath, serving in a background goroutine. Returns the
// *grpc.Server so the caller can GracefulStop it on shutdown; the error
// return covers only setup failures (socket creation) — the serve loop's
// own terminal error is logged, not returned, since by the time it fires
// the caller has long since moved on.
//
// Removes a stale socket file at socketPath before listening: a unix
// socket file left behind by a killed previous process blocks a fresh
// bind with "address already in use" even though nothing is listening on
// it anymore.
func StartSpawnListener(socketPath string) (*grpc.Server, error) {
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove stale socket %s: %w", socketPath, err)
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", socketPath, err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterSpawnServiceServer(grpcServer, NewSpawnServer())

	go func() {
		log.Printf("[agent-box] SpawnService listening on %s", socketPath)
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("[agent-box] SpawnService listener stopped: %v", err)
		}
	}()

	return grpcServer, nil
}
