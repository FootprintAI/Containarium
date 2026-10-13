// Package sshauthz serves the SSH authorization contract. Decision logic is
// intentionally deferred to the daemon-decider issue (#2517).
package sshauthz

import (
	"context"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SSHAuthzServer exposes a guarded stub until a real decider is installed.
type SSHAuthzServer struct {
	pb.UnimplementedSSHAuthzServiceServer
}

func (*SSHAuthzServer) Authorize(ctx context.Context, _ *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	if err := auth.RequireExplicitScope(ctx, auth.ScopeSSHAuthorize); err != nil {
		return nil, err
	}
	if err := auth.RequireVerifiedSentinelSSHAuthz(ctx); err != nil {
		return nil, err
	}
	return nil, status.Error(codes.Unimplemented, "SSH authorization decider is not implemented")
}
