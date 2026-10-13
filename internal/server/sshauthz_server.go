package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SSHAuthzServer serves SSHAuthzService, the per-connection SSH
// authorization contract the sentinel's ssh-authz plugin calls
// (docs/architecture/ssh-live-authorization.md, component 1; #2516).
//
// This is the contract stub: once the caller is authorized, Authorize
// returns Unimplemented until the daemon decider (#2517) lands, so the
// sentinel plugin and its tests can be built against generated types and
// a live route today.
type SSHAuthzServer struct {
	pb.UnimplementedSSHAuthzServiceServer
}

// NewSSHAuthzServer returns the stub server.
func NewSSHAuthzServer() *SSHAuthzServer { return &SSHAuthzServer{} }

// Authorize requires the ssh:authorize scope, explicitly — the gateway
// stamps it only on a request whose sentinel signature verified
// (gateway.MountSSHAuthz); a token or mTLS peer without it is refused.
func (s *SSHAuthzServer) Authorize(ctx context.Context, _ *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	if err := auth.RequireExplicitScope(ctx, auth.ScopeSSHAuthorize); err != nil {
		return nil, err
	}
	return nil, status.Error(codes.Unimplemented, "ssh authorization decider not implemented yet (#2517)")
}
