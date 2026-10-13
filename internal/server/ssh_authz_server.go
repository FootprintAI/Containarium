package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SSHAuthzServer serves SSHAuthzService (#2516, docs/architecture/
// ssh-live-authorization.md component 1): the per-connection "may this
// credential log in as this account right now?" question the sentinel's
// ssh-authz-plugin asks this backend.
//
// This is the contract landing: the service is registered and gated so the
// REST route, the OpenAPI entry and the generated client exist for the
// plugin (#2518) and the cloud to build against, but Authorize answers
// Unimplemented until the decider (#2517, internal/server/sshauthz) is
// wired in. No decision logic lives here.
type SSHAuthzServer struct {
	pb.UnimplementedSSHAuthzServiceServer
}

// NewSSHAuthzServer returns the contract stub.
func NewSSHAuthzServer() *SSHAuthzServer { return &SSHAuthzServer{} }

// Authorize — admin or ssh:authz. The sentinel is the intended caller: on
// the REST shim its request signature is verified and mapped to the
// ssh:authz scope (gateway.sshAuthzHandler), so this guard sees the same
// identity a scoped token would carry. Everything allowed through gets
// Unimplemented until #2517 lands the decider.
func (s *SSHAuthzServer) Authorize(ctx context.Context, _ *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeSSHAuthz); err != nil {
		return nil, err
	}
	return nil, status.Error(codes.Unimplemented, "SSH authorization decider not implemented on this daemon yet (#2517)")
}
