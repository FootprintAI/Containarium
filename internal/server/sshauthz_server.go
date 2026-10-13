package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	coreauthz "github.com/footprintai/containarium/internal/sshauthz"
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
	decider *coreauthz.Decider
}

// NewSSHAuthzServer returns the stub server.
func NewSSHAuthzServer() *SSHAuthzServer { return &SSHAuthzServer{} }

// SetDecider wires the decision engine after enrollment has been loaded. A
// nil decider keeps the contract stub fail-closed for an unenrolled daemon.
func (s *SSHAuthzServer) SetDecider(d *coreauthz.Decider) { s.decider = d }

// Authorize requires the ssh:authorize scope, explicitly — the gateway
// stamps it only on a request whose sentinel signature verified
// (gateway.MountSSHAuthz); a token or mTLS peer without it is refused.
func (s *SSHAuthzServer) Authorize(ctx context.Context, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	if err := auth.RequireExplicitScope(ctx, auth.ScopeSSHAuthorize); err != nil {
		return nil, err
	}
	if s.decider != nil {
		return s.decider.Decide(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "ssh authorization decider not implemented yet (#2517)")
}
