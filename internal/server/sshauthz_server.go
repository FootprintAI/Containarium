package server

import (
	"context"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SSHAuthzServer serves SSHAuthzService, the per-connection SSH
// authorization contract the sentinel's ssh-authz plugin calls
// (docs/architecture/ssh-live-authorization.md, component 1; #2516).
//
// The answer comes from the wired decider: the self-host decider
// (internal/sshauthz.SelfHostDecider, #2517) on a daemon with a key
// registry and no cloud enrollment. With no decider wired, Authorize
// returns Unimplemented once the caller is authorized.
type SSHAuthzServer struct {
	pb.UnimplementedSSHAuthzServiceServer

	mu      sync.RWMutex
	decider SSHAuthzDecider
}

// SSHAuthzDecider decides one AuthorizeSSHRequest. The self-host decider
// (#2517) and the managed-mode forwarder (#2525) both satisfy it.
type SSHAuthzDecider interface {
	Decide(ctx context.Context, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error)
}

// NewSSHAuthzServer returns a server with no decider wired.
func NewSSHAuthzServer() *SSHAuthzServer { return &SSHAuthzServer{} }

// SetDecider wires the decision engine once the daemon's state is loaded.
// Nil restores the Unimplemented answer.
func (s *SSHAuthzServer) SetDecider(d SSHAuthzDecider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decider = d
}

// Authorize requires the ssh:authorize scope, explicitly — the gateway
// stamps it only on a request whose sentinel signature verified
// (gateway.MountSSHAuthz); a token or mTLS peer without it is refused.
func (s *SSHAuthzServer) Authorize(ctx context.Context, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	if err := auth.RequireExplicitScope(ctx, auth.ScopeSSHAuthorize); err != nil {
		return nil, err
	}
	s.mu.RLock()
	d := s.decider
	s.mu.RUnlock()
	if d == nil {
		return nil, status.Error(codes.Unimplemented, "ssh authorization decider not configured on this daemon")
	}
	return d.Decide(ctx, req)
}
