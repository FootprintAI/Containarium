package server

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func sshAuthzCtx(username, roles, scopes string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		auth.MDKeyUsername, username,
		auth.MDKeyRoles, roles,
		auth.MDKeyScopes, scopes,
	))
}

// #2516: the stub is gated like every other RPC (TestEveryRPCHasAuthGuard)
// and answers Unimplemented to anyone allowed through — the decision logic
// is #2517's. The gateway mount maps a verified sentinel signature to the
// ssh:authz scope, so that is the identity the guard must accept.
func TestSSHAuthzServer_Authorize(t *testing.T) {
	req := &pb.AuthorizeSSHRequest{Login: "alice"}
	tests := []struct {
		name string
		ctx  context.Context
		want codes.Code
	}{
		{"no subject", context.Background(), codes.Unauthenticated},
		{"sentinel via gateway (ssh:authz scope)", sshAuthzCtx("sentinel-authz", "", auth.ScopeSSHAuthz), codes.Unimplemented},
		{"admin", sshAuthzCtx("root", auth.RoleAdmin, ""), codes.Unimplemented},
		{"user with an unrelated scope", sshAuthzCtx("bob", "user", auth.ScopeContainersRead), codes.PermissionDenied},
		{"user with no scopes", sshAuthzCtx("bob", "user", ""), codes.PermissionDenied},
	}
	s := NewSSHAuthzServer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := s.Authorize(tt.ctx, req)
			if got := status.Code(err); got != tt.want {
				t.Fatalf("Authorize → %v (%v), want %v", got, err, tt.want)
			}
			if resp != nil {
				t.Errorf("resp = %v, want nil on every error", resp)
			}
		})
	}
}
