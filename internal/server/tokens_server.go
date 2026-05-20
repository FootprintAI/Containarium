package server

import (
	"context"
	"log"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Phase 1.2 follow-up — TokensService implementation. Pairs
// with the revocation list landed in PR #248 (`PgRevocationStore`).
//
// The RPC is admin-only. A tenant token can't kill another
// tenant's session — that's policy on the server side, not
// just convention. A future enhancement might allow a token
// to revoke its own jti regardless of role (self-logout
// flow), but the audit doc treats that as a separate
// follow-up; doing it now would mean two policies in one
// PR.

// TokensServer implements pb.TokensServiceServer.
type TokensServer struct {
	pb.UnimplementedTokensServiceServer

	tokenManager *auth.TokenManager
	store        auth.RevocationStore

	// maxLifetime is the cleanup horizon used when callers
	// don't supply expires_at. The value is the daemon's
	// configured max token lifetime — anything past that
	// can't authenticate anyway, so the revocation row is
	// safe to prune.
	maxLifetime time.Duration
}

// NewTokensServer wires the RPC handler. `store` is the
// shared revocation store (also referenced by tokenManager);
// passing it explicitly lets the handler insert with an
// operator-provided reason without round-tripping through
// the token manager.
func NewTokensServer(tm *auth.TokenManager, store auth.RevocationStore, maxLifetime time.Duration) *TokensServer {
	if maxLifetime <= 0 {
		maxLifetime = auth.DefaultMaxTokenExpiry
	}
	return &TokensServer{
		tokenManager: tm,
		store:        store,
		maxLifetime:  maxLifetime,
	}
}

// RevokeToken adds a jti to the revocation list. Admin-only.
//
// The cleanup horizon is, in order of preference:
//  1. expires_at from the request (caller knows the token's
//     real exp claim — best case),
//  2. now + daemon max token lifetime (worst-case fallback —
//     the row eventually prunes itself).
func (s *TokensServer) RevokeToken(ctx context.Context, req *pb.RevokeTokenRequest) (*pb.RevokeTokenResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if req.Jti == "" {
		return nil, status.Error(codes.InvalidArgument, "jti is required")
	}
	if s.store == nil {
		return nil, status.Error(codes.Unavailable, "revocation list is not configured on this daemon")
	}

	expiresAt := time.Now().Add(s.maxLifetime)
	if req.ExpiresAt != "" {
		// Accept RFC3339 (the canonical CLI format). Other
		// formats are caller-error and rejected — easier to
		// notice now than to discover after the row never
		// prunes.
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "expires_at must be RFC3339: %v", err)
		}
		expiresAt = t
	}

	reason := req.Reason
	if reason == "" {
		reason = "operator_revoke"
	}

	// We can't easily detect "already revoked" because
	// PgRevocationStore.Revoke is ON CONFLICT DO NOTHING —
	// a duplicate call returns nil. For the response, we
	// optimistically claim newly_revoked=true; an audit
	// query confirms the canonical revoke timestamp if it
	// matters.
	if err := s.store.Revoke(ctx, req.Jti, expiresAt, reason); err != nil {
		log.Printf("[tokens] revoke jti=%s failed: %v", req.Jti, err)
		return nil, status.Errorf(codes.Internal, "revoke failed: %v", err)
	}
	log.Printf("[tokens] revoked jti=%s reason=%q expires_at=%s", req.Jti, reason, expiresAt.Format(time.RFC3339))

	return &pb.RevokeTokenResponse{
		NewlyRevoked: true,
		Message:      "jti added to revocation list; token will be rejected on next use",
	}, nil
}
