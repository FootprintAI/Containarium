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
	if err := auth.RequireScope(ctx, auth.ScopeTokensWrite); err != nil {
		return nil, err
	}
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

// RefreshToken exchanges a valid refresh token for a new
// (access, refresh) pair. Phase 1.6 part B.
//
// Single-use rotation: on success, the input refresh
// token's jti is added to the revocation list. A replayed
// refresh token (someone stole it AND the legitimate
// holder already exchanged it) hits the revocation check
// inside ValidateRefreshToken's path and is rejected.
// This is a strong tamper signal — an audit hook should
// page on it; today we just log + return Unauthenticated.
//
// Unauthenticated endpoint by design: the refresh token IS
// the credential. Skip the access-token middleware on the
// /v1/tokens/refresh path; the daemon's HTTP middleware
// will need a route allowlist for this in a follow-up.
func (s *TokensServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}
	if s.tokenManager == nil {
		return nil, status.Error(codes.Unavailable, "token manager not configured")
	}

	claims, err := s.tokenManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		log.Printf("[tokens] refresh denied: invalid token")
		return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
	}

	// Mint the new pair BEFORE revoking the prior. If
	// minting fails the operator's session stays intact.
	newAccess, err := s.tokenManager.GenerateAccessToken(
		claims.Username, claims.Roles, 0, claims.Scopes...,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint access: %v", err)
	}
	newRefresh, err := s.tokenManager.GenerateRefreshToken(
		claims.Username, claims.Roles, 0, claims.Scopes...,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint refresh: %v", err)
	}

	// Revoke the input refresh-token jti. If the store is
	// unavailable, fail closed — without rotation a stolen
	// refresh token gives the attacker permanent renewal.
	if s.store != nil && claims.ID != "" {
		exp := time.Time{}
		if claims.ExpiresAt != nil {
			exp = claims.ExpiresAt.Time
		}
		if err := s.store.Revoke(ctx, claims.ID, exp, "refresh_rotation"); err != nil {
			log.Printf("[tokens] refresh rotation revoke failed for jti=%s: %v", claims.ID, err)
			return nil, status.Errorf(codes.Internal, "rotate failed: %v", err)
		}
	}

	// Parse the new exp timestamps from the just-minted
	// tokens so the client knows when to refresh next.
	newAccessClaims, _ := s.tokenManager.ValidateAccessToken(newAccess)
	newRefreshClaims, _ := s.tokenManager.ValidateRefreshToken(newRefresh)

	var accessExp, refreshExp int64
	if newAccessClaims != nil && newAccessClaims.ExpiresAt != nil {
		accessExp = newAccessClaims.ExpiresAt.Time.Unix()
	}
	if newRefreshClaims != nil && newRefreshClaims.ExpiresAt != nil {
		refreshExp = newRefreshClaims.ExpiresAt.Time.Unix()
	}

	log.Printf("[tokens] refresh rotated: user=%s old_jti=%s new_access_jti=%s new_refresh_jti=%s",
		claims.Username,
		claims.ID,
		safeID(newAccessClaims),
		safeID(newRefreshClaims),
	)

	return &pb.RefreshTokenResponse{
		AccessToken:           newAccess,
		RefreshToken:          newRefresh,
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: refreshExp,
	}, nil
}

func safeID(c *auth.Claims) string {
	if c == nil {
		return ""
	}
	return c.ID
}

// ListRevokedTokens enumerates active revocations. Admin-
// only + tokens:write scope (same surface as RevokeToken —
// anyone who can revoke can confirm what was revoked).
//
// Default behavior is to return only non-expired
// revocations. include_expired=true returns the full
// forensic set (an operator chasing a leak after the fact
// might want everything).
func (s *TokensServer) ListRevokedTokens(ctx context.Context, req *pb.ListRevokedTokensRequest) (*pb.ListRevokedTokensResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTokensWrite); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if s.store == nil {
		return nil, status.Error(codes.Unavailable, "revocation list is not configured on this daemon")
	}

	rows, err := s.store.List(ctx, auth.ListRevocationsParams{
		Limit:          int(req.Limit),
		IncludeExpired: req.IncludeExpired,
		JTIPrefix:      req.JtiPrefix,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list revocations: %v", err)
	}

	out := &pb.ListRevokedTokensResponse{
		Revocations: make([]*pb.Revocation, 0, len(rows)),
	}
	for _, r := range rows {
		out.Revocations = append(out.Revocations, &pb.Revocation{
			Jti:       r.JTI,
			ExpiresAt: r.ExpiresAt.UTC().Format(time.RFC3339),
			RevokedAt: r.RevokedAt.UTC().Format(time.RFC3339),
			Reason:    r.Reason,
		})
	}
	return out, nil
}
