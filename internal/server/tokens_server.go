package server

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
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
// Single-use rotation with reuse detection (closes the race in #1864):
// the input refresh token's jti is claimed — atomically revoked — BEFORE
// anything is minted, not after. Minting first (the prior order) let two
// concurrent exchanges of the same refresh token both pass
// ValidateRefreshToken (neither had been revoked yet) and both walk away
// with a valid new pair, contradicting the single-use contract documented
// in README.md. Revoking is now the claim: RevokeClaim's INSERT ... ON
// CONFLICT is the atomic check, so only one concurrent caller can ever
// win it.
//
// The loser — whose claim fails because the jti is already revoked —
// has just witnessed the credential presented twice. That's the same
// signal a stolen-and-replayed refresh token produces, and the two
// cases are indistinguishable from here, so the response is the same
// either way: revoke the entire rotation family (every token, past or
// future, that descends from the same original login), forcing a full
// re-authentication rather than guessing which presenter was
// legitimate. See RevocationStore.RevokeFamily.
//
// Unauthenticated endpoint by design: the refresh token IS the
// credential. Skip the access-token middleware on the
// /v1/tokens/refresh path; the daemon's HTTP middleware will need a
// route allowlist for this in a follow-up.
func (s *TokensServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}
	if s.tokenManager == nil {
		return nil, status.Error(codes.Unavailable, "token manager not configured")
	}

	// ValidateRefreshTokenClaims deliberately skips the revocation-list
	// check that ValidateRefreshToken enforces. Rotation makes the
	// presented jti revoked on success, so using the revocation-checked
	// validator here would reject a replay of an already-rotated token
	// at this step — before the reuse-detection logic below ever saw
	// it. The RevokeClaim call further down IS this handler's own
	// revocation check, and its failure IS the reuse signal.
	claims, err := s.tokenManager.ValidateRefreshTokenClaims(req.RefreshToken)
	if err != nil {
		log.Printf("[tokens] refresh denied: invalid token")
		return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
	}

	// familyID falls back to the token's own jti for a pre-family token
	// (minted before this fix) — it's the sole member of its own family,
	// so reuse detection still applies to it going forward.
	familyID := claims.FamilyID
	if familyID == "" {
		familyID = claims.ID
	}

	if s.store != nil && claims.ID != "" {
		if revoked, rerr := s.store.IsFamilyRevoked(ctx, familyID); rerr != nil {
			log.Printf("[tokens] refresh family lookup failed for family=%s: %v (continuing; the per-jti claim below is the primary gate)", familyID, rerr)
		} else if revoked {
			log.Printf("[tokens] refresh denied: family=%s already revoked", familyID)
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		}

		exp := time.Time{}
		if claims.ExpiresAt != nil {
			exp = claims.ExpiresAt.Time
		}
		claimed, cerr := s.store.RevokeClaim(ctx, claims.ID, exp, "refresh_rotation")
		if cerr != nil {
			log.Printf("[tokens] refresh rotation claim failed for jti=%s: %v", claims.ID, cerr)
			return nil, status.Errorf(codes.Internal, "rotate failed: %v", cerr)
		}
		if !claimed {
			if ferr := s.store.RevokeFamily(ctx, familyID, "refresh_reuse_detected"); ferr != nil {
				log.Printf("[tokens] refresh reuse: failed to revoke family=%s: %v", familyID, ferr)
			}
			log.Printf("[tokens] refresh DENIED — reuse of already-rotated jti=%s; family=%s revoked", claims.ID, familyID)
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		}
	}

	// The claim above is what makes this exchange exclusive; minting
	// after it is safe because we already own the only valid rotation
	// of this jti.
	newAccess, err := s.tokenManager.GenerateAccessToken(
		claims.Username, claims.Roles, 0, claims.Scopes...,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint access: %v", err)
	}
	newRefresh, err := s.tokenManager.GenerateRefreshTokenInFamily(
		claims.Username, claims.Roles, 0, familyID, claims.Scopes...,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint refresh: %v", err)
	}

	// Parse the new exp timestamps from the just-minted
	// tokens so the client knows when to refresh next.
	newAccessClaims, _ := s.tokenManager.ValidateAccessToken(newAccess)
	newRefreshClaims, _ := s.tokenManager.ValidateRefreshToken(newRefresh)

	var accessExp, refreshExp int64
	if newAccessClaims != nil && newAccessClaims.ExpiresAt != nil {
		accessExp = newAccessClaims.ExpiresAt.Unix()
	}
	if newRefreshClaims != nil && newRefreshClaims.ExpiresAt != nil {
		refreshExp = newRefreshClaims.ExpiresAt.Unix()
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

// ListRevokedTokens enumerates active revocations. It's a read
// path, gated by admin role OR an explicit tokens:read scope
// (#621) — a least-privilege compliance/evidence token can list
// revocations without holding the write surface. Previously this
// required admin AND tokens:write; the write-scope gate on a read
// RPC was the bug.
//
// Default behavior is to return only non-expired
// revocations. include_expired=true returns the full
// forensic set (an operator chasing a leak after the fact
// might want everything).
func (s *TokensServer) ListRevokedTokens(ctx context.Context, req *pb.ListRevokedTokensRequest) (*pb.ListRevokedTokensResponse, error) {
	// Read path: admins (by role) or a least-privilege token with tokens:read
	// (#621). Previously required admin AND tokens:write.
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeTokensRead); err != nil {
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

// GetUnscopedTokenReport reports how many recent calls used a token with no
// scopes claim — the measured-rollout deliverable for #1679's strict mode.
// Same read-path gate as ListRevokedTokens (#621): admin by role, or a
// least-privilege token with tokens:read.
func (s *TokensServer) GetUnscopedTokenReport(ctx context.Context, _ *pb.GetUnscopedTokenReportRequest) (*pb.GetUnscopedTokenReportResponse, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeTokensRead); err != nil {
		return nil, err
	}

	report := auth.UnscopedTokenCalls()
	resp := &pb.GetUnscopedTokenReportResponse{
		UnscopedCallCount: report.Count,
		StrictModeEnabled: auth.StrictScopesEnabled(),
	}
	if !report.Since.IsZero() {
		resp.Since = report.Since.UTC().Format(time.RFC3339)
	}
	return resp, nil
}

// ExchangeDelegatedToken mints a token acting FOR another subject, on the
// authority of the caller's own credential (containarium-cloud#1427).
//
// A service that fronts this API for end users — the cloud control plane is
// the case that motivated it — presents its own service credential on every
// call. #1676 bounds an agent token by the caller's scopes, but when the
// caller is a shared service account that bound means nothing, and #1678's
// audit `actor` records the service rather than the person. `act` is a JWT
// claim and never a header (#1677), so the fronting service cannot assert it:
// it holds no signing key, and giving it one would let it mint any identity.
// It asks this daemon to mint instead.
//
// Two invariants make that safe, and they are the same two RunAgentSkill's
// own delegated mint relies on:
//
//   - Granted scopes are the INTERSECTION of the caller's with those
//     requested. An exchange can never widen authority — without this the
//     endpoint is exactly the escalation primitive #1676 closed, reopened
//     under a new name.
//   - `act` is built server-side from the authenticated caller, wrapping the
//     caller's own chain, so the delegation path is recorded rather than
//     claimed.
func (s *TokensServer) ExchangeDelegatedToken(ctx context.Context, req *pb.ExchangeDelegatedTokenRequest) (*pb.ExchangeDelegatedTokenResponse, error) {
	// tokens:delegate, not tokens:write — acting as another subject is a
	// distinct capability from managing your own tokens.
	if err := auth.RequireScope(ctx, auth.ScopeTokensDelegate); err != nil {
		return nil, err
	}

	// This endpoint FAILS CLOSED on an unscoped token, regardless of
	// CONTAINARIUM_STRICT_SCOPES. Everywhere else a missing scopes claim is
	// tolerated (#1679) so that tokens minted before scopes existed keep
	// working; that tolerance is safe for a handler that merely reads or
	// mutates, because the token's own authority still bounds the blast
	// radius.
	//
	// It is NOT safe here. The ceiling below is the caller's scope set, and
	// IntersectScopes treats a nil caller as unbounded — so an unscoped
	// caller could ask for, and be granted, any scope in the system. That
	// makes this endpoint the escalation primitive #1676 closed, reopened
	// under a new name, with the fail-open as its trigger.
	//
	// The usual reason to fail open does not apply: this RPC is new, so
	// there is no population of legacy callers to preserve. A fronting
	// service must present a scoped credential — which is what
	// containarium-cloud#1428 is separately doing to the cloud's own
	// service token.
	callerScopes, scopesPresent := auth.ScopesFromGRPCContext(ctx)
	if !scopesPresent {
		return nil, status.Error(codes.PermissionDenied,
			"delegation requires a token carrying an explicit scopes claim: "+
				"the granted set is bounded by the caller's own scopes, and an "+
				"unscoped token has no bound to apply")
	}

	subject := strings.TrimSpace(req.GetSubject())
	if subject == "" {
		// An empty subject would mint an unattributed token — the exact
		// state this endpoint exists to eliminate, so it is an error
		// rather than a silent fallback to the caller's own identity.
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}

	caller, callerRoles, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok || caller == "" {
		return nil, status.Error(codes.Unauthenticated, "no authenticated subject in request context")
	}

	// The caller becomes the actor, wrapping whatever chain it already
	// carries, so a multi-hop delegation nests instead of flattening. Never
	// taken from the request — that is #1677's rule.
	callerAct, _ := auth.ActFromGRPCContext(ctx)
	act := &auth.Actor{Subject: caller, Act: callerAct}

	granted := auth.IntersectScopes(callerScopes, req.GetScopes())
	if len(req.GetScopes()) == 0 {
		// No explicit request means "whatever I have" — still the caller's
		// own set, never wider.
		granted = callerScopes
	}

	// An empty intersection must NOT mint. This is the trap in the claim
	// shape: HasScope treats an ABSENT scopes claim as unrestricted, and
	// generate() omits the claim when it is handed zero scopes. So a token
	// minted from an empty grant is not powerless — it is unlimited, which is
	// the precise inversion of what the caller asked for and what the response
	// would report.
	//
	// Concretely, before this check: a caller holding only tokens:delegate
	// requests secrets:read, the intersection correctly yields nothing, the
	// response honestly says granted_scopes=[], and the token it hands back
	// passes RequireScope for every scope in the system.
	//
	// There is no way to express "no authority" in this claim, so refusing is
	// the only correct answer. It also loses nothing: a token that genuinely
	// carried zero scopes could not be used for anything.
	if len(granted) == 0 {
		return nil, status.Error(codes.PermissionDenied,
			"the requested scopes intersect none of the caller's own, so this exchange "+
				"would grant nothing; a token carrying no scopes claim reads as UNRESTRICTED "+
				"rather than powerless, so it is refused instead of minted")
	}

	// A caller asking for longer than the daemon permits gets a shorter
	// token, not a failure: generate() caps it internally, and failing here
	// would make a working exchange depend on the client knowing the
	// daemon's configured maximum.
	//
	// An unspecified TTL is an access-token lifetime, NOT the daemon
	// maximum. Passing 0 straight through would mint the longest-lived
	// token the daemon allows for the least specific request — the wrong
	// default for a credential handed to a fronting service.
	ttl := auth.DefaultAccessTokenExpiry
	if secs := req.GetExpiresInSeconds(); secs > 0 {
		ttl = time.Duration(secs) * time.Second
	}

	// Roles, on the same rule as scopes: intersected with the caller's own,
	// never unioned. IntersectRoles rather than IntersectScopes deliberately —
	// the latter treats a nil caller as "no ceiling", which is right for
	// scopes and would let a role-less caller mint an admin token here.
	//
	// An empty request yields no roles, and that is the intended default
	// rather than an oversight. The two claims' absent-state semantics are
	// opposite: an absent scopes claim reads as unrestricted (hence the
	// refusal above), while an absent roles claim reads as no roles at all.
	// Since empty is already the safe state for roles, the only way to get
	// this wrong would be to inherit admin silently, so a caller that needs a
	// role has to name it.
	grantedRoles := auth.IntersectRoles(callerRoles, req.GetRoles())

	token, err := s.tokenManager.GenerateDelegatedToken(subject, grantedRoles, ttl, act, granted...)
	if err != nil {
		// Depth violations are a client-correctable conflict (the chain is
		// too long), not a server fault — surface them as such.
		if strings.Contains(err.Error(), "delegation chain depth") {
			return nil, status.Errorf(codes.FailedPrecondition, "mint delegated token: %v", err)
		}
		return nil, status.Errorf(codes.Internal, "mint delegated token: %v", err)
	}

	// Report the token's OWN exp rather than recomputing the deadline here.
	// The manager caps a too-long TTL silently, so a locally derived
	// timestamp can claim a validity the token does not have — and the
	// caller caches against this value, so it would keep presenting a token
	// the daemon already rejects.
	claims, err := s.tokenManager.ValidateToken(token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "minted token failed self-validation: %v", err)
	}

	return &pb.ExchangeDelegatedTokenResponse{
		Token:         token,
		ExpiresAt:     timestamppb.New(claims.ExpiresAt.Time),
		GrantedScopes: granted,
		GrantedRoles:  grantedRoles,
	}, nil
}
