package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ExchangeDelegatedToken exists to let a fronting service act for a user
// without holding a signing key (containarium-cloud#1427). Its safety rests
// entirely on two invariants, so those are what these tests pin.

func delegateTestServer(t *testing.T) *TokensServer {
	t.Helper()
	tm, err := auth.NewTokenManager(delegateTestSecret, "containarium-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return NewTokensServer(tm, nil, 0)
}

const delegateTestSecret = "test-secret-for-delegation-tests-0123456789"

// callerCtx builds an authenticated caller carrying both a scopes claim and
// an act chain — the shape the gateway annotator produces in production. The
// two ContextWithTestSubject* helpers each write a full metadata set, so the
// scopes pair is merged onto the act-bearing context rather than layered by a
// second constructor call, which would drop the act.
func callerCtx(username string, scopes []string, act *auth.Actor) context.Context {
	ctx := auth.ContextWithTestSubjectAct(context.Background(), username, []string{"admin"}, act)
	if scopes == nil {
		return ctx
	}
	md, _ := metadata.FromIncomingContext(ctx)
	md = md.Copy()
	md.Set(auth.MDKeyScopes, strings.Join(scopes, ","))
	return metadata.NewIncomingContext(ctx, md)
}

// THE invariant: an exchange can never produce more authority than the caller
// already holds. Without it this endpoint is #1676's escalation reopened.
func TestExchangeDelegatedToken_CannotWidenAuthority(t *testing.T) {
	s := delegateTestServer(t)
	ctx := callerCtx("cloud-daemon",
		[]string{auth.ScopeTokensDelegate, auth.ScopeContainersRead},
		nil)

	resp, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{
		Subject: "alice@example.com",
		// Asking for far more than the caller holds.
		Scopes: []string{auth.ScopeContainersRead, auth.ScopeSecretsRead, auth.ScopeContainersWrite},
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	for _, s := range resp.GetGrantedScopes() {
		if s == auth.ScopeSecretsRead || s == auth.ScopeContainersWrite {
			t.Fatalf("granted %q — the caller does not hold it; the exchange widened authority", s)
		}
	}
	if len(resp.GetGrantedScopes()) != 1 || resp.GetGrantedScopes()[0] != auth.ScopeContainersRead {
		t.Errorf("granted = %v, want only containers:read", resp.GetGrantedScopes())
	}
}

// act must come from the authenticated context, never from the request — the
// rule #1677 states. A caller that could name its own actor could forge the
// audit trail.
func TestExchangeDelegatedToken_ActIsServerSetAndNests(t *testing.T) {
	s := delegateTestServer(t)
	// The caller itself already acts for someone: a two-hop chain.
	existing := &auth.Actor{Subject: "human@example.com"}
	ctx := callerCtx("cloud-daemon", []string{auth.ScopeTokensDelegate}, existing)

	resp, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{
		Subject: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	tm, _ := auth.NewTokenManager(delegateTestSecret, "containarium-test")
	claims, err := tm.ValidateToken(resp.GetToken())
	if err != nil {
		t.Fatalf("minted token does not validate: %v", err)
	}
	if claims.Username != "alice@example.com" {
		t.Errorf("subject = %q, want the delegated-for user", claims.Username)
	}
	if claims.Act == nil {
		t.Fatal("no act chain — the delegation path was not recorded")
	}
	if claims.Act.Subject != "cloud-daemon" {
		t.Errorf("act.sub = %q, want the authenticated caller", claims.Act.Subject)
	}
	// The caller's own chain must be WRAPPED, not dropped: RootActor is what
	// #1678's audit `actor` column resolves to, and flattening here would
	// lose the human furthest from the leaf.
	if got := auth.RootActor(claims.Act); got != "human@example.com" {
		t.Errorf("RootActor = %q, want the original human — the chain was flattened", got)
	}
}

func TestExchangeDelegatedToken_RequiresDelegateScope(t *testing.T) {
	s := delegateTestServer(t)
	// tokens:write is deliberately NOT enough: managing your own tokens and
	// acting as someone else are different capabilities.
	ctx := callerCtx("cloud-daemon", []string{auth.ScopeTokensWrite}, nil)

	_, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{Subject: "alice@example.com"})
	if err == nil {
		t.Fatal("tokens:write alone must not permit acting as another subject")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
}

func TestExchangeDelegatedToken_RejectsEmptySubject(t *testing.T) {
	s := delegateTestServer(t)
	ctx := callerCtx("cloud-daemon", []string{auth.ScopeTokensDelegate}, nil)

	// An empty subject would mint an unattributed token — the state this
	// endpoint exists to remove, so it must not silently fall back.
	_, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{Subject: "  "})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument for an empty subject", err)
	}
}

func TestExchangeDelegatedToken_RejectsAnOverlongChain(t *testing.T) {
	s := delegateTestServer(t)
	// Build a chain already at the maximum; one more hop must be refused
	// rather than truncated — truncation drops the human furthest from the
	// leaf, which is the one an auditor needs.
	var deep *auth.Actor
	for i := 0; i < auth.MaxActDepth; i++ {
		deep = &auth.Actor{Subject: "hop", Act: deep}
	}
	ctx := callerCtx("cloud-daemon", []string{auth.ScopeTokensDelegate}, deep)

	_, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{Subject: "alice@example.com"})
	if err == nil {
		t.Fatal("a chain past MaxActDepth must be refused, not silently truncated")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "depth") {
		t.Errorf("err = %v, want a depth violation", err)
	}
}

func TestExchangeDelegatedToken_ReportsExpiry(t *testing.T) {
	s := delegateTestServer(t)
	ctx := callerCtx("cloud-daemon", []string{auth.ScopeTokensDelegate}, nil)

	resp, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{
		Subject:          "alice@example.com",
		ExpiresInSeconds: 300,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	// The caller is meant to cache by this, so it has to be present and sane
	// — the round trip is only acceptable if it can be amortized.
	if resp.GetExpiresAt() == nil {
		t.Fatal("no expires_at — a caller cannot cache without it")
	}
	if d := time.Until(resp.GetExpiresAt().AsTime()); d <= 0 || d > 6*time.Minute {
		t.Errorf("expires in %v, want ~5 minutes", d)
	}
}

// The fail-open scope default (#1679) must NOT reach this endpoint. Everywhere
// else a token with no scopes claim is tolerated for backward compatibility;
// here the caller's scope set IS the ceiling, and IntersectScopes reads a nil
// caller as unbounded — so tolerating it would grant any scope asked for.
func TestExchangeDelegatedToken_RefusesAnUnscopedCaller(t *testing.T) {
	s := delegateTestServer(t)
	// nil scopes = no scopes claim at all, the pre-1.7 token shape.
	ctx := callerCtx("legacy-service", nil, nil)

	resp, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{
		Subject: "alice@example.com",
		Scopes:  []string{auth.ScopeSecretsRead, auth.ScopeContainersWrite},
	})
	if err == nil {
		t.Fatalf("an unscoped caller was granted %v — the exchange has no ceiling to apply",
			resp.GetGrantedScopes())
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
}

// An exchange that would grant nothing must REFUSE, not mint.
//
// This test replaces one that asserted on resp.GetGrantedScopes() and passed
// while the endpoint was handing out unrestricted tokens. The response field
// said "granted nothing" and was telling the truth; the token attached to it
// carried no scopes claim, which HasScope reads as no restriction at all. The
// assertion was on the wrong object — the report rather than the credential.
//
// So this asserts on what the caller actually receives, and the sibling below
// proves the failure the old test missed.
func TestExchangeDelegatedToken_RefusesAnExchangeThatWouldGrantNothing(t *testing.T) {
	s := delegateTestServer(t)
	// tokens:delegate is the only scope held, and it is not what is requested.
	ctx := callerCtx("cloud-daemon", []string{auth.ScopeTokensDelegate}, nil)

	resp, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{
		Subject: "alice@example.com",
		Scopes:  []string{auth.ScopeSecretsRead},
	})
	if err == nil {
		t.Fatalf("minted a token for an empty grant (scopes=%v); a token with no scopes "+
			"claim is UNRESTRICTED, not powerless", resp.GetGrantedScopes())
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
}

// The regression itself, asserted on the minted TOKEN rather than the response.
// Every token this endpoint hands out must carry a non-empty scopes claim,
// because an absent claim is unrestricted — so "granted nothing" and "granted
// everything" are the same bytes on the wire.
func TestExchangeDelegatedToken_NeverMintsAnUnrestrictedToken(t *testing.T) {
	tm, err := auth.NewTokenManager(delegateTestSecret, "containarium-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	s := NewTokensServer(tm, nil, 0)

	cases := []struct {
		name         string
		callerScopes []string
		requested    []string
	}{
		{"asks for what it does not hold", []string{auth.ScopeTokensDelegate}, []string{auth.ScopeSecretsRead}},
		{"asks for nothing at all", []string{auth.ScopeTokensDelegate, auth.ScopeContainersRead}, nil},
		{"partial overlap", []string{auth.ScopeTokensDelegate, auth.ScopeContainersRead},
			[]string{auth.ScopeContainersRead, auth.ScopeSecretsWrite}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := callerCtx("cloud-daemon", c.callerScopes, nil)
			resp, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{
				Subject: "alice@example.com",
				Scopes:  c.requested,
			})
			if err != nil {
				return // refused outright, which is a correct outcome here
			}
			claims, verr := tm.ValidateToken(resp.GetToken())
			if verr != nil {
				t.Fatalf("minted token does not validate: %v", verr)
			}
			if len(claims.Scopes) == 0 {
				t.Fatalf("minted a token whose scopes claim is empty/absent — every "+
					"RequireScope will pass on it. response said granted=%v",
					resp.GetGrantedScopes())
			}
			// And it must never exceed what the caller held.
			for _, got := range claims.Scopes {
				if !auth.HasExplicitScope(c.callerScopes, got) {
					t.Errorf("token carries %q, which the caller does not hold", got)
				}
			}
		})
	}
}

// Roles follow the same rule as scopes — intersected with the caller's, never
// unioned — but with the opposite empty-state default, because the two claims
// mean opposite things when absent.

func TestExchangeDelegatedToken_RolesAreIntersectedNotUnioned(t *testing.T) {
	tm, err := auth.NewTokenManager(delegateTestSecret, "containarium-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	s := NewTokensServer(tm, nil, 0)

	// The caller is a plain user. It asks for admin anyway.
	ctx := auth.ContextWithTestSubjectAct(context.Background(), "cloud-daemon",
		[]string{"user"}, nil)
	md, _ := metadata.FromIncomingContext(ctx)
	md = md.Copy()
	md.Set(auth.MDKeyScopes, auth.ScopeTokensDelegate+","+auth.ScopeContainersRead)
	ctx = metadata.NewIncomingContext(context.Background(), md)

	resp, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{
		Subject: "alice@example.com",
		Scopes:  []string{auth.ScopeContainersRead},
		Roles:   []string{auth.RoleAdmin},
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	for _, r := range resp.GetGrantedRoles() {
		if r == auth.RoleAdmin {
			t.Fatal("granted admin to a caller that holds only the user role — roles were unioned, not intersected")
		}
	}
	claims, err := tm.ValidateToken(resp.GetToken())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if auth.HasRole(claims.Roles, auth.RoleAdmin) {
		t.Fatalf("minted token carries admin; roles=%v", claims.Roles)
	}
}

// The whole point of the roles field: an admin caller can pass admin through,
// so the cloud driver's calls reach admin-gated RPCs and cross-tenant paths.
// Without this the delegated token is useless for its actual purpose.
func TestExchangeDelegatedToken_AdminCallerCanDelegateAdmin(t *testing.T) {
	tm, err := auth.NewTokenManager(delegateTestSecret, "containarium-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	s := NewTokensServer(tm, nil, 0)
	ctx := callerCtx("cloud-region-driver", []string{auth.ScopeWildcard}, nil)

	resp, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{
		Subject: "tenant-alice",
		Scopes:  []string{auth.ScopeContainersRead, auth.ScopeContainersWrite},
		Roles:   []string{auth.RoleAdmin},
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	claims, err := tm.ValidateToken(resp.GetToken())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !auth.HasRole(claims.Roles, auth.RoleAdmin) {
		t.Fatalf("admin was not delegated; roles=%v — cross-tenant and admin-gated RPCs stay unreachable", claims.Roles)
	}
	// And it must still be bounded by scopes, which is what makes carrying
	// admin acceptable at all.
	pctx := auth.ContextWithTestSubjectScopes(context.Background(),
		claims.Username, claims.Roles, claims.Scopes)
	if err := auth.RequireScope(pctx, auth.ScopeSecretsRead); err == nil {
		t.Error("an admin-carrying delegated token reached a scope it was not granted")
	}
}

// Absent roles must mean NO roles. If this ever inherits the caller's, every
// delegated token silently becomes admin — the roles-shaped version of the
// empty-scope bug above.
func TestExchangeDelegatedToken_NoRolesRequestedMeansNoRoles(t *testing.T) {
	tm, _ := auth.NewTokenManager(delegateTestSecret, "containarium-test")
	s := NewTokensServer(tm, nil, 0)
	ctx := callerCtx("cloud-region-driver", []string{auth.ScopeWildcard}, nil)

	resp, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{
		Subject: "tenant-alice",
		Scopes:  []string{auth.ScopeContainersRead},
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	claims, _ := tm.ValidateToken(resp.GetToken())
	if len(claims.Roles) != 0 {
		t.Fatalf("roles = %v, want none — a caller that did not ask for a role must not get one", claims.Roles)
	}
	// Such a token is still useful: it can act for its own subject.
	pctx := auth.ContextWithTestSubjectScopes(context.Background(),
		claims.Username, claims.Roles, claims.Scopes)
	if err := auth.AuthorizeTenant(pctx, "tenant-alice"); err != nil {
		t.Errorf("role-less token cannot act for its own subject: %v", err)
	}
	if err := auth.AuthorizeTenant(pctx, "tenant-bob"); err == nil {
		t.Error("role-less token reached another tenant")
	}
}

// The reuse trap, pinned. IntersectScopes treats a nil caller as "no ceiling"
// and returns the requested set unchanged — correct for scopes, where an
// absent claim means unrestricted. Applied to roles it means a caller holding
// NO roles can mint an admin token, which is the whole escalation this
// endpoint is supposed to prevent.
//
// The two functions agree on every case where the caller holds something, so a
// test with a role-holding caller passes either way. This one does not.
func TestExchangeDelegatedToken_RolelessCallerCannotMintARole(t *testing.T) {
	tm, err := auth.NewTokenManager(delegateTestSecret, "containarium-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	s := NewTokensServer(tm, nil, 0)

	// Authenticated and scoped, but holding no roles whatsoever.
	md := metadata.Pairs(
		auth.MDKeyUsername, "roleless-service",
		auth.MDKeyRoles, "",
		auth.MDKeyScopes, auth.ScopeTokensDelegate+","+auth.ScopeContainersRead,
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := s.ExchangeDelegatedToken(ctx, &pb.ExchangeDelegatedTokenRequest{
		Subject: "tenant-alice",
		Scopes:  []string{auth.ScopeContainersRead},
		Roles:   []string{auth.RoleAdmin},
	})
	if err != nil {
		return // refusing outright is also correct
	}
	if len(resp.GetGrantedRoles()) != 0 {
		t.Fatalf("granted %v to a caller holding no roles at all", resp.GetGrantedRoles())
	}
	claims, verr := tm.ValidateToken(resp.GetToken())
	if verr != nil {
		t.Fatalf("validate: %v", verr)
	}
	if auth.HasRole(claims.Roles, auth.RoleAdmin) {
		t.Fatalf("a caller with no roles minted an admin token; roles=%v", claims.Roles)
	}
}
