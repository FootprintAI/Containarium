package auth

import (
	"context"
	"encoding/json"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Metadata keys used to propagate the authenticated subject from
// the HTTP/JWT layer through grpc-gateway into the gRPC server.
// Set by AuthMiddleware (HTTP) and by the gateway annotator
// (internal/gateway/gateway.go), read by SubjectFromGRPCContext.
//
// Phase 1.7b — `scopes` joined the trio. Stored as a comma-
// separated string in metadata (gRPC metadata is single-line
// per key, and []string is fragile across the wire).
//
// #1677 — `act` joined too. Unlike scopes it's a nested struct, not a
// flat list, so it's carried as a single JSON-encoded string rather than
// a delimited join.
// #1678 — `jti` joined too, so audit rows can name the acting credential
// ("given a token_id, what did it do"). It wasn't propagated before because
// nothing needed it off the HTTP layer; the audit package is the first
// gRPC-side consumer.
const (
	MDKeyUsername = "username"
	MDKeyRoles    = "roles"
	MDKeyScopes   = "scopes"
	MDKeyAct      = "act"
	MDKeyJTI      = "jti"
)

// RoleAdmin is the role granted to operator / system tokens. Holders
// bypass per-tenant subject checks (see AuthorizeTenant). Issued by
// `containarium token generate --roles admin`.
const RoleAdmin = "admin"

// SystemSubject is the synthetic username carried by daemon-internal
// contexts (autosleep, peer-to-peer forwarders, startup tasks) that
// don't originate from a user request. Combined with the admin role
// it passes AuthorizeTenant for any target tenant.
const SystemSubject = "_system"

// ContextWithSystemIdentity returns a context tagged as the
// daemon-internal _system principal with admin role. Use it at the
// entry point of any code path that calls an RPC handler from a
// non-user context (autosleep ticker, peer forwarding, startup
// reconcilers). Without this, AuthorizeTenant rejects the call as
// Unauthenticated.
func ContextWithSystemIdentity(ctx context.Context) context.Context {
	claims := &Claims{Username: SystemSubject, Roles: []string{RoleAdmin}}
	return ContextWithClaims(ctx, claims)
}

// ContextWithTestSubject is a test-only helper that constructs a
// gRPC-incoming context with the given username and roles. Wires up
// metadata exactly the way the gateway annotator does in production.
// Lives in non-test code so multiple packages' tests can use it.
func ContextWithTestSubject(ctx context.Context, username string, roles ...string) context.Context {
	md := metadata.Pairs(MDKeyUsername, username, MDKeyRoles, strings.Join(roles, ","))
	return metadata.NewIncomingContext(ctx, md)
}

// ContextWithTestSubjectScopes is a test-only helper that also
// stamps a scopes claim. Used by Phase 1.7b RequireScope tests.
// Pass scopes=nil for an unrestricted token (matches the pre-1.7
// production path).
func ContextWithTestSubjectScopes(ctx context.Context, username string, roles []string, scopes []string) context.Context {
	pairs := []string{MDKeyUsername, username, MDKeyRoles, strings.Join(roles, ",")}
	if scopes != nil {
		pairs = append(pairs, MDKeyScopes, strings.Join(scopes, ","))
	}
	md := metadata.Pairs(pairs...)
	return metadata.NewIncomingContext(ctx, md)
}

// ContextWithTestSubjectAct is a test-only helper that also stamps a
// delegation (`act`) claim, the same way the gateway annotator does in
// production (#1677). Pass act=nil for an undelegated caller.
func ContextWithTestSubjectAct(ctx context.Context, username string, roles []string, act *Actor) context.Context {
	pairs := []string{MDKeyUsername, username, MDKeyRoles, strings.Join(roles, ",")}
	if act != nil {
		encoded, err := json.Marshal(act)
		if err == nil {
			pairs = append(pairs, MDKeyAct, string(encoded))
		}
	}
	md := metadata.Pairs(pairs...)
	return metadata.NewIncomingContext(ctx, md)
}

// ContextWithTestJTI is a test-only helper that stamps a jti onto an
// existing gRPC-incoming test context (e.g. one built by
// ContextWithTestSubject or ContextWithTestSubjectAct), the same way a
// chain of HTTP middleware would layer metadata onto a single request.
// Merges into whatever metadata is already present rather than replacing
// it, so it composes with the other ContextWithTestSubject* helpers. #1678.
func ContextWithTestJTI(ctx context.Context, jti string) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	md = md.Copy()
	md.Set(MDKeyJTI, jti)
	return metadata.NewIncomingContext(ctx, md)
}

// SubjectFromGRPCContext returns the authenticated username and
// roles. It looks first at incoming gRPC metadata (the production
// path: HTTP middleware → gateway annotator → gRPC metadata), then
// falls back to context values for in-process gRPC calls and tests.
// The boolean is false if no subject is in either place.
func SubjectFromGRPCContext(ctx context.Context) (username string, roles []string, ok bool) {
	if md, mdOk := metadata.FromIncomingContext(ctx); mdOk {
		if vals := md.Get(MDKeyUsername); len(vals) > 0 && vals[0] != "" {
			username = vals[0]
			ok = true
		}
		if vals := md.Get(MDKeyRoles); len(vals) > 0 && vals[0] != "" {
			roles = splitRoles(vals[0])
		}
	}
	if !ok {
		if u, found := UsernameFromContext(ctx); found && u != "" {
			username = u
			ok = true
		}
	}
	if len(roles) == 0 {
		if r, found := RolesFromContext(ctx); found {
			roles = r
		}
	}
	return username, roles, ok
}

// ScopesFromGRPCContext returns the JWT's `scopes` claim
// propagated through metadata or context. Returns (nil, false)
// when the claim wasn't carried — distinct from (empty, true)
// which would mean an explicit empty grant. HasScope treats nil
// as "no restriction" (Phase 1.7 backwards-compat), so callers
// can pass the returned slice through to HasScope directly.
func ScopesFromGRPCContext(ctx context.Context) (scopes []string, present bool) {
	if md, mdOk := metadata.FromIncomingContext(ctx); mdOk {
		if vals := md.Get(MDKeyScopes); len(vals) > 0 {
			if vals[0] == "" {
				return nil, false
			}
			return ParseScopes(vals[0]), true
		}
	}
	if s, found := ScopesFromContext(ctx); found {
		return s, s != nil
	}
	return nil, false
}

// ActFromGRPCContext returns the JWT's `act` delegation claim (#1677)
// propagated through metadata or context — the same
// metadata-then-context-value fallback ScopesFromGRPCContext and
// SubjectFromGRPCContext use, and for the same reason: the primary API
// surface is REST via grpc-gateway, and the caller's claims only survive
// that hop as gRPC metadata, not a context value. Returns (nil, false) when
// no delegation was carried — the valid, backward-compatible "unattributed"
// case, never an error.
func ActFromGRPCContext(ctx context.Context) (act *Actor, present bool) {
	if md, mdOk := metadata.FromIncomingContext(ctx); mdOk {
		if vals := md.Get(MDKeyAct); len(vals) > 0 && vals[0] != "" {
			var a Actor
			if err := json.Unmarshal([]byte(vals[0]), &a); err == nil {
				return &a, true
			}
			return nil, false
		}
	}
	if a, found := ActFromContext(ctx); found {
		return a, a != nil
	}
	return nil, false
}

// JTIFromGRPCContext returns the authenticated token's own `jti` claim
// (#1678), propagated through metadata or context the same way
// ActFromGRPCContext's claim is. Audit attribution is the first gRPC-side
// consumer — nothing needed jti off the HTTP layer before. Returns ("",
// false) when no jti was carried (pre-1.2 tokens minted without one, or a
// caller that bypassed the standard mint path).
func JTIFromGRPCContext(ctx context.Context) (jti string, present bool) {
	if md, mdOk := metadata.FromIncomingContext(ctx); mdOk {
		if vals := md.Get(MDKeyJTI); len(vals) > 0 && vals[0] != "" {
			return vals[0], true
		}
	}
	if j, found := JTIFromContext(ctx); found && j != "" {
		return j, true
	}
	return "", false
}

// HasRole reports whether `roles` contains `wanted`.
func HasRole(roles []string, wanted string) bool {
	for _, r := range roles {
		if r == wanted {
			return true
		}
	}
	return false
}

// RequireRole returns nil if the authenticated subject holds
// `role`. Returns Unauthenticated if no subject is in context,
// PermissionDenied if the subject exists but lacks the role.
//
// Use at the top of handlers that should be admin-only — fleet
// topology disclosure, cross-backend infrastructure operations,
// peer-to-peer system endpoints. Tenant-scoped operations should
// use AuthorizeTenant instead; this is for the strictly-narrower
// class of cluster-wide ops. Tracks audit finding A-MED-4.
func RequireRole(ctx context.Context, role string) error {
	_, roles, ok := SubjectFromGRPCContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no authenticated subject in request context")
	}
	if !HasRole(roles, role) {
		return status.Error(codes.PermissionDenied, "role required: "+role)
	}
	return nil
}

// RequireRoleOrScope passes if the caller holds the role OR explicitly holds
// the scope. It's for read paths an admin reaches by role and a
// least-privilege token reaches by an explicit read scope (#621). Uses
// HasExplicitScope, not HasScope — an absent scopes claim must NOT unlock an
// otherwise admin-only read.
func RequireRoleOrScope(ctx context.Context, role, scope string) error {
	_, roles, ok := SubjectFromGRPCContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no authenticated subject in request context")
	}
	if HasRole(roles, role) {
		return nil
	}
	if scopes, _ := ScopesFromGRPCContext(ctx); HasExplicitScope(scopes, scope) {
		return nil
	}
	return status.Errorf(codes.PermissionDenied, "requires role %q or scope %q", role, scope)
}

// RequireScope returns nil if the authenticated subject's JWT
// carries the required scope (or no scopes claim at all, which
// is the Phase 1.7 backwards-compat "unrestricted" path — unless
// strict mode is armed, see below). Returns Unauthenticated when
// no subject is in context and PermissionDenied when scopes are
// explicitly granted but the required one is missing.
//
// Use at the top of handlers AFTER the existing role check, not
// instead of it. Roles and scopes are orthogonal: roles answer
// "who is this caller?", scopes answer "what was this specific
// token authorized to do?". Both must pass.
//
// Phase 1.7b — pairs with the MCP-side filter landed in PR #250.
// The MCP filter catches agent abuse before the network call;
// this catches REST/gRPC callers who bypass MCP entirely.
//
// #1679 — every call whose token carries no scopes claim is
// recorded (see UnscopedTokenCalls), regardless of mode, so an
// operator can measure the unscoped population before opting in.
// When StrictScopesEnabled(), such a call is rejected outright
// instead of falling through to the backwards-compat unrestricted
// path; IsStrictScopesDenial distinguishes that rejection from an
// ordinary insufficient-scope denial.
func RequireScope(ctx context.Context, required string) error {
	if _, _, ok := SubjectFromGRPCContext(ctx); !ok {
		return status.Error(codes.Unauthenticated, "no authenticated subject in request context")
	}
	scopes, present := ScopesFromGRPCContext(ctx)
	if !present {
		recordUnscopedCall()
		if StrictScopesEnabled() {
			return status.Errorf(codes.PermissionDenied, "%s (scope required: %s) — mint a token with --scopes", strictScopesDenialPrefix, required)
		}
	}
	if HasScope(scopes, required) {
		return nil
	}
	return status.Error(codes.PermissionDenied, "scope required: "+required)
}

// AuthorizeTenant returns nil if the authenticated subject is
// allowed to act on `requestedUsername` — either because they are
// that user, or because they hold the admin role. Returns a
// PermissionDenied gRPC status otherwise, and Unauthenticated if
// no subject is in context at all.
//
// Call at the top of every gRPC handler that takes a username from
// the request body. Without this check, a token issued to tenant A
// can act on tenant B's resources (CWE-639 IDOR).
func AuthorizeTenant(ctx context.Context, requestedUsername string) error {
	subject, roles, ok := SubjectFromGRPCContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no authenticated subject in request context")
	}
	if HasRole(roles, RoleAdmin) {
		return nil
	}
	if subject != requestedUsername {
		return status.Error(codes.PermissionDenied, "not authorized for this tenant")
	}
	return nil
}

func splitRoles(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
