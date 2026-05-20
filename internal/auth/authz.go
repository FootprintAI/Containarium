package auth

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Metadata keys used to propagate the authenticated subject from
// the HTTP/JWT layer through grpc-gateway into the gRPC server.
// Set by AuthMiddleware (HTTP) and by the gateway annotator
// (internal/gateway/gateway.go), read by SubjectFromGRPCContext.
const (
	MDKeyUsername = "username"
	MDKeyRoles    = "roles"
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

// HasRole reports whether `roles` contains `wanted`.
func HasRole(roles []string, wanted string) bool {
	for _, r := range roles {
		if r == wanted {
			return true
		}
	}
	return false
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
