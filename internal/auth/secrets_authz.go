package auth

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthorizeSecretTenant is AuthorizeTenant for the secret RPCs, with one extra
// requirement on the cross-tenant path.
//
// Why this exists rather than reusing AuthorizeTenant. Two behaviors that are
// each reasonable on their own compose into an unintended one:
//
//  1. HasScope treats a nil scopes claim as "unrestricted" — `token generate`
//     without --scopes is documented that way, and RequireScope therefore
//     cannot deny anything to such a token.
//  2. AuthorizeTenant short-circuits on the admin role, so `req.Username` is
//     not compared against the caller.
//
// Together, a token minted `--roles admin` with no --scopes — the ordinary
// shape for an orchestrator, CI runner, or automation account — passes both
// gates on GetSecret for ANY tenant and receives the decrypted value. Envelope
// encryption does not help there: the daemon decrypts on demand for the caller.
// So whoever holds one such token holds every tenant's third-party API keys.
//
// The rule here targets that composition and nothing else:
//
//   - A caller acting on ITS OWN tenant is unaffected. That is not the
//     vulnerability, and it is the path every ordinary `containarium secrets`
//     invocation takes, so tightening it would break working deployments to no
//     security end.
//   - A caller acting on ANOTHER tenant needs the admin role AND the relevant
//     secrets scope stated explicitly in its token. The role alone no longer
//     implies it.
//
// The effect is that cross-tenant plaintext access becomes a property an
// operator grants deliberately, per token, instead of one that rides along with
// every admin credential in the deployment. An operator who genuinely needs it
// re-mints with `--scopes secrets:read` (or `secrets:write`) and carries on.
//
// Note that this deliberately does NOT change HasScope's nil semantics. Doing
// that globally would revoke every existing unscoped token across every RPC at
// once — a much larger blast radius than the one being closed, and in the
// unhelpful direction.
func AuthorizeSecretTenant(ctx context.Context, requestedUsername, requiredScope string) error {
	subject, roles, ok := SubjectFromGRPCContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no authenticated subject in request context")
	}

	// Self-access: unchanged from AuthorizeTenant.
	if subject == requestedUsername {
		return nil
	}

	// Cross-tenant at all still requires the admin role.
	if !HasRole(roles, RoleAdmin) {
		return status.Error(codes.PermissionDenied, "not authorized for this tenant")
	}

	// ...and, for secrets specifically, an explicitly granted scope.
	// HasExplicitScope (unlike HasScope) does not treat an absent claim as a
	// match, which is the whole point: a missing claim must not silently unlock
	// another tenant's plaintext.
	scopes, _ := ScopesFromGRPCContext(ctx)
	if !HasExplicitScope(scopes, requiredScope) {
		return status.Error(codes.PermissionDenied,
			"cross-tenant secret access requires the "+requiredScope+
				" scope to be granted explicitly on this token; the admin role alone no longer implies it "+
				"(re-mint with `containarium token generate --scopes "+requiredScope+" ...`)")
	}
	return nil
}
