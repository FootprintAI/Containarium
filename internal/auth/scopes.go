package auth

import "strings"

// Phase 1.7 — least-privilege scopes for MCP tools (audit
// finding tracked under the 1.7 line in
// docs/security/ZERO-TRUST-TODO.md).
//
// JWT scopes work the way OAuth2 scopes do: a token can
// carry an array of granted scopes (`scopes` claim); the
// receiver checks that the action's required scope is in
// that list before allowing it. They're orthogonal to roles
// — admin role + narrow scopes = "this LLM agent can act
// on my containers but cannot touch secrets" — and the
// least-privilege win is real for the MCP case where an
// agent's JWT effectively grants every tool today.
//
// Backwards compat is preserved by treating a missing or
// nil `scopes` claim as "no scope restriction" — existing
// tokens behave exactly as before. Operators opt in by
// minting tokens with the `--scopes` flag.
//
// Scope strings follow `<resource>:<action>`. The wildcard
// scope `*` matches anything — useful for the daemon's
// long-lived "service" tokens which need full surface
// access. Avoid `*` for tokens handed to agents.

// Scope constants. Keep this list short; new scopes need a
// careful audit (each new scope is a new policy decision).
const (
	ScopeWildcard = "*"

	// container management
	ScopeContainersRead  = "containers:read"
	ScopeContainersWrite = "containers:write"

	// secrets (separate from containers — much higher risk)
	ScopeSecretsRead  = "secrets:read"
	ScopeSecretsWrite = "secrets:write"

	// database backups (BackupServer). Separate from containers:
	// a backup read returns dump locations/checksums, and a write
	// can exfiltrate a tenant's whole database off-host or restore
	// (destructively) over it — both warrant their own grant.
	ScopeBackupsRead  = "backups:read"
	ScopeBackupsWrite = "backups:write"

	// shared volumes (VolumeServer). A write can create/attach/delete
	// CephFS volumes mounted RW across tenants — cross-tenant data
	// surface, so it's gated separately from containers.
	ScopeVolumesRead  = "volumes:read"
	ScopeVolumesWrite = "volumes:write"

	// routes / expose (network surface)
	ScopeRoutesRead  = "routes:read"
	ScopeRoutesWrite = "routes:write"

	// security findings + scanning (ZapServer, PentestServer,
	// ClamAV reads on SecurityServer)
	ScopeSecurityRead  = "security:read"
	ScopeSecurityWrite = "security:write"

	// alerting rules + webhook config
	ScopeAlertsRead  = "alerts:read"
	ScopeAlertsWrite = "alerts:write"

	// traffic introspection (TrafficServer)
	ScopeTrafficRead = "traffic:read"

	// developer-loop tools (push, sync, sync_ssh_config)
	ScopeCodeWrite = "code:write"
	ScopeSSHWrite  = "ssh:write"

	// JWT lifecycle (revoke). Admin role still required on
	// the server side — this scope just narrows what an
	// agent token CAN do; admin-on-paper agent tokens
	// without `tokens:write` can't revoke either.
	ScopeTokensWrite = "tokens:write"
)

// HasScope returns true when the granted-scopes set covers
// the required scope. Semantics:
//
//   - `granted == nil` → no scope restriction. Returns true
//     for any required scope. This is the backwards-compat
//     path: tokens minted before Phase 1.7 don't carry a
//     scopes claim, and they keep working.
//   - `granted == []string{"*"}` (or includes "*") → any
//     scope is allowed.
//   - otherwise → exact membership check.
//
// Empty required scope is interpreted as "no scope needed"
// (some MCP tools are pure-introspection — list_backends,
// get_system_info — and don't gate on a resource); these
// always return true. Use this sparingly; the explicit
// catalog is the supply chain of trust.
func HasScope(granted []string, required string) bool {
	if required == "" {
		return true
	}
	if granted == nil {
		return true
	}
	for _, s := range granted {
		s = strings.TrimSpace(s)
		if s == ScopeWildcard || s == required {
			return true
		}
	}
	return false
}

// ParseScopes normalizes a comma-separated scope string
// into a []string suitable for the JWT claim. Whitespace
// and empty elements are dropped; the order of remaining
// entries is preserved.
//
// Returns nil for an empty or whitespace-only input — the
// caller decides whether that means "no restriction" (omit
// the claim) or "deny everything" (set an empty array).
// HasScope treats nil as "no restriction".
func ParseScopes(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
