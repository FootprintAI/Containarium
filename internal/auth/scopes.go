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

	// KMS / envelope-encryption administration (KmsService).
	// Platform-wide, not tenant-scoped: reports the active KMS
	// backend, envelope coverage, and triggers legacy→envelope
	// migration. Admin role is ALSO required on the server side —
	// this scope just narrows what an admin token CAN do.
	ScopeKMSAdmin = "kms:admin"

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

	// tokens:delegate — mint a token that acts FOR another subject
	// (ExchangeDelegatedToken, containarium-cloud#1427). Deliberately
	// SEPARATE from tokens:write: managing your own tokens and acting as
	// someone else are different capabilities, and the second is the one
	// that puts a name in an audit row. A service that fronts this API for
	// end users needs exactly this and nothing else from the tokens
	// surface, so it should be grantable on its own.
	ScopeTokensDelegate = "tokens:delegate"

	// agent skills (AgentSkillService). `agents:read` lists/inspects the
	// skill catalog; `agents:run` provisions a skill's box and runs a task.
	// A skill's OWN token is minted with only the scopes the skill declares
	// (allowed_scopes) — these two gate the operator/agent that drives the
	// AgentSkillService, not the skill's in-box token.
	ScopeAgentsRead = "agents:read"
	ScopeAgentsRun  = "agents:run"
	// agents:call delegates a task to a running peer agent over A2A
	// (SendAgentTask). Separate from agents:run: running a skill provisions a
	// box, calling a peer only sends it work.
	ScopeAgentsCall = "agents:call"

	// crews (CrewService). crews:read lists/inspects the crew catalog;
	// crews:run provisions a crew's member boxes and runs the collaboration.
	ScopeCrewsRead = "crews:read"
	ScopeCrewsRun  = "crews:run"

	// managed Kubernetes clusters (ClusterServer, #1413).
	// clusters:read lists/inspects clusters and their scale history;
	// clusters:write creates/deletes clusters, edits node pools, and
	// fetches the kubeconfig — the kubeconfig is deliberately behind
	// the WRITE scope because it is cluster-admin material (holding it
	// mutates the cluster's workloads), so an inspection-only token
	// cannot take control of a cluster.
	ScopeClustersRead  = "clusters:read"
	ScopeClustersWrite = "clusters:write"
	// clusters:scale is the cluster-autoscaler machine credential's
	// ONLY scope (#1415): resize the token's own cluster's node pool
	// within server-enforced bounds. It grants no read of other
	// clusters, no kubeconfig, no create/delete.
	ScopeClustersScale = "clusters:scale"

	// read-only scopes for surfaces that were admin-only, so a least-privilege
	// (e.g. compliance/evidence) token can read one without full admin (#621).
	ScopeAuditRead         = "audit:read"          // audit-log query
	ScopeNetworkPolicyRead = "network-policy:read" // NetworkPolicyService Get/List
	ScopeTokensRead        = "tokens:read"         // token listing

	// ephemeral sandboxes (SandboxServer, #1488). A sandbox has no
	// per-tenant Linux account and no SSH — spawn/exec/file/delete is its
	// entire access surface, and an agent's own token is what reaches it,
	// so it's gated separately from the persistent-box containers scope
	// rather than folded into it.
	ScopeSandboxesRead  = "sandboxes:read"
	ScopeSandboxesWrite = "sandboxes:write"
)

// AllScopes is the catalog of every known scope. It backs IsKnownScope so
// callers (e.g. the skill catalog) can reject a manifest that declares a
// scope that does not exist — turning a typo into a load-time error instead
// of a silently-overbroad token.
var AllScopes = []string{
	ScopeContainersRead, ScopeContainersWrite,
	ScopeSecretsRead, ScopeSecretsWrite,
	ScopeKMSAdmin,
	ScopeBackupsRead, ScopeBackupsWrite,
	ScopeVolumesRead, ScopeVolumesWrite,
	ScopeRoutesRead, ScopeRoutesWrite,
	ScopeSecurityRead, ScopeSecurityWrite,
	ScopeAlertsRead, ScopeAlertsWrite,
	ScopeTrafficRead,
	ScopeCodeWrite, ScopeSSHWrite,
	ScopeTokensWrite, ScopeTokensDelegate,
	ScopeAgentsRead, ScopeAgentsRun, ScopeAgentsCall,
	ScopeCrewsRead, ScopeCrewsRun,
	ScopeClustersRead, ScopeClustersWrite, ScopeClustersScale,
	ScopeAuditRead, ScopeNetworkPolicyRead, ScopeTokensRead,
}

// HasExplicitScope reports whether want is explicitly in granted (or the
// wildcard is). Unlike HasScope, a nil/absent scopes claim does NOT match —
// use this when *granting* access by scope (a missing claim must not silently
// unlock an otherwise admin-only read).
func HasExplicitScope(granted []string, want string) bool {
	for _, s := range granted {
		if s = strings.TrimSpace(s); s == want || s == ScopeWildcard {
			return true
		}
	}
	return false
}

// IsKnownScope reports whether s is a defined scope (the wildcard counts).
func IsKnownScope(s string) bool {
	if s == ScopeWildcard {
		return true
	}
	for _, k := range AllScopes {
		if k == s {
			return true
		}
	}
	return false
}

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

// IntersectScopes bounds a manifest's scopes by the caller's own granted
// scopes, so a scope catalog (e.g. a skill's allowed_scopes) is a ceiling and
// never a floor (#1676). Semantics mirror HasScope:
//
//   - caller == nil → unrestricted caller (no scopes claim, the Phase 1.7
//     backwards-compat path); the manifest passes through unchanged.
//   - caller containing the wildcard → same as unrestricted.
//   - manifest containing the wildcard → the caller's own scopes pass through
//     unchanged (the manifest imposes no additional ceiling).
//   - otherwise → the set intersection: only scopes present in both.
//
// A non-nil but empty caller (explicit zero-scope token) intersects to empty
// regardless of the manifest — fail closed, matching HasScope's explicit-deny
// semantics for an empty granted list.
//
// Always returns a non-nil slice, so a caller can safely range over or mint a
// token from the result without a nil check.
func IntersectScopes(caller, manifest []string) []string {
	if caller == nil || HasExplicitScope(caller, ScopeWildcard) {
		out := make([]string, len(manifest))
		copy(out, manifest)
		return out
	}
	if HasExplicitScope(manifest, ScopeWildcard) {
		out := make([]string, len(caller))
		copy(out, caller)
		return out
	}
	callerSet := make(map[string]struct{}, len(caller))
	for _, s := range caller {
		callerSet[strings.TrimSpace(s)] = struct{}{}
	}
	out := make([]string, 0, len(manifest))
	for _, s := range manifest {
		s = strings.TrimSpace(s)
		if _, ok := callerSet[s]; ok {
			out = append(out, s)
		}
	}
	return out
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
