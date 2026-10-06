package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/footprintai/containarium/internal/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Privileged-Podman authorization policy (audit A-HIGH-3).
//
// The pre-Phase-3 behavior: `enable_podman=true` on CreateContainer
// silently set `security.privileged=true` and `lxc.apparmor.profile=unconfined`
// on the LXC, granting the user effective host-root inside the
// container. Anyone with CreateContainer permission could
// elevate to a privileged container — by design, but a HIGH
// severity privilege-escalation primitive when tenants aren't
// trusted.
//
// The new policy:
//
//   CONTAINARIUM_PRIVILEGED_PODMAN_POLICY = all | admin-only | disabled
//
//   all         (default when unset) — pre-Phase-3 behavior: any
//                caller that requests podman gets a privileged
//                container. Backwards-compatible.
//   admin-only  — only callers with the admin role get privileged
//                podman; non-admin requests are rejected with
//                PermissionDenied. Recommended for multi-tenant
//                deployments.
//   disabled    — no caller gets a privileged container, even
//                admins. Podman falls back to unprivileged mode
//                (limited functionality). For paranoid setups.
//
// The default stays `all` for backwards compat during rollout.
// Operators set the env var to `admin-only` once they've
// verified that no non-admin workflow requires privileged Podman.
//
// Matching is exact (#2299): the value must be one of the three
// lowercase spellings above, with no surrounding whitespace. Unset —
// or set to the empty string, which is how most env templating
// spells "unset" — keeps the `all` default. Anything else (a typo,
// `ALL`, `Disabled `, `none`) fails closed: the daemon refuses to
// start (validatePrivilegedPolicyEnv, called from NewDualServer), and
// any path that reads the policy without that check treats it as
// `disabled`. A mistyped restrictive setting must never silently
// become the most permissive one.
//
// A future iteration can split `enable_podman` from
// `enable_privileged` in the proto contract; this PR keeps the
// proto shape and gates the implied privilege escalation server-side.

const privilegedPolicyEnv = "CONTAINARIUM_PRIVILEGED_PODMAN_POLICY"

type PrivilegedPolicy int

const (
	PrivilegedPolicyAll PrivilegedPolicy = iota // pre-Phase-3 default
	PrivilegedPolicyAdminOnly
	PrivilegedPolicyDisabled
)

// The accepted spellings, one per policy. Parsing compares against these
// exactly; String renders them back.
const (
	privilegedPolicyValueAll       = "all"
	privilegedPolicyValueAdminOnly = "admin-only"
	privilegedPolicyValueDisabled  = "disabled"
)

func (p PrivilegedPolicy) String() string {
	switch p {
	case PrivilegedPolicyAll:
		return privilegedPolicyValueAll
	case PrivilegedPolicyAdminOnly:
		return privilegedPolicyValueAdminOnly
	case PrivilegedPolicyDisabled:
		return privilegedPolicyValueDisabled
	}
	return fmt.Sprintf("PrivilegedPolicy(%d)", int(p))
}

var (
	privilegedPolicyOnce sync.Once
	privilegedPolicy     PrivilegedPolicy
	privilegedPolicyErr  error
)

// parsePrivilegedPolicy maps the raw env value to a policy. set reports
// whether the variable is present in the environment at all. An unset or
// empty value yields the backwards-compatible `all`. Any other value that
// is not exactly one of the three accepted spellings returns an error AND
// PrivilegedPolicyDisabled, so a caller that ignores the error still fails
// closed.
func parsePrivilegedPolicy(raw string, set bool) (PrivilegedPolicy, error) {
	if !set || raw == "" {
		return PrivilegedPolicyAll, nil
	}
	switch raw {
	case privilegedPolicyValueAll:
		return PrivilegedPolicyAll, nil
	case privilegedPolicyValueAdminOnly:
		return PrivilegedPolicyAdminOnly, nil
	case privilegedPolicyValueDisabled:
		return PrivilegedPolicyDisabled, nil
	}
	return PrivilegedPolicyDisabled, fmt.Errorf(
		"%s=%q is not a recognised policy; it must be exactly one of %q, %q or %q (lowercase, no surrounding whitespace), or unset",
		privilegedPolicyEnv, raw,
		privilegedPolicyValueAll, privilegedPolicyValueAdminOnly, privilegedPolicyValueDisabled)
}

// loadPrivilegedPolicy reads the policy once per process. An unrecognised
// value resolves to PrivilegedPolicyDisabled (fail closed); the error is
// kept for validatePrivilegedPolicyEnv to report at startup.
func loadPrivilegedPolicy() PrivilegedPolicy {
	privilegedPolicyOnce.Do(func() {
		raw, set := os.LookupEnv(privilegedPolicyEnv)
		privilegedPolicy, privilegedPolicyErr = parsePrivilegedPolicy(raw, set)
		switch {
		case privilegedPolicyErr != nil:
			log.Printf("ERROR: %v; treating it as %q (privileged Podman is OFF for every caller)", privilegedPolicyErr, privilegedPolicy)
		case privilegedPolicy == PrivilegedPolicyAll:
			log.Printf("WARNING: %s is %q — any user who enables Podman gets a privileged container (audit A-HIGH-3 still open)", privilegedPolicyEnv, privilegedPolicy)
		case privilegedPolicy == PrivilegedPolicyAdminOnly:
			log.Printf("[privileged-policy] enabled = admin-only; non-admin podman requests will be rejected")
		case privilegedPolicy == PrivilegedPolicyDisabled:
			log.Printf("[privileged-policy] enabled = disabled; privileged Podman is OFF for every caller including admins")
		}
	})
	return privilegedPolicy
}

// validatePrivilegedPolicyEnv loads the policy eagerly and returns an error
// when the variable is set to an unrecognised value. NewDualServer calls it
// so the daemon refuses to start on a typo instead of discovering it at the
// first podman create.
func validatePrivilegedPolicyEnv() error {
	loadPrivilegedPolicy()
	return privilegedPolicyErr
}

// authorizePrivilegedPodman decides whether the caller's
// `enable_podman=true` request should result in a privileged
// container. Returns:
//
//	(true,  nil)       — set EnablePodmanPrivileged=true
//	(false, nil)       — set EnablePodmanPrivileged=false (Podman
//	                     runs unprivileged; some workloads break,
//	                     but the daemon doesn't return an error)
//	(false, err)       — reject the CreateContainer call entirely
//	                     with status.Error
//
// The choice between "silently downgrade" and "reject" depends on
// policy:
//   - PrivilegedPolicyAll       → (true, nil)
//   - PrivilegedPolicyAdminOnly → (true, nil) for admin; (false,
//     PermissionDenied) for non-admin
//   - PrivilegedPolicyDisabled  → (false, nil) — downgrade
func authorizePrivilegedPodman(ctx context.Context) (bool, error) {
	switch loadPrivilegedPolicy() {
	case PrivilegedPolicyAll:
		return true, nil
	case PrivilegedPolicyDisabled:
		return false, nil
	case PrivilegedPolicyAdminOnly:
		if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
			return false, status.Errorf(codes.PermissionDenied,
				"privileged Podman is admin-only on this daemon (set %s=disabled to drop privileged mode entirely)",
				privilegedPolicyEnv)
		}
		return true, nil
	}
	// Unreachable with the three policies above; fail closed if a new one
	// is added without a case here.
	return false, nil
}
