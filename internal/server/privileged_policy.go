package server

import (
	"context"
	"log"
	"os"
	"strings"
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
//   all         (default) — pre-Phase-3 behavior: any caller that
//                requests podman gets a privileged container.
//                Backwards-compatible.
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

var (
	privilegedPolicyOnce sync.Once
	privilegedPolicy     PrivilegedPolicy
)

func loadPrivilegedPolicy() PrivilegedPolicy {
	privilegedPolicyOnce.Do(func() {
		raw := strings.ToLower(strings.TrimSpace(os.Getenv(privilegedPolicyEnv)))
		switch raw {
		case "", "all":
			privilegedPolicy = PrivilegedPolicyAll
			log.Printf("WARNING: %s is %q — any user who enables Podman gets a privileged container (audit A-HIGH-3 still open)", privilegedPolicyEnv, "all")
		case "admin-only":
			privilegedPolicy = PrivilegedPolicyAdminOnly
			log.Printf("[privileged-policy] enabled = admin-only; non-admin podman requests will be rejected")
		case "disabled":
			privilegedPolicy = PrivilegedPolicyDisabled
			log.Printf("[privileged-policy] enabled = disabled; privileged Podman is OFF for every caller including admins")
		default:
			privilegedPolicy = PrivilegedPolicyAll
			log.Printf("WARNING: %s=%q is unrecognized; defaulting to 'all' (any user gets privileged Podman)", privilegedPolicyEnv, raw)
		}
	})
	return privilegedPolicy
}

// authorizePrivilegedPodman decides whether the caller's
// `enable_podman=true` request should result in a privileged
// container. Returns:
//
//   (true,  nil)       — set EnablePodmanPrivileged=true
//   (false, nil)       — set EnablePodmanPrivileged=false (Podman
//                        runs unprivileged; some workloads break,
//                        but the daemon doesn't return an error)
//   (false, err)       — reject the CreateContainer call entirely
//                        with status.Error
//
// The choice between "silently downgrade" and "reject" depends on
// policy:
//   - PrivilegedPolicyAll       → (true, nil)
//   - PrivilegedPolicyAdminOnly → (true, nil) for admin; (false,
//                                  PermissionDenied) for non-admin
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
	return true, nil
}
