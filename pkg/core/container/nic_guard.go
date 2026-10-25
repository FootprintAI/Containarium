package container

import (
	"context"
	"errors"
	"fmt"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// NICGuard guards a container's NIC between create and start
// (docs/architecture/tenant-network-guard.md, "ACL-at-birth"): the tenant
// guard implements it by attaching the tenant's ingress ACL before the box
// is started, so there is no window in which a co-tenant can reach a new
// box. Prepare is a no-op when the guard is off.
type NICGuard interface {
	Prepare(ctx context.Context, containerName, tenant string) error
}

// ErrNICGuard wraps a Prepare failure. Create fails closed on it: the
// instance deletion is attempted and the error surfaces as FAILED_PRECONDITION, the
// same shape as an --encrypted create with no key provider.
var ErrNICGuard = errors.New("tenant network guard could not guard the container's NIC")

// SetNICGuard installs the guard consulted on every Create. Nil disables
// the hook (the default; the daemon wires the tenant guard when it builds
// one).
func (m *Manager) SetNICGuard(g NICGuard) { m.nicGuard = g }

// guardNIC runs the NICGuard hook for a just-created container. The tenant
// uses explicit native membership when supplied, otherwise the existing
// cloud_org_id / instance-name resolver. Required native membership is persisted
// before this call and must never use the legacy optional/no-op hook.
func (m *Manager) guardNIC(containerName string, opts CreateOptions) error {
	if opts.NetworkTenant != "" {
		// Ordinary Prepare can be a no-op on an unsupported/off guard.
		// Explicit security-domain assignment must never take that path.
		strict, ok := m.nicGuard.(interface {
			PrepareNetworkTenant(context.Context, string, string) error
		})
		if !ok {
			return fmt.Errorf("%w: explicit network Tenant requires an enforced NIC guard", ErrNICGuard)
		}
		if err := strict.PrepareNetworkTenant(context.Background(), containerName, opts.NetworkTenant); err != nil {
			return fmt.Errorf("%w: %v", ErrNICGuard, err)
		}
		return nil
	}
	if m.nicGuard == nil {
		return nil
	}
	tenant := incus.ResolveTenant("", opts.Labels[incus.CloudOrgIDLabel], containerName)
	if err := m.nicGuard.Prepare(context.Background(), containerName, tenant); err != nil {
		return fmt.Errorf("%w: %v", ErrNICGuard, err)
	}
	return nil
}

// cleanupGuardedCreate retains both causes when cleanup fails. The caller must
// inspect the original stopped instance before retrying; never start it as repair.
func (m *Manager) cleanupGuardedCreate(name string, cause error) error {
	if err := m.incus.DeleteContainer(name); err != nil {
		return errors.Join(cause, fmt.Errorf("cleanup failed for %q; instance retained stopped, inspect before retry: %w", name, err))
	}
	return cause
}
