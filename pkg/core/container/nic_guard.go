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
// instance is deleted and the error surfaces as FAILED_PRECONDITION, the
// same shape as an --encrypted create with no key provider.
var ErrNICGuard = errors.New("tenant network guard could not guard the container's NIC")

// SetNICGuard installs the guard consulted on every Create. Nil disables
// the hook (the default; the daemon wires the tenant guard when it builds
// one).
func (m *Manager) SetNICGuard(g NICGuard) { m.nicGuard = g }

// guardNIC runs the NICGuard hook for a just-created container. The tenant
// is resolved from what Create knows: the cloud_org_id attribution label
// when the hosted control plane created the box, else the
// <tenant>-container name. (The explicit user.containarium.tenant config
// key is written by the pull-mode actuator after create; the reconciler
// picks it up on its next pass.)
func (m *Manager) guardNIC(containerName string, opts CreateOptions) error {
	if m.nicGuard == nil {
		return nil
	}
	tenant := incus.ResolveTenant("", opts.Labels[incus.CloudOrgIDLabel], containerName)
	if err := m.nicGuard.Prepare(context.Background(), containerName, tenant); err != nil {
		return fmt.Errorf("%w: %v", ErrNICGuard, err)
	}
	return nil
}
