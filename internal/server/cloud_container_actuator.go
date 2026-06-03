package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/cloud"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// cloudContainerActuator implements cloud.ContainerActuator by driving the local
// Incus instance state for cloud-assigned containers (#354). Create stamps
// user.containarium.tenant=<org_id> so the #315 network-policy enforcer can match
// the container to its org's egress policy (cloud names are cld-<uuid>, not
// <tenant>-container, so the label — not the name — carries the tenant).
//
// Scope: create / start / stop / delete to converge to desired_state. It does
// NOT manage routes, secrets, or the richer create options the user-facing
// ContainerService offers — cloud-assigned boxes are minimal v1 workloads.
type cloudContainerActuator struct {
	incus *incus.Client
}

// newCloudContainerActuator builds an actuator with its own Incus client.
// Returns an error (→ caller runs policy-sync-only) if Incus is unavailable,
// e.g. on a non-Linux dev box.
func newCloudContainerActuator() (*cloudContainerActuator, error) {
	c, err := incus.New()
	if err != nil {
		return nil, fmt.Errorf("incus client: %w", err)
	}
	return &cloudContainerActuator{incus: c}, nil
}

// EnsureRunning creates the container (stamping the tenant label) if absent, then
// ensures it is started. Idempotent.
func (a *cloudContainerActuator) EnsureRunning(_ context.Context, spec cloud.ContainerSpec) error {
	info, err := a.incus.GetContainer(spec.LocalName)
	if err != nil {
		// Treat any lookup failure as "not present" and try to create — a real
		// create error surfaces below; a benign not-found proceeds to create.
		if cerr := a.create(spec); cerr != nil {
			return cerr
		}
	} else if isRunning(info.State) {
		return nil // already converged
	}
	if err := a.incus.StartContainer(spec.LocalName); err != nil {
		return fmt.Errorf("start %s: %w", spec.LocalName, err)
	}
	return nil
}

// EnsureStopped stops the container if it exists and is running. Idempotent.
func (a *cloudContainerActuator) EnsureStopped(_ context.Context, localName string) error {
	info, err := a.incus.GetContainer(localName)
	if err != nil {
		return nil // absent → nothing to stop
	}
	if !isRunning(info.State) {
		return nil
	}
	if err := a.incus.StopContainer(localName, false); err != nil {
		return fmt.Errorf("stop %s: %w", localName, err)
	}
	return nil
}

// EnsureDeleted deletes the container if it exists. Idempotent.
func (a *cloudContainerActuator) EnsureDeleted(_ context.Context, localName string) error {
	if _, err := a.incus.GetContainer(localName); err != nil {
		return nil // already gone
	}
	if err := a.incus.DeleteContainer(localName); err != nil {
		return fmt.Errorf("delete %s: %w", localName, err)
	}
	return nil
}

// create makes the instance (stopped) and stamps the tenant label before start.
func (a *cloudContainerActuator) create(spec cloud.ContainerSpec) error {
	if err := a.incus.CreateContainer(buildContainerConfig(spec)); err != nil {
		return fmt.Errorf("create %s: %w", spec.LocalName, err)
	}
	// Stamp the owning org as the tenant label so the network-policy enforcer
	// identifies this cloud container (it isn't named <tenant>-container).
	if spec.OrgID != "" {
		if err := a.incus.SetConfig(spec.LocalName, incus.TenantLabelKey, spec.OrgID); err != nil {
			return fmt.Errorf("stamp tenant label on %s: %w", spec.LocalName, err)
		}
	}
	return nil
}

// buildContainerConfig maps a cloud ContainerSpec to the Incus create config.
// It wires the resource options the actuation contract carries: memory (RAMMB),
// root-disk size (DiskGB), and GPU passthrough (GPUCount > 0 → pass through all
// GPUs, the cloud-v1 "this is a GPU box" semantics — per-GPU pinning needs host
// GPU inventory the assignment doesn't carry). CPU isn't in the assignment;
// routes/secrets aren't in the actuation contract, so they're not set here.
// Pure (no Incus calls) so the mapping is unit-testable.
func buildContainerConfig(spec cloud.ContainerSpec) incus.ContainerConfig {
	cfg := incus.ContainerConfig{Name: spec.LocalName, Image: spec.Image}
	if spec.RAMMB > 0 {
		cfg.Memory = fmt.Sprintf("%dMB", spec.RAMMB)
	}
	if spec.DiskGB > 0 {
		cfg.Disk = &incus.DiskDevice{Path: "/", Pool: "default", Size: fmt.Sprintf("%dGB", spec.DiskGB)}
	}
	if spec.GPUCount > 0 {
		cfg.GPU = &incus.GPUDevice{} // empty = pass through all GPUs
	}
	if len(spec.SecretEnv) > 0 {
		cfg.Env = make(map[string]string, len(spec.SecretEnv))
		for k, v := range spec.SecretEnv {
			cfg.Env[k] = v
		}
	}
	return cfg
}

// isRunning matches Incus's running state case-insensitively.
func isRunning(state string) bool { return strings.EqualFold(state, "running") }
