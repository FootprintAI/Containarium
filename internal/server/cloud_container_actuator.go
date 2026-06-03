package server

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/cloud"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// cloudContainerActuator implements cloud.ContainerActuator by driving the local
// Incus instance state for cloud-assigned containers (#354). Create stamps
// user.containarium.tenant=<org_id> so the #315 network-policy enforcer can match
// the container to its org's egress policy (cloud names are cld-<uuid>, not
// <tenant>-container, so the label — not the name — carries the tenant).
//
// Scope: create / start / stop / delete to converge to desired_state, plus
// exposing the container's routes at the host edge (routeStore → Caddy) and
// injecting secret_env. Not the richer create options the user-facing
// ContainerService offers — cloud-assigned boxes are minimal v1 workloads.
type cloudContainerActuator struct {
	incus  *incus.Client
	routes *app.RouteStore // nil when the host has no route store (no Postgres/Caddy) → routes skipped
}

// newCloudContainerActuator builds an actuator with its own Incus client and the
// daemon's route store (may be nil — then route exposure is skipped). Returns an
// error (→ caller runs policy-sync-only) if Incus is unavailable, e.g. non-Linux.
func newCloudContainerActuator(routes *app.RouteStore) (*cloudContainerActuator, error) {
	c, err := incus.New()
	if err != nil {
		return nil, fmt.Errorf("incus client: %w", err)
	}
	return &cloudContainerActuator{incus: c, routes: routes}, nil
}

// EnsureRunning creates the container (stamping the tenant label) if absent,
// ensures it is started, and converges its edge routes. Idempotent.
func (a *cloudContainerActuator) EnsureRunning(ctx context.Context, spec cloud.ContainerSpec) error {
	info, err := a.incus.GetContainer(spec.LocalName)
	if err != nil {
		// Treat any lookup failure as "not present" and try to create — a real
		// create error surfaces below; a benign not-found proceeds to create.
		if cerr := a.create(spec); cerr != nil {
			return cerr
		}
	} else if isRunning(info.State) {
		a.applyRoutes(ctx, spec) // already running — still converge routes
		return nil
	}
	if err := a.incus.StartContainer(spec.LocalName); err != nil {
		return fmt.Errorf("start %s: %w", spec.LocalName, err)
	}
	a.applyRoutes(ctx, spec)
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

// EnsureDeleted removes the container's edge routes, then deletes it. Idempotent.
func (a *cloudContainerActuator) EnsureDeleted(ctx context.Context, localName string) error {
	a.removeRoutes(ctx, localName)
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

// applyRoutes converges the container's edge routes to spec.Routes: upsert each
// (pointing at the container's current IP) and delete any cloud route for this
// container the cloud no longer sends. Best-effort — route errors are logged,
// never fail the reconcile (the loop retries). No-op when there's no route store.
//
// The container IP is read fresh: right after first start it may be empty (DHCP
// lag), in which case routes are skipped this pass and applied on the next
// reconcile once the lease lands.
func (a *cloudContainerActuator) applyRoutes(ctx context.Context, spec cloud.ContainerSpec) {
	if a.routes == nil || len(spec.Routes) == 0 {
		// Still converge-away stale routes even if the desired set is now empty.
		if a.routes != nil {
			a.pruneRoutes(ctx, spec.LocalName, nil)
		}
		return
	}
	info, err := a.incus.GetContainer(spec.LocalName)
	if err != nil || info.IPAddress == "" {
		log.Printf("[cloud] %s: IP not ready, deferring route exposure to next reconcile", spec.LocalName)
		return
	}
	desired := make(map[string]bool, len(spec.Routes))
	for _, r := range spec.Routes {
		if r.Domain == "" {
			continue
		}
		desired[r.Domain] = true
		rec := routeRecordFor(spec.LocalName, info.IPAddress, r)
		if err := a.routes.Save(ctx, rec); err != nil {
			log.Printf("[cloud] expose route %s → %s:%d: %v", r.Domain, info.IPAddress, r.TargetPort, err)
		}
	}
	a.pruneRoutes(ctx, spec.LocalName, desired)
}

// pruneRoutes deletes this container's cloud-created routes whose domain isn't in
// `keep`. Only touches routes created_by="cloud" so it won't remove an operator's
// manually-exposed route on the same container.
func (a *cloudContainerActuator) pruneRoutes(ctx context.Context, localName string, keep map[string]bool) {
	existing, err := a.routes.ListByContainer(ctx, localName)
	if err != nil {
		return
	}
	for _, r := range existing {
		if r.CreatedBy == cloudRouteCreatedBy && !keep[r.FullDomain] {
			if err := a.routes.Delete(ctx, r.FullDomain); err != nil {
				log.Printf("[cloud] prune route %s: %v", r.FullDomain, err)
			}
		}
	}
}

// removeRoutes deletes all of this container's cloud-created routes (on delete).
func (a *cloudContainerActuator) removeRoutes(ctx context.Context, localName string) {
	if a.routes != nil {
		a.pruneRoutes(ctx, localName, nil)
	}
}

// cloudRouteCreatedBy tags routes the cloud actuator owns, so convergence/cleanup
// never touches operator-authored routes on the same container.
const cloudRouteCreatedBy = "cloud-actuation"

// routeRecordFor maps a cloud route + the container's IP to a daemon RouteRecord.
// Protocol: the daemon edge speaks http/grpc; grpc passes through, everything
// else (http/https/"") becomes http. Pure → unit-testable.
func routeRecordFor(localName, ip string, r cloud.RouteSpec) *app.RouteRecord {
	proto := "http"
	if strings.EqualFold(r.Protocol, "grpc") {
		proto = "grpc"
	}
	sub := r.Domain
	if i := strings.IndexByte(sub, '.'); i > 0 {
		sub = sub[:i]
	}
	return &app.RouteRecord{
		Subdomain:     sub,
		FullDomain:    r.Domain,
		TargetIP:      ip,
		TargetPort:    int(r.TargetPort),
		Protocol:      proto,
		ContainerName: localName,
		Active:        true,
		CreatedBy:     cloudRouteCreatedBy,
	}
}
