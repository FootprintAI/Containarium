package wake

import (
	"context"
	"fmt"
	"log"

	"github.com/footprintai/containarium/internal/app"
)

// ProxyManager is the subset of *app.ProxyManager that Router needs.
// Defined as an interface so unit tests can fake the Caddy mutation
// without standing up the real admin API.
type ProxyManager interface {
	UpdateRoute(subdomain, containerIP string, port int) error
	UpdateGRPCRoute(subdomain, containerIP string, port int) error
}

// Router applies the route swap between "direct" (Caddy → container)
// and "wake" (Caddy → daemon wake handler) modes. The tracker is the
// authoritative state; we update it before we touch Caddy so a racing
// RouteSyncJob tick either sees the new state and pushes the same
// upstream, or sees the old state and we overwrite its push moments
// later.
type Router struct {
	proxy    ProxyManager
	tracker  *WakeStateTracker
	wakeHost string // daemon's IP visible to Caddy (e.g. "10.0.3.1")
	wakePort int    // daemon's HTTP port (e.g. 8080)
}

// NewRouter constructs a Router. wakeHost+wakePort must be an address
// that the Caddy LXC can reach to deliver wake-mode requests to this
// daemon's HTTP gateway.
func NewRouter(p ProxyManager, t *WakeStateTracker, wakeHost string, wakePort int) *Router {
	return &Router{
		proxy:    p,
		tracker:  t,
		wakeHost: wakeHost,
		wakePort: wakePort,
	}
}

// WakeHost reports the daemon address Caddy is pointed at while a
// container is in wake mode. Exposed so RouteSyncJob (the other reader)
// can push the same value on its periodic sync.
func (r *Router) WakeHost() string { return r.wakeHost }

// WakePort reports the daemon port Caddy is pointed at while a
// container is in wake mode.
func (r *Router) WakePort() int { return r.wakePort }

// SwapToWake marks a container as in wake mode and points each of its
// routes at the daemon's wake handler. Idempotent — repeated calls
// when already in wake mode just overwrite the tracker entry and
// re-push the same Caddy config. A nil or empty routes slice is
// treated as a no-op (the container has no public route, so wake-on-
// HTTP wouldn't fire anyway).
//
// Caller is responsible for fetching the routes via routeStore.
// ListByContainer; we don't reach into Postgres from here so the
// Router stays narrow and unit-testable without a DB.
func (r *Router) SwapToWake(ctx context.Context, containerName string, routes []*app.RouteRecord) error {
	if r == nil || len(routes) == 0 {
		return nil
	}
	// Mark tracker FIRST so RouteSyncJob — if it ticks between the
	// tracker write and the Caddy push — sees the new state and
	// pushes the wake upstream itself.
	for _, route := range routes {
		r.tracker.MarkWakeMode(containerName, route.FullDomain, r.wakeHost, r.wakePort)
	}

	var firstErr error
	for _, route := range routes {
		var err error
		if route.Protocol == string(app.RouteProtocolGRPC) {
			err = r.proxy.UpdateGRPCRoute(route.FullDomain, r.wakeHost, r.wakePort)
		} else {
			err = r.proxy.UpdateRoute(route.FullDomain, r.wakeHost, r.wakePort)
		}
		if err != nil {
			log.Printf("[wake] swap-to-wake %s: %v", route.FullDomain, err)
			if firstErr == nil {
				firstErr = fmt.Errorf("swap-to-wake %s: %w", route.FullDomain, err)
			}
			// Continue with other routes — best-effort, the next
			// RouteSyncJob tick will retry whichever ones failed.
		}
	}
	return firstErr
}

// SwapToDirect clears the tracker entry and points each of the
// container's routes back at its TargetIP/TargetPort. Idempotent.
//
// Tracker is cleared FIRST so RouteSyncJob doesn't race us and re-push
// the wake upstream over the direct one we're about to write.
func (r *Router) SwapToDirect(ctx context.Context, containerName string, routes []*app.RouteRecord) error {
	if r == nil || len(routes) == 0 {
		return nil
	}
	r.tracker.ClearWakeMode(containerName)

	var firstErr error
	for _, route := range routes {
		var err error
		if route.Protocol == string(app.RouteProtocolGRPC) {
			err = r.proxy.UpdateGRPCRoute(route.FullDomain, route.TargetIP, route.TargetPort)
		} else {
			err = r.proxy.UpdateRoute(route.FullDomain, route.TargetIP, route.TargetPort)
		}
		if err != nil {
			log.Printf("[wake] swap-to-direct %s: %v", route.FullDomain, err)
			if firstErr == nil {
				firstErr = fmt.Errorf("swap-to-direct %s: %w", route.FullDomain, err)
			}
		}
	}
	return firstErr
}
