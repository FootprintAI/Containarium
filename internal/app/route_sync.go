package app

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// WakeTracker is the subset of *wake.WakeStateTracker that RouteSyncJob
// reads when deciding what upstream to push to Caddy. Declared as an
// interface so the wake/app import direction stays one-way (wake →
// app) — app/route_sync.go would import internal/wake otherwise and
// create a cycle. Satisfied by *wake.WakeStateTracker.
type WakeTracker interface {
	IsInWakeMode(containerName string) (host string, port int, ok bool)
}

// RouteSyncJob synchronizes routes from PostgreSQL (source of truth) to Caddy (runtime cache)
type RouteSyncJob struct {
	routeStore     *RouteStore
	proxyManager   *ProxyManager
	l4ProxyManager *L4ProxyManager // optional, for tls_passthrough routes
	wakeTracker    WakeTracker     // optional; when set, sleeping containers route to daemon's wake handler
	interval       time.Duration

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// NewRouteSyncJob creates a new route sync job
func NewRouteSyncJob(routeStore *RouteStore, proxyManager *ProxyManager, interval time.Duration) *RouteSyncJob {
	if interval <= 0 {
		interval = 5 * time.Second // default 5 seconds
	}

	return &RouteSyncJob{
		routeStore:   routeStore,
		proxyManager: proxyManager,
		interval:     interval,
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
}

// SetL4ProxyManager sets the L4 proxy manager for TLS passthrough route sync.
func (j *RouteSyncJob) SetL4ProxyManager(l4 *L4ProxyManager) {
	j.l4ProxyManager = l4
}

// SetWakeTracker wires the wake-state tracker so the sync loop knows
// which containers are currently routed through the daemon's wake
// handler. Nil is allowed and disables the wake-coordination branch
// (the loop behaves exactly as it did before Phase 3).
func (j *RouteSyncJob) SetWakeTracker(t WakeTracker) {
	j.wakeTracker = t
}

// ProxyManager returns the underlying *ProxyManager so the wake
// wiring in DualServer can build a Router without having to pass
// proxyManager around as a separate construction parameter (it's
// already captured here).
func (j *RouteSyncJob) ProxyManager() *ProxyManager { return j.proxyManager }

// RouteStore returns the underlying *RouteStore for the same wiring
// reason as ProxyManager — DualServer composes a wake.WakeProxy from
// the same primitives the sync job already holds.
func (j *RouteSyncJob) RouteStore() *RouteStore { return j.routeStore }

// Start begins the background sync job
// It runs an immediate sync, then syncs at the configured interval
func (j *RouteSyncJob) Start(ctx context.Context) {
	j.mu.Lock()
	if j.running {
		j.mu.Unlock()
		return
	}
	j.running = true
	j.stopCh = make(chan struct{})
	j.doneCh = make(chan struct{})
	j.mu.Unlock()

	go j.run(ctx)
}

// Stop stops the background sync job
func (j *RouteSyncJob) Stop() {
	j.mu.Lock()
	if !j.running {
		j.mu.Unlock()
		return
	}
	j.mu.Unlock()

	close(j.stopCh)
	<-j.doneCh

	j.mu.Lock()
	j.running = false
	j.mu.Unlock()
}

// SyncNow triggers an immediate sync
func (j *RouteSyncJob) SyncNow(ctx context.Context) error {
	return j.sync(ctx)
}

// run is the main loop for the background sync job
func (j *RouteSyncJob) run(ctx context.Context) {
	defer close(j.doneCh)

	// Run initial sync immediately
	if err := j.sync(ctx); err != nil {
		log.Printf("[RouteSyncJob] Initial sync failed: %v", err)
	}

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	for {
		select {
		case <-j.stopCh:
			log.Println("[RouteSyncJob] Stopping route sync job")
			return
		case <-ctx.Done():
			log.Println("[RouteSyncJob] Context cancelled, stopping route sync job")
			return
		case <-ticker.C:
			if err := j.sync(ctx); err != nil {
				log.Printf("[RouteSyncJob] Sync failed: %v", err)
			}
		}
	}
}

// sync performs the actual synchronization from PostgreSQL to Caddy
func (j *RouteSyncJob) sync(ctx context.Context) error {
	// Self-heal the base Caddy config first. The bundled Caddy boots from a stub
	// Caddyfile and is configured entirely over the admin API; any caddy
	// reload/restart/crash reverts the running config to that stub, wiping the
	// http app. Without this, the route diff below would loop on
	// "400 invalid traversal path" and :443 would stay dark (issue #400).
	// Rebuilding the base lets the diff repopulate HTTP routes (+ TLS subjects)
	// and re-activate layer4 on this same tick. Cheap (one GET) when intact.
	if rebuilt, err := j.proxyManager.EnsureBaseConfig(); err != nil {
		log.Printf("[RouteSyncJob] Base Caddy config reconcile failed: %v", err)
	} else if rebuilt {
		log.Printf("[RouteSyncJob] Caddy reverted to stub config — rebuilt base edge config; routes/TLS/L4 will be repopulated this sync (#400)")
	}

	// Get routes from PostgreSQL (source of truth)
	dbRoutes, err := j.routeStore.List(ctx, true) // activeOnly = true
	if err != nil {
		return err
	}

	// Split routes by protocol type
	var httpGRPCRoutes []*RouteRecord
	var tlsPassthroughRoutes []*RouteRecord
	for _, r := range dbRoutes {
		if r.Protocol == string(RouteProtocolTLSPassthrough) {
			tlsPassthroughRoutes = append(tlsPassthroughRoutes, r)
		} else {
			httpGRPCRoutes = append(httpGRPCRoutes, r)
		}
	}

	// Sync HTTP/gRPC routes to ProxyManager (existing behavior)
	if err := j.syncHTTPRoutes(httpGRPCRoutes); err != nil {
		log.Printf("[RouteSyncJob] HTTP route sync error: %v", err)
	}

	// Sync TLS passthrough routes to L4ProxyManager
	if j.l4ProxyManager != nil {
		if err := j.syncL4Routes(tlsPassthroughRoutes); err != nil {
			log.Printf("[RouteSyncJob] L4 route sync error: %v", err)
		}
	}

	return nil
}

// syncHTTPRoutes synchronizes HTTP/gRPC routes to the Caddy HTTP server
func (j *RouteSyncJob) syncHTTPRoutes(dbRoutes []*RouteRecord) error {
	// Get current routes from Caddy
	caddyRoutes, err := j.proxyManager.ListRoutes()
	if err != nil {
		return err
	}

	// Build maps for efficient diffing
	dbRouteMap := make(map[string]*RouteRecord)
	for _, r := range dbRoutes {
		dbRouteMap[r.FullDomain] = r
	}

	caddyRouteMap := make(map[string]Route)
	for _, r := range caddyRoutes {
		caddyRouteMap[r.FullDomain] = r
	}

	var added, removed, updated int

	// Find routes to add or update (in DB but not in Caddy, or different)
	for domain, dbRoute := range dbRouteMap {
		caddyRoute, exists := caddyRouteMap[domain]

		if !exists {
			if err := j.addRouteToCaddy(dbRoute); err != nil {
				log.Printf("[RouteSyncJob] Failed to add route %s: %v", domain, err)
				continue
			}
			added++
		} else {
			if j.needsUpdate(dbRoute, caddyRoute) {
				if err := j.updateRouteInCaddy(dbRoute); err != nil {
					log.Printf("[RouteSyncJob] Failed to update route %s: %v", domain, err)
					continue
				}
				updated++
			}
		}
	}

	// Find routes to remove (in Caddy but not in DB)
	for domain := range caddyRouteMap {
		if _, exists := dbRouteMap[domain]; !exists {
			if err := j.proxyManager.RemoveRoute(domain); err != nil {
				log.Printf("[RouteSyncJob] Failed to remove route %s: %v", domain, err)
				continue
			}
			removed++
		}
	}

	if added > 0 || removed > 0 || updated > 0 {
		log.Printf("[RouteSyncJob] HTTP routes synced: +%d added, -%d removed, ~%d updated", added, removed, updated)
	}

	return nil
}

// syncL4Routes synchronizes TLS passthrough routes to the Caddy L4 layer.
// L4 is lazily activated when passthrough routes exist and deactivated when empty.
func (j *RouteSyncJob) syncL4Routes(dbRoutes []*RouteRecord) error {
	// L4 ownership of :443 is a one-way latch. Activating L4 moves the HTTP
	// server off :443 onto the fallback port and hands :443 to the layer4
	// app; deactivating reverses it. BOTH rewrite the :443 listen address,
	// which restarts the :443 listener and drops every in-flight TLS
	// connection on it — including the response of a concurrent container
	// create (issue #416: edge create returns "tls: internal error" while
	// the box itself is provisioned). The 5s reconcile previously toggled
	// activate/deactivate on every 0<->1 transition in the passthrough-route
	// set, so any container's route churn bounced :443 for everyone.
	//
	// Fix: once L4 is active, keep it active. When the route set empties we
	// drain the SNI routes down to the catch-all (handled by the diff below)
	// instead of deactivating. A layer4 server holding only the catch-all is
	// behaviourally identical to the HTTP-on-:443 baseline — non-matching SNI
	// already falls through to the HTTP fallback — but it never rewrites the
	// listen address, so the listener is never restarted under live traffic.
	if !j.l4ProxyManager.IsL4Active() {
		if len(dbRoutes) == 0 {
			return nil // never activated and nothing to route — stay lazy
		}
		if err := j.l4ProxyManager.ActivateL4(); err != nil {
			return fmt.Errorf("failed to activate L4: %w", err)
		}
		log.Printf("[RouteSyncJob] L4 activated for %d passthrough route(s)", len(dbRoutes))
	}

	// Get current L4 routes from Caddy
	caddyL4Routes, err := j.l4ProxyManager.ListL4Routes()
	if err != nil {
		return err
	}

	// Build maps for efficient diffing
	dbRouteMap := make(map[string]*RouteRecord)
	for _, r := range dbRoutes {
		dbRouteMap[r.FullDomain] = r
	}

	caddyL4Map := make(map[string]L4Route)
	for _, r := range caddyL4Routes {
		caddyL4Map[r.SNI] = r
	}

	var added, removed, updated int

	// Find routes to add or update
	for domain, dbRoute := range dbRouteMap {
		existing, exists := caddyL4Map[domain]

		if !exists {
			if err := j.l4ProxyManager.AddL4Route(dbRoute.FullDomain, dbRoute.TargetIP, dbRoute.TargetPort); err != nil {
				log.Printf("[RouteSyncJob] Failed to add L4 route %s: %v", domain, err)
				continue
			}
			added++
		} else if existing.UpstreamIP != dbRoute.TargetIP || existing.UpstreamPort != dbRoute.TargetPort {
			if err := j.l4ProxyManager.AddL4Route(dbRoute.FullDomain, dbRoute.TargetIP, dbRoute.TargetPort); err != nil {
				log.Printf("[RouteSyncJob] Failed to update L4 route %s: %v", domain, err)
				continue
			}
			updated++
		}
	}

	// Find routes to remove (in Caddy but not in DB)
	for sni := range caddyL4Map {
		if _, exists := dbRouteMap[sni]; !exists {
			if err := j.l4ProxyManager.RemoveL4Route(sni); err != nil {
				log.Printf("[RouteSyncJob] Failed to remove L4 route %s: %v", sni, err)
				continue
			}
			removed++
		}
	}

	if added > 0 || removed > 0 || updated > 0 {
		log.Printf("[RouteSyncJob] L4 routes synced: +%d added, -%d removed, ~%d updated", added, removed, updated)
	}

	return nil
}

// effectiveUpstream returns the (host, port) the sync job should push
// to Caddy for the given route. If the container is currently in wake
// mode, that's the daemon's wake handler address; otherwise it's the
// route's direct target. Centralised here so addRouteToCaddy,
// updateRouteInCaddy, and needsUpdate all agree.
func (j *RouteSyncJob) effectiveUpstream(route *RouteRecord) (string, int) {
	if j.wakeTracker != nil && route.ContainerName != "" {
		if host, port, ok := j.wakeTracker.IsInWakeMode(route.ContainerName); ok {
			return host, port
		}
	}
	return route.TargetIP, route.TargetPort
}

// needsUpdate checks if a route needs to be updated in Caddy
func (j *RouteSyncJob) needsUpdate(dbRoute *RouteRecord, caddyRoute Route) bool {
	wantIP, wantPort := j.effectiveUpstream(dbRoute)
	if wantIP != caddyRoute.UpstreamIP {
		return true
	}
	if wantPort != caddyRoute.UpstreamPort {
		return true
	}
	// Check if protocol changed
	if dbRoute.Protocol == "grpc" && caddyRoute.Protocol != RouteProtocolGRPC {
		return true
	}
	if dbRoute.Protocol == "http" && caddyRoute.Protocol != RouteProtocolHTTP {
		return true
	}
	return false
}

// addRouteToCaddy adds a route to Caddy based on the database record
func (j *RouteSyncJob) addRouteToCaddy(route *RouteRecord) error {
	ip, port := j.effectiveUpstream(route)
	if route.Protocol == "grpc" {
		return j.proxyManager.AddGRPCRoute(route.FullDomain, ip, port)
	}
	return j.proxyManager.AddRoute(route.FullDomain, ip, port)
}

// updateRouteInCaddy updates a route in Caddy based on the database record
func (j *RouteSyncJob) updateRouteInCaddy(route *RouteRecord) error {
	ip, port := j.effectiveUpstream(route)
	if route.Protocol == "grpc" {
		return j.proxyManager.UpdateGRPCRoute(route.FullDomain, ip, port)
	}
	return j.proxyManager.UpdateRoute(route.FullDomain, ip, port)
}
