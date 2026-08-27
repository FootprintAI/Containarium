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

	// l4Activated latches once the layer4 app has been brought up, and is
	// what lets the sync tell "never needed L4" apart from "had L4 and lost
	// it" (#1067).
	//
	// Caddy is configured entirely over the admin API, so a crash, restart
	// or binary swap reverts it to the stub Caddyfile and the layer4 app
	// disappears. The HTTP side self-heals via EnsureBaseConfig; L4 did not,
	// because its activation is guarded by "are there passthrough routes?"
	// — so a wipe that happened while the route set was empty left :443 as
	// plain HTTP indefinitely, with no PROXY/SNI passthrough and nothing to
	// notice.
	//
	// Guarded by mu: SyncNow can run concurrently with the ticker.
	l4Activated bool
}

// l4WasActivated reports whether this daemon has ever had layer4 up.
func (j *RouteSyncJob) l4WasActivated() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.l4Activated
}

// markL4Activated records that layer4 is up.
func (j *RouteSyncJob) markL4Activated() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.l4Activated = true
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
		// Per-route TLS subjects come back via the diff below, but the
		// `*.<base-domain>` wildcard isn't tied to a route — re-provision it
		// here so a Caddy reload doesn't silently drop wildcard coverage (#389).
		if j.proxyManager.HasDNSChallenge() {
			if err := j.proxyManager.ProvisionWildcardTLS(); err != nil {
				log.Printf("[RouteSyncJob] re-provision wildcard TLS after rebuild failed: %v", err)
			}
		}
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

	// Reconcile TLS automation subjects for every route that should have a
	// certificate. Deliberately AFTER syncHTTPRoutes, so routes added on this
	// tick are included, and deliberately not gated on that call succeeding —
	// the subjects of already-synced routes still need checking when one route
	// fails.
	//
	// syncHTTPRoutes only provisions TLS for routes it ADDS to Caddy; a route
	// already present takes the needsUpdate path, which never looks at TLS
	// subjects. Without this call a route whose subject went missing is never
	// repaired (#1584).
	if err := j.syncTLSSubjects(dbRoutes); err != nil {
		log.Printf("[RouteSyncJob] TLS subject reconcile error: %v", err)
	}

	return nil
}

// syncTLSSubjects ensures every active route that Caddy terminates TLS for has
// a subject in Caddy's TLS automation policies (#1584).
//
// Excludes TLS-passthrough routes: those terminate TLS at the backend, so
// Caddy must not chase a certificate for them. Excludes inactive routes for
// the same reason RemoveTLSSubject exists — no point spending ACME budget on a
// hostname nothing serves.
func (j *RouteSyncJob) syncTLSSubjects(dbRoutes []*RouteRecord) error {
	if j.proxyManager == nil {
		return nil
	}

	domains := make([]string, 0, len(dbRoutes))
	for _, r := range dbRoutes {
		if r == nil || !r.Active || r.FullDomain == "" {
			continue
		}
		if r.Protocol == string(RouteProtocolTLSPassthrough) {
			continue
		}
		domains = append(domains, r.FullDomain)
	}

	return j.proxyManager.EnsureTLSSubjects(domains)
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
	//
	// The same latch also covers Caddy losing its config entirely (#1067).
	// Once L4 has been up, a later tick finding the layer4 app gone means
	// Caddy reverted to its stub — not that we should stay lazy — so it is
	// rebuilt regardless of how many passthrough routes currently exist.
	// The route set being empty at that moment is exactly the case that
	// used to leave :443 as plain HTTP forever.
	if !j.l4ProxyManager.IsL4Active() {
		healing := j.l4WasActivated()
		if len(dbRoutes) == 0 && !healing {
			return nil // never activated and nothing to route — stay lazy
		}
		if err := j.l4ProxyManager.ActivateL4(); err != nil {
			return fmt.Errorf("failed to activate L4: %w", err)
		}
		if healing {
			log.Printf("[RouteSyncJob] layer4 app was missing though L4 had been active — Caddy "+
				"reverted to its stub config; rebuilt L4 and reclaimed :443 for %d passthrough route(s) (#1067)",
				len(dbRoutes))
		} else {
			log.Printf("[RouteSyncJob] L4 activated for %d passthrough route(s)", len(dbRoutes))
		}
	}
	// L4 is up now, however it got there.
	j.markL4Activated()

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
