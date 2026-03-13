package app

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// RouteSyncJob synchronizes routes from PostgreSQL (source of truth) to Caddy (runtime cache)
type RouteSyncJob struct {
	routeStore     *RouteStore
	proxyManager   *ProxyManager
	l4ProxyManager *L4ProxyManager // optional, for tls_passthrough routes
	interval       time.Duration

	mu       sync.Mutex
	running  bool
	stopCh   chan struct{}
	doneCh   chan struct{}
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
	if len(dbRoutes) == 0 {
		// No passthrough routes — deactivate L4 if active
		if j.l4ProxyManager.IsL4Active() {
			if err := j.l4ProxyManager.DeactivateL4(); err != nil {
				log.Printf("[RouteSyncJob] Failed to deactivate L4: %v", err)
			} else {
				log.Printf("[RouteSyncJob] L4 deactivated (no passthrough routes)")
			}
		}
		return nil
	}

	// Passthrough routes exist — ensure L4 is active
	if !j.l4ProxyManager.IsL4Active() {
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

// needsUpdate checks if a route needs to be updated in Caddy
func (j *RouteSyncJob) needsUpdate(dbRoute *RouteRecord, caddyRoute Route) bool {
	// Check if target IP or port changed
	if dbRoute.TargetIP != caddyRoute.UpstreamIP {
		return true
	}
	if dbRoute.TargetPort != caddyRoute.UpstreamPort {
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
	if route.Protocol == "grpc" {
		return j.proxyManager.AddGRPCRoute(route.FullDomain, route.TargetIP, route.TargetPort)
	}
	return j.proxyManager.AddRoute(route.FullDomain, route.TargetIP, route.TargetPort)
}

// updateRouteInCaddy updates a route in Caddy based on the database record
func (j *RouteSyncJob) updateRouteInCaddy(route *RouteRecord) error {
	if route.Protocol == "grpc" {
		return j.proxyManager.UpdateGRPCRoute(route.FullDomain, route.TargetIP, route.TargetPort)
	}
	return j.proxyManager.UpdateRoute(route.FullDomain, route.TargetIP, route.TargetPort)
}
