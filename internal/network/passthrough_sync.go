package network

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// PassthroughSyncJob synchronizes passthrough routes from PostgreSQL (source of truth) to iptables (runtime)
type PassthroughSyncJob struct {
	store   *PassthroughStore
	manager *PassthroughManager
	interval time.Duration

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// NewPassthroughSyncJob creates a new passthrough sync job
func NewPassthroughSyncJob(store *PassthroughStore, manager *PassthroughManager, interval time.Duration) *PassthroughSyncJob {
	if interval <= 0 {
		interval = 5 * time.Second
	}

	return &PassthroughSyncJob{
		store:    store,
		manager:  manager,
		interval: interval,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Start begins the background sync job
func (j *PassthroughSyncJob) Start(ctx context.Context) {
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
func (j *PassthroughSyncJob) Stop() {
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
func (j *PassthroughSyncJob) SyncNow(ctx context.Context) error {
	return j.sync(ctx)
}

// run is the main loop for the background sync job
func (j *PassthroughSyncJob) run(ctx context.Context) {
	defer close(j.doneCh)

	// Run initial sync immediately
	if err := j.sync(ctx); err != nil {
		log.Printf("[PassthroughSyncJob] Initial sync failed: %v", err)
	}

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	for {
		select {
		case <-j.stopCh:
			log.Println("[PassthroughSyncJob] Stopping passthrough sync job")
			return
		case <-ctx.Done():
			log.Println("[PassthroughSyncJob] Context cancelled, stopping passthrough sync job")
			return
		case <-ticker.C:
			if err := j.sync(ctx); err != nil {
				log.Printf("[PassthroughSyncJob] Sync failed: %v", err)
			}
		}
	}
}

// sync performs the actual synchronization from PostgreSQL to iptables
func (j *PassthroughSyncJob) sync(ctx context.Context) error {
	// Get routes from PostgreSQL (source of truth)
	dbRoutes, err := j.store.List(ctx, true) // activeOnly = true
	if err != nil {
		return fmt.Errorf("failed to list passthrough routes from DB: %w", err)
	}

	// Get current routes from iptables
	iptablesRoutes, err := j.manager.ListRoutes()
	if err != nil {
		return fmt.Errorf("failed to list passthrough routes from iptables: %w", err)
	}

	// Build maps for efficient diffing
	// Key: "externalPort/protocol"
	dbRouteMap := make(map[string]*PassthroughRecord)
	for _, r := range dbRoutes {
		key := fmt.Sprintf("%d/%s", r.ExternalPort, r.Protocol)
		dbRouteMap[key] = r
	}

	iptablesRouteMap := make(map[string]PassthroughRoute)
	for _, r := range iptablesRoutes {
		key := fmt.Sprintf("%d/%s", r.ExternalPort, r.Protocol)
		iptablesRouteMap[key] = r
	}

	var added, removed, updated int

	// Find routes to add or update (in DB but not in iptables, or different)
	for key, dbRoute := range dbRouteMap {
		iptablesRoute, exists := iptablesRouteMap[key]

		if !exists {
			// Route in DB but not in iptables - add it
			if err := j.manager.AddRoute(dbRoute.ExternalPort, dbRoute.TargetIP, dbRoute.TargetPort, dbRoute.Protocol); err != nil {
				log.Printf("[PassthroughSyncJob] Failed to add route %s: %v", key, err)
				continue
			}
			added++
		} else {
			// Route exists in both - check if it needs update
			if j.needsUpdate(dbRoute, iptablesRoute) {
				// Remove old rule and add new one
				if err := j.manager.RemoveRoute(dbRoute.ExternalPort, dbRoute.Protocol); err != nil {
					log.Printf("[PassthroughSyncJob] Failed to remove old route %s for update: %v", key, err)
					continue
				}
				if err := j.manager.AddRoute(dbRoute.ExternalPort, dbRoute.TargetIP, dbRoute.TargetPort, dbRoute.Protocol); err != nil {
					log.Printf("[PassthroughSyncJob] Failed to add updated route %s: %v", key, err)
					continue
				}
				updated++
			}
		}
	}

	// Find routes to remove (in iptables but not in DB)
	for key, iptablesRoute := range iptablesRouteMap {
		if _, exists := dbRouteMap[key]; !exists {
			if err := j.manager.RemoveRoute(iptablesRoute.ExternalPort, iptablesRoute.Protocol); err != nil {
				log.Printf("[PassthroughSyncJob] Failed to remove route %s: %v", key, err)
				continue
			}
			removed++
		}
	}

	// Only log if there were changes
	if added > 0 || removed > 0 || updated > 0 {
		log.Printf("[PassthroughSyncJob] Synced passthrough routes: +%d added, -%d removed, ~%d updated", added, removed, updated)
	}

	return nil
}

// needsUpdate checks if a passthrough route needs to be updated in iptables
func (j *PassthroughSyncJob) needsUpdate(dbRoute *PassthroughRecord, iptablesRoute PassthroughRoute) bool {
	if dbRoute.TargetIP != iptablesRoute.TargetIP {
		return true
	}
	if dbRoute.TargetPort != iptablesRoute.TargetPort {
		return true
	}
	return false
}
