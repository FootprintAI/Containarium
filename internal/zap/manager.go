package zap

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/app"
)

const maxConcurrentWorkers = 2 // ZAP scans are heavy, limit concurrency

// ManagerConfig holds configuration for the ZAP manager
type ManagerConfig struct {
	Interval time.Duration // scan interval (default 30 days)
}

// Manager orchestrates periodic ZAP scans using a PostgreSQL job queue
type Manager struct {
	mu         sync.RWMutex
	store      *Store
	routeStore *app.RouteStore
	scanner    *Scanner
	config     ManagerConfig
	cancel     context.CancelFunc
}

// NewManager creates a new ZAP manager
func NewManager(
	store *Store,
	routeStore *app.RouteStore,
	config ManagerConfig,
) *Manager {
	if config.Interval == 0 {
		config.Interval = 30 * 24 * time.Hour // 30 days
	}

	return &Manager{
		store:      store,
		routeStore: routeStore,
		scanner:    NewScanner(),
		config:     config,
	}
}

// Start begins the worker pool and periodic scan enqueue loop
func (m *Manager) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)

	// Start worker goroutines
	m.startWorkers(ctx, maxConcurrentWorkers)

	// Start periodic scan cycle loop
	go m.scanCycleLoop(ctx)

	log.Printf("ZAP manager started (interval: %v, workers: %d)", m.config.Interval, maxConcurrentWorkers)
}

// Stop stops the worker pool and scan loop
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	log.Printf("ZAP manager stopped")
}

// ZapAvailable returns whether ZAP is installed
func (m *Manager) ZapAvailable() bool {
	return m.scanner.Available()
}

// ZapVersion returns the ZAP version string
func (m *Manager) ZapVersion() string {
	return m.scanner.Version()
}

// Interval returns the configured scan interval
func (m *Manager) Interval() time.Duration {
	return m.config.Interval
}

// scanCycleLoop runs periodic scan enqueue cycles
func (m *Manager) scanCycleLoop(ctx context.Context) {
	// Startup delay — give the system time to settle
	timer := time.NewTimer(10 * time.Minute)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			m.runScanCycle(ctx)
			timer.Reset(m.config.Interval)
		}
	}
}

// runScanCycle creates a scan run and enqueues jobs for all targets
func (m *Manager) runScanCycle(ctx context.Context) {
	scanRunID, targetsCount, err := m.enqueueScan(ctx, "scheduled", "")
	if err != nil {
		log.Printf("ZAP scan cycle: failed to enqueue: %v", err)
		return
	}

	// Cleanup old data (90 day retention)
	if err := m.store.Cleanup(ctx, 90); err != nil {
		log.Printf("ZAP scan cycle: cleanup failed: %v", err)
	}
	if err := m.store.CleanupOldJobs(ctx, 90); err != nil {
		log.Printf("ZAP scan cycle: job cleanup failed: %v", err)
	}

	log.Printf("ZAP scan cycle: %d jobs enqueued for scan run %s", targetsCount, scanRunID)
}

// enqueueScan creates a scan run record, collects targets, and enqueues a job per target.
// containerName scopes the scan to a single container (filters route targets to
// that container's routes) and is recorded on the run. Empty = cluster-wide.
func (m *Manager) enqueueScan(ctx context.Context, trigger, containerName string) (string, int, error) {
	scanRunID, err := m.store.CreateScanRun(ctx, trigger, containerName)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create scan run: %w", err)
	}

	if containerName != "" {
		log.Printf("ZAP scan %s started (trigger: %s, scope: %s)", scanRunID, trigger, containerName)
	} else {
		log.Printf("ZAP scan %s started (trigger: %s)", scanRunID, trigger)
	}

	targets := m.collectTargets(ctx, containerName)
	if len(targets) == 0 {
		log.Printf("ZAP scan %s: no targets found", scanRunID)
		now := time.Now()
		m.store.UpdateScanRun(ctx, &ScanRun{
			ID:          scanRunID,
			Status:      "completed",
			CompletedAt: &now,
		})
		return scanRunID, 0, nil
	}

	// Update scan run with target count
	m.store.UpdateScanRun(ctx, &ScanRun{
		ID:           scanRunID,
		Status:       "running",
		TargetsCount: len(targets),
	})

	// Enqueue one job per target URL
	for _, t := range targets {
		if _, err := m.store.EnqueueScanJob(ctx, scanRunID, t.url, t.containerName); err != nil {
			log.Printf("ZAP scan %s: failed to enqueue target %s: %v", scanRunID, t.url, err)
		}
	}

	log.Printf("ZAP scan %s: %d targets enqueued", scanRunID, len(targets))
	return scanRunID, len(targets), nil
}

// RunScan enqueues a scan (non-blocking). Workers process jobs asynchronously.
// containerName scopes the scan to a specific container; empty = cluster-wide.
func (m *Manager) RunScan(ctx context.Context, trigger, containerName string) (string, error) {
	scanRunID, _, err := m.enqueueScan(ctx, trigger, containerName)
	return scanRunID, err
}

type zapTarget struct {
	url           string
	containerName string
}

// collectTargets gathers all exposed URLs from the route store.
// If containerName is non-empty, only routes belonging to that container
// are returned — the scoping path for operator-triggered scans.
func (m *Manager) collectTargets(ctx context.Context, containerName string) []zapTarget {
	if m.routeStore == nil {
		return nil
	}

	routes, err := m.routeStore.List(ctx, true) // active only
	if err != nil {
		log.Printf("ZAP target collector: failed to list routes: %v", err)
		return nil
	}

	seen := make(map[string]bool)
	var targets []zapTarget

	for _, r := range routes {
		if containerName != "" && r.ContainerName != containerName {
			continue
		}
		url := fmt.Sprintf("https://%s", r.FullDomain)
		if seen[url] {
			continue
		}
		seen[url] = true
		targets = append(targets, zapTarget{
			url:           url,
			containerName: r.ContainerName,
		})
	}

	return targets
}

// startWorkers spawns count goroutines that poll the job queue
func (m *Manager) startWorkers(ctx context.Context, count int) {
	for i := 0; i < count; i++ {
		go m.worker(ctx, i)
	}
}

// worker is a long-running goroutine that claims and processes ZAP scan jobs
func (m *Manager) worker(ctx context.Context, id int) {
	log.Printf("ZAP worker %d started", id)
	for {
		select {
		case <-ctx.Done():
			log.Printf("ZAP worker %d stopped", id)
			return
		default:
		}

		job, err := m.store.ClaimNextJob(ctx)
		if err != nil {
			log.Printf("ZAP worker %d: claim error: %v", id, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		if job == nil {
			// No jobs available, wait before polling again
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			continue
		}

		log.Printf("ZAP worker %d: processing job %d (scan_run=%s, target=%s)",
			id, job.ID, job.ScanRunID, job.TargetURL)

		if err := m.scanTarget(ctx, job); err != nil {
			log.Printf("ZAP worker %d: job %d failed: %v", id, job.ID, err)
			if failErr := m.store.FailJob(ctx, job.ID, err.Error()); failErr != nil {
				log.Printf("ZAP worker %d: failed to mark job %d as failed: %v", id, job.ID, failErr)
			}
		} else {
			if err := m.store.CompleteJob(ctx, job.ID); err != nil {
				log.Printf("ZAP worker %d: failed to mark job %d as completed: %v", id, job.ID, err)
			}
			log.Printf("ZAP worker %d: job %d completed", id, job.ID)
		}

		// Check if the scan run is fully done
		m.tryFinalizeScanRun(ctx, job.ScanRunID)
	}
}

// scanTarget runs ZAP against a single target URL and saves alerts
func (m *Manager) scanTarget(ctx context.Context, job *ScanJob) error {
	// Ensure ZAP daemon is running
	if err := m.scanner.EnsureDaemonRunning(ctx); err != nil {
		return fmt.Errorf("failed to start ZAP daemon: %w", err)
	}

	alerts, err := m.scanner.ScanURL(ctx, job.TargetURL)
	if err != nil {
		return fmt.Errorf("ZAP scan failed for %s: %w", job.TargetURL, err)
	}

	// Deduplicate by fingerprint
	seen := make(map[string]bool)
	var deduped []Alert
	for _, a := range alerts {
		if !seen[a.Fingerprint] {
			seen[a.Fingerprint] = true
			deduped = append(deduped, a)
		}
	}

	if len(deduped) > 0 {
		if err := m.store.SaveAlerts(ctx, job.ScanRunID, deduped); err != nil {
			return fmt.Errorf("failed to save alerts: %w", err)
		}
	}

	return nil
}

// tryFinalizeScanRun checks if all jobs for a scan run are done, and if so, finalizes it
func (m *Manager) tryFinalizeScanRun(ctx context.Context, scanRunID string) {
	pending, err := m.store.CountPendingJobs(ctx, scanRunID)
	if err != nil {
		log.Printf("ZAP finalize: failed to count pending jobs for %s: %v", scanRunID, err)
		return
	}
	if pending > 0 {
		return
	}

	m.finalizeScanRun(ctx, scanRunID)
}

// finalizeScanRun counts alerts, updates the scan run status, and marks resolved alerts
func (m *Manager) finalizeScanRun(ctx context.Context, scanRunID string) {
	run, err := m.store.GetScanRun(ctx, scanRunID)
	if err != nil {
		log.Printf("ZAP finalize: failed to get scan run %s: %v", scanRunID, err)
		return
	}

	// Already finalized
	if run.Status == "completed" || run.Status == "failed" {
		return
	}

	// Count alerts by risk
	byRisk, err := m.store.CountAlertsByRisk(ctx, scanRunID)
	if err != nil {
		log.Printf("ZAP finalize: failed to count alerts for %s: %v", scanRunID, err)
	}

	// Collect fingerprints seen in this scan run
	seenFingerprints, err := m.store.GetFingerprintsForScanRun(ctx, scanRunID)
	if err != nil {
		log.Printf("ZAP finalize: failed to get fingerprints for %s: %v", scanRunID, err)
	}

	// Mark resolved alerts
	if err := m.store.MarkResolved(ctx, scanRunID, seenFingerprints); err != nil {
		log.Printf("ZAP finalize: failed to mark resolved for %s: %v", scanRunID, err)
	}

	// Update scan run to completed
	now := time.Now()
	m.store.UpdateScanRun(ctx, &ScanRun{
		ID:           scanRunID,
		Status:       "completed",
		TargetsCount: run.TargetsCount,
		HighCount:    byRisk["high"],
		MediumCount:  byRisk["medium"],
		LowCount:     byRisk["low"],
		InfoCount:    byRisk["informational"],
		CompletedAt:  &now,
	})

	duration := now.Sub(run.StartedAt)
	totalAlerts := byRisk["high"] + byRisk["medium"] + byRisk["low"] + byRisk["informational"]
	log.Printf("ZAP scan %s completed: %d targets, %d alerts (high=%d, medium=%d, low=%d, info=%d) in %s",
		scanRunID, run.TargetsCount, totalAlerts,
		byRisk["high"], byRisk["medium"], byRisk["low"], byRisk["informational"],
		duration.Truncate(time.Second))

	// Generate and store reports while ZAP daemon is still warm
	m.generateAndStoreReports(ctx, scanRunID)
}

// generateAndStoreReports generates HTML and JSON reports from ZAP and stores them in the DB
func (m *Manager) generateAndStoreReports(ctx context.Context, scanRunID string) {
	// Ensure daemon is running and apiBase is set
	if err := m.scanner.EnsureDaemonRunning(ctx); err != nil {
		log.Printf("ZAP report: daemon not available for %s: %v", scanRunID, err)
		return
	}

	htmlReport, err := m.scanner.GenerateHTMLReport()
	if err != nil {
		log.Printf("ZAP report: failed to generate HTML for %s: %v", scanRunID, err)
		htmlReport = ""
	}

	jsonReport, err := m.scanner.GenerateJSONReport()
	if err != nil {
		log.Printf("ZAP report: failed to generate JSON for %s: %v", scanRunID, err)
		jsonReport = ""
	}

	if htmlReport != "" || jsonReport != "" {
		if err := m.store.SaveReport(ctx, scanRunID, htmlReport, jsonReport); err != nil {
			log.Printf("ZAP report: failed to save reports for %s: %v", scanRunID, err)
		} else {
			log.Printf("ZAP report: saved HTML (%d bytes) and JSON (%d bytes) for %s",
				len(htmlReport), len(jsonReport), scanRunID)
		}
	}
}
