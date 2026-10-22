package security

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// maxConcurrentScans limits parallel scan workers.
const maxConcurrentScans = 1

// SecurityContainerName is the name of the core security container (ZAP lives
// there; the ClamAV scanner no longer does, #2631). Defined here to avoid an
// import cycle with internal/server.
const SecurityContainerName = "containarium-core-security"

// Scanner owns the ClamAV scan job queue and report store.
//
// Scans are never started by the system: no startup cycle, no periodic loop,
// no scan of a newly created box, no scan-all (#2631). A scan runs only because
// a box's owner asked for one, and is meant to execute inside that box with its
// own privileges, never by mounting a tenant's rootfs into a platform
// container. Until the in-box runner exists, ScanContainer records an
// `incomplete` report, never `clean`.
type Scanner struct {
	store    *Store
	box      boxAPI // runs the scan inside the tenant's box
	timeout  time.Duration
	interval time.Duration // retention cleanup cadence
	cancel   context.CancelFunc
	// onScanResult, if set, is called after each completed scan with the
	// container name, owning tenant, and result status (ScanStatusClean |
	// ScanStatusInfected | ScanStatusIncomplete). Only "infected" acts on the
	// quarantine; "clean" and "incomplete" leave it untouched (the verdict is
	// self-reported, #2654). The daemon wires this to the auto-quarantine hook
	// (#659). Kept a plain callback so internal/security keeps no dependency on
	// internal/server.
	onScanResult func(containerName, username, status string)

	// Test seam for ScanContainer (#2589). Nil in production, where the
	// Postgres store is used.
	reports reportSaver // persists the report; nil -> store
}

// reportSaver persists one scan report. *Store satisfies it.
type reportSaver interface {
	SaveReport(ctx context.Context, report *Report) error
}

func (s *Scanner) reportSaver() reportSaver {
	if s.reports != nil {
		return s.reports
	}
	return s.store
}

// SetScanResultHook registers a callback invoked after each completed scan
// (auto-quarantine, #659). Set before Start; nil disables it.
func (s *Scanner) SetScanResultHook(fn func(containerName, username, status string)) {
	s.onScanResult = fn
}

// NewScanner creates a new scanner
func NewScanner(store *Store, box boxAPI) *Scanner {
	return &Scanner{
		store:    store,
		box:      box,
		timeout:  DefaultInBoxScanTimeout,
		interval: 24 * time.Hour,
	}
}

// Start begins the background scanning loop and worker pool
func (s *Scanner) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)

	// Reconcile away any scan-<box> devices leaked by a scan that a prior
	// daemon restart interrupted (#832): ScanContainer removes its mount in a
	// defer, which a kill/restart mid-scan skips. A leaked device's mount pins
	// the target's storage volume (later delete → "dataset is busy" → the TTL
	// sweeper loops forever), and a leaked device whose source was since
	// deleted blocks the security container from starting. No scan survives a
	// restart, so all such devices are stale.
	s.reconcileStaleScanDevices(ctx)

	// Start worker pool
	s.startWorkers(ctx, maxConcurrentScans)

	// Retention cleanup only. Nothing here enqueues a scan (#2631).
	go func() {
		timer := time.NewTimer(5 * time.Minute)
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				s.runRetentionCleanup(ctx)
				timer.Reset(s.interval)
			}
		}
	}()

	log.Printf("Security scanner started (retention cleanup every %v, workers: %d); scans run only when a box owner requests one", s.interval, maxConcurrentScans)
}

// Stop stops the background workers and cleanup loop
func (s *Scanner) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	log.Printf("Security scanner stopped")
}

// scanDevicePrefix tags the disk devices ScanContainer attaches to the
// security container ("scan-<box>"). Reconciliation keys off it.
const scanDevicePrefix = "scan-"

// reconcileStaleScanDevices removes every scan-<box> disk device left on the
// security container — they only ever exist mid-scan, so any present at
// startup leaked from a scan a prior daemon interrupted (#832). Best-effort:
// a missing security container (fresh host) or a per-device failure is logged,
// never fatal to startup.
func (s *Scanner) reconcileStaleScanDevices(ctx context.Context) {
	out, err := exec.CommandContext(ctx, "incus", "config", "device", "list",
		SecurityContainerName).CombinedOutput()
	if err != nil {
		// Fresh host: the security container may not exist yet — not an error.
		log.Printf("Security scan: skip stale scan-device reconcile (%s): %v",
			SecurityContainerName, err)
		return
	}
	removed := 0
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if !strings.HasPrefix(name, scanDevicePrefix) {
			continue
		}
		// #nosec G204 -- name is a device listed by incus on our own security
		// container; removing a scan-* device is exactly this function's job.
		if rmOut, rmErr := exec.CommandContext(ctx, "incus", "config", "device", "remove",
			SecurityContainerName, name).CombinedOutput(); rmErr != nil {
			log.Printf("Security scan: failed to remove stale scan device %s: %v (%s)",
				name, rmErr, strings.TrimSpace(string(rmOut)))
			continue
		}
		removed++
	}
	if removed > 0 {
		log.Printf("Security scan: reconciled %d stale scan device(s) from %s",
			removed, SecurityContainerName)
	}
}

// runRetentionCleanup deletes old reports and jobs (keep 90 days).
func (s *Scanner) runRetentionCleanup(ctx context.Context) {
	if err := s.store.Cleanup(ctx, 90); err != nil {
		log.Printf("Security scan: report cleanup failed: %v", err)
	}
	if err := s.store.CleanupOldJobs(ctx, 90); err != nil {
		log.Printf("Security scan: job cleanup failed: %v", err)
	}
}

// ErrScanActive is returned by EnqueueOne when the box already has a scan
// pending or running; the caller maps it to AlreadyExists.
var ErrScanActive = errors.New("a scan for this box is already pending or running")

// EnqueueOne enqueues a scan job for a single container, started by its owner.
// Returns the job ID, or ErrScanActive if one is already pending or running.
func (s *Scanner) EnqueueOne(ctx context.Context, containerName, username string) (int64, error) {
	if _, active, err := s.store.ActiveScanJob(ctx, containerName); err != nil {
		return 0, err
	} else if active {
		return 0, ErrScanActive
	}
	return s.store.EnqueueScanJob(ctx, containerName, username)
}

// startWorkers spawns count goroutines that poll the job queue and process scans.
func (s *Scanner) startWorkers(ctx context.Context, count int) {
	for i := 0; i < count; i++ {
		go s.worker(ctx, i)
	}
}

// worker is a long-running goroutine that claims and processes scan jobs.
func (s *Scanner) worker(ctx context.Context, id int) {
	log.Printf("Scan worker %d started", id)
	for {
		select {
		case <-ctx.Done():
			log.Printf("Scan worker %d stopped", id)
			return
		default:
		}

		job, err := s.store.ClaimNextJob(ctx)
		if err != nil {
			log.Printf("Scan worker %d: claim error: %v", id, err)
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
			case <-time.After(5 * time.Second):
			}
			continue
		}

		log.Printf("Scan worker %d: processing job %d (%s)", id, job.ID, job.ContainerName)
		if err := s.ScanContainer(ctx, job.ContainerName, job.Username); err != nil {
			log.Printf("Scan worker %d: job %d failed: %v", id, job.ID, err)
			if failErr := s.store.FailJob(ctx, job.ID, err.Error()); failErr != nil {
				log.Printf("Scan worker %d: failed to mark job %d as failed: %v", id, job.ID, failErr)
			}
			continue
		}

		if err := s.store.CompleteJob(ctx, job.ID); err != nil {
			log.Printf("Scan worker %d: failed to mark job %d as completed: %v", id, job.ID, err)
		}
		log.Printf("Scan worker %d: job %d completed", id, job.ID)
	}
}

// ScanContainer runs one requested scan inside the tenant's own box (#2631).
// It never mounts or reads a tenant's files from the platform, and it reports
// `clean` only for a clamscan exit 0 with no findings — every other outcome is
// a distinct non-clean status with a reason (#2496). The report carries the
// verdict only: status, signature names with counts, duration.
func (s *Scanner) ScanContainer(ctx context.Context, containerName, username string) error {
	startTime := time.Now()
	report := &Report{
		ContainerName: containerName,
		Username:      username,
		ScannedAt:     startTime,
	}

	if status, reason := s.preflight(s.box, containerName); status != "" {
		report.Status, report.Findings = status, reason
	} else {
		version := scannerVersion(s.box, containerName)
		stdout, _, code, err := s.box.ExecWithExitCode(containerName, inBoxScanCommand(s.timeout))
		switch {
		case err != nil:
			report.Status = ScanStatusIncomplete
			report.Findings = fmt.Sprintf(reasonExecFailedFmt, err)
		default:
			report.Status, report.FindingsCount, report.Findings = classifyInBoxRun(code, stdout)
			if report.Status == ScanStatusClean {
				report.Findings = version
			}
		}
	}
	report.ScanDuration = time.Since(startTime).Truncate(time.Second).String()

	if err := s.reportSaver().SaveReport(ctx, report); err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}
	switch report.Status {
	case ScanStatusInfected:
		log.Printf("Security scan: %s (%s) INFECTED - %d findings", containerName, username, report.FindingsCount)
	case ScanStatusClean:
		log.Printf("Security scan: %s (%s) clean (self-reported, took %s)", containerName, username, report.ScanDuration)
	default:
		log.Printf("Security scan: %s (%s) %s - %s", containerName, username, strings.ToUpper(report.Status), report.Findings)
	}
	if s.onScanResult != nil {
		s.onScanResult(containerName, username, report.Status)
	}
	return nil
}
