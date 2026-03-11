package security

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/incus"
)

// maxConcurrentScans limits parallel ClamAV scans to avoid overloading the
// security container's CPU and memory.
const maxConcurrentScans = 3

// SecurityContainerName is the name of the core ClamAV security container.
// Defined here to avoid an import cycle with internal/server.
const SecurityContainerName = "containarium-core-security"

// Scanner performs periodic ClamAV scans of container filesystems
type Scanner struct {
	incusClient *incus.Client
	store       *Store
	interval    time.Duration
	storagePool string
	cancel      context.CancelFunc
}

// NewScanner creates a new scanner
func NewScanner(incusClient *incus.Client, store *Store) *Scanner {
	return &Scanner{
		incusClient: incusClient,
		store:       store,
		interval:    24 * time.Hour,
		storagePool: "default",
	}
}

// Start begins the background scanning loop and worker pool
func (s *Scanner) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)

	// Start worker pool
	s.startWorkers(ctx, maxConcurrentScans)

	go func() {
		// Run first scan after a startup delay
		timer := time.NewTimer(5 * time.Minute)
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				s.runScanCycle(ctx)
				timer.Reset(s.interval)
			}
		}
	}()

	log.Printf("Security scanner started (interval: %v, workers: %d)", s.interval, maxConcurrentScans)
}

// Stop stops the background scanning loop
func (s *Scanner) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	log.Printf("Security scanner stopped")
}

// runScanCycle enqueues scan jobs for all running user containers
func (s *Scanner) runScanCycle(ctx context.Context) {
	log.Printf("Starting ClamAV scan cycle...")

	count, err := s.EnqueueAll(ctx)
	if err != nil {
		log.Printf("Security scan: failed to enqueue jobs: %v", err)
		return
	}

	// Cleanup old reports and jobs (keep 90 days)
	if err := s.store.Cleanup(ctx, 90); err != nil {
		log.Printf("Security scan: report cleanup failed: %v", err)
	}
	if err := s.store.CleanupOldJobs(ctx, 90); err != nil {
		log.Printf("Security scan: job cleanup failed: %v", err)
	}

	log.Printf("ClamAV scan cycle: %d jobs enqueued", count)
}

// EnqueueAll enqueues a scan job for each running user container.
// Returns the number of jobs enqueued.
func (s *Scanner) EnqueueAll(ctx context.Context) (int, error) {
	containers, err := s.incusClient.ListContainers()
	if err != nil {
		return 0, fmt.Errorf("failed to list containers: %w", err)
	}

	enqueued := 0
	for _, c := range containers {
		if c.State != "Running" || c.Role.IsCoreRole() {
			continue
		}
		username := c.Name
		if strings.HasSuffix(c.Name, "-container") {
			username = strings.TrimSuffix(c.Name, "-container")
		}
		if _, err := s.store.EnqueueScanJob(ctx, c.Name, username); err != nil {
			log.Printf("Security scan: failed to enqueue job for %s: %v", c.Name, err)
			continue
		}
		enqueued++
	}

	return enqueued, nil
}

// EnqueueOne enqueues a scan job for a single container.
// Returns the job ID.
func (s *Scanner) EnqueueOne(ctx context.Context, containerName, username string) (int64, error) {
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

// ScanContainer scans a single container's filesystem via disk device mount.
// Each container gets a unique mount path so multiple scans can run concurrently.
func (s *Scanner) ScanContainer(ctx context.Context, containerName, username string) error {
	deviceName := fmt.Sprintf("scan-%s", strings.ReplaceAll(containerName, "/", "-"))
	mountPath := fmt.Sprintf("/mnt/scan-%s", strings.ReplaceAll(containerName, "/", "-"))
	rootfsPath := fmt.Sprintf("/var/lib/incus/storage-pools/%s/containers/%s/rootfs", s.storagePool, containerName)

	// Remove any stale device from a previous interrupted scan
	rmStaleCmd := exec.CommandContext(ctx, "incus", "config", "device", "remove",
		SecurityContainerName, deviceName,
	)
	rmStaleCmd.CombinedOutput() // ignore errors — device may not exist

	// Add disk device using incus CLI (simpler than raw API for device management)
	addCmd := exec.CommandContext(ctx, "incus", "config", "device", "add",
		SecurityContainerName, deviceName, "disk",
		fmt.Sprintf("source=%s", rootfsPath),
		fmt.Sprintf("path=%s", mountPath),
		"readonly=true",
	)
	if out, err := addCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to mount rootfs: %w (output: %s)", err, string(out))
	}

	// Ensure cleanup
	defer func() {
		rmCmd := exec.Command("incus", "config", "device", "remove",
			SecurityContainerName, deviceName,
		)
		if out, err := rmCmd.CombinedOutput(); err != nil {
			log.Printf("Warning: failed to unmount scan device %s: %v (output: %s)", deviceName, err, string(out))
		}
	}()

	// Wait briefly for device to be available
	time.Sleep(2 * time.Second)

	// Run clamscan
	startTime := time.Now()
	stdout, _, scanErr := s.incusClient.ExecWithOutput(SecurityContainerName, []string{
		"clamscan", "-ri", "--no-summary",
		fmt.Sprintf("--exclude-dir=^%s/sys", mountPath),
		fmt.Sprintf("--exclude-dir=^%s/proc", mountPath),
		fmt.Sprintf("--exclude-dir=^%s/dev", mountPath),
		mountPath,
	})
	scanDuration := time.Since(startTime)

	// Parse output - clamscan returns exit code 1 if infections found (not an error)
	status, findingsCount, findings := ParseClamScanOutput(stdout)

	// If scanErr is set but it's just exit code 1 (infections found), that's OK
	if scanErr != nil && status == "clean" {
		log.Printf("Warning: clamscan error for %s: %v", containerName, scanErr)
	}

	// Save report
	report := &Report{
		ContainerName: containerName,
		Username:      username,
		Status:        status,
		FindingsCount: findingsCount,
		Findings:      findings,
		ScannedAt:     startTime,
		ScanDuration:  scanDuration.Truncate(time.Second).String(),
	}

	if err := s.store.SaveReport(ctx, report); err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	if status == "infected" {
		log.Printf("Security scan: %s (%s) INFECTED - %d findings", containerName, username, findingsCount)
	} else {
		log.Printf("Security scan: %s (%s) clean (took %s)", containerName, username, scanDuration.Truncate(time.Second))
	}

	return nil
}
