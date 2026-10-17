package security

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// maxConcurrentScans limits parallel ClamAV scans to avoid overloading the
// security container's CPU and memory. Set to 1 because all scans share a
// single clamd daemon inside the security container.
const maxConcurrentScans = 1

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
	// onScanResult, if set, is called after each completed scan with the
	// container name, owning tenant, and result status (ScanStatusClean |
	// ScanStatusInfected | ScanStatusIncomplete). Only "infected" and "clean"
	// act on the quarantine; "incomplete" must leave it untouched.
	// The daemon wires this to the auto-quarantine hook (#659). Kept a plain
	// callback so internal/security keeps no dependency on internal/server.
	onScanResult func(containerName, username, status string)

	// Test seams for ScanContainer (#2589). All nil in production, where the
	// concrete incus client, the incus CLI and the Postgres store are used.
	execer  scanExecer     // exec inside the security container; nil -> incusClient
	devices scanDevices    // mount/unmount of the scan disk device; nil -> incus CLI
	reports reportSaver    // persists the report; nil -> store
	settle  *time.Duration // wait after mounting; nil -> mountSettleTime
}

// mountSettleTime is how long ScanContainer waits for the freshly added disk
// device to appear before looking at it.
const mountSettleTime = 2 * time.Second

// scanExecer runs a command inside the security container.
// *incus.Client satisfies it.
type scanExecer interface {
	ExecWithOutput(container string, cmd []string) (stdout, stderr string, err error)
}

// scanDevices mounts a target's rootfs read-only into the security container
// and removes it again.
type scanDevices interface {
	Remove(ctx context.Context, deviceName string) (output string, err error)
	Add(ctx context.Context, deviceName, source, mountPath string) (output string, err error)
}

// reportSaver persists one scan report. *Store satisfies it.
type reportSaver interface {
	SaveReport(ctx context.Context, report *Report) error
}

// incusCLIDevices drives the disk device through the incus CLI, which is
// simpler than the raw API for device management.
type incusCLIDevices struct{}

func (incusCLIDevices) Remove(ctx context.Context, deviceName string) (string, error) {
	// #nosec G204 -- argv, never a shell; deviceName is scanDevicePrefix plus
	// the name of a container the daemon itself listed from Incus.
	out, err := exec.CommandContext(ctx, "incus", "config", "device", "remove", SecurityContainerName, deviceName).CombinedOutput()
	return string(out), err
}

func (incusCLIDevices) Add(ctx context.Context, deviceName, source, mountPath string) (string, error) {
	// #nosec G204 -- argv, never a shell; deviceName, source and mountPath are
	// built from the daemon's own storage pool and the name of a container it
	// listed from Incus.
	out, err := exec.CommandContext(ctx, "incus", "config", "device", "add",
		SecurityContainerName, deviceName, "disk",
		fmt.Sprintf("source=%s", source),
		fmt.Sprintf("path=%s", mountPath),
		"readonly=true",
	).CombinedOutput()
	return string(out), err
}

func (s *Scanner) scanExec() scanExecer {
	if s.execer != nil {
		return s.execer
	}
	return s.incusClient
}

func (s *Scanner) scanDevices() scanDevices {
	if s.devices != nil {
		return s.devices
	}
	return incusCLIDevices{}
}

func (s *Scanner) reportSaver() reportSaver {
	if s.reports != nil {
		return s.reports
	}
	return s.store
}

func (s *Scanner) settleTime() time.Duration {
	if s.settle != nil {
		return *s.settle
	}
	return mountSettleTime
}

// SetScanResultHook registers a callback invoked after each completed scan
// (auto-quarantine, #659). Set before Start; nil disables it.
func (s *Scanner) SetScanResultHook(fn func(containerName, username, status string)) {
	s.onScanResult = fn
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

// EnqueueNewContainer enqueues a scan for a newly created container after a short delay
// to allow the container to fully boot and install packages.
func (s *Scanner) EnqueueNewContainer(containerName string) {
	username := containerName
	if strings.HasSuffix(containerName, "-container") {
		username = strings.TrimSuffix(containerName, "-container")
	}
	// Delay scan to allow container setup to complete
	go func() {
		time.Sleep(2 * time.Minute)
		ctx := context.Background()
		if _, err := s.store.EnqueueScanJob(ctx, containerName, username); err != nil {
			log.Printf("[security] failed to enqueue scan for new container %s: %v", containerName, err)
		} else {
			log.Printf("[security] scan queued for new container %s", containerName)
		}
	}()
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
	deviceName := scanDevicePrefix + strings.ReplaceAll(containerName, "/", "-")
	mountPath := fmt.Sprintf("/mnt/scan-%s", strings.ReplaceAll(containerName, "/", "-"))
	rootfsPath := fmt.Sprintf("/var/lib/incus/storage-pools/%s/containers/%s/rootfs", s.storagePool, containerName)

	// Remove any stale device from a previous interrupted scan
	devices := s.scanDevices()
	_, _ = devices.Remove(ctx, deviceName) // ignore errors — device may not exist

	// Add the disk device (read-only)
	if out, err := devices.Add(ctx, deviceName, rootfsPath, mountPath); err != nil {
		return fmt.Errorf("failed to mount rootfs: %w (output: %s)", err, out)
	}

	// Ensure cleanup. Detached from ctx so a cancelled scan still unmounts.
	defer func() {
		if out, err := devices.Remove(context.WithoutCancel(ctx), deviceName); err != nil {
			log.Printf("Warning: failed to unmount scan device %s: %v (output: %s)", deviceName, err, out)
		}
	}()

	// Wait briefly for device to be available
	time.Sleep(s.settleTime())

	// Verify the mount has actual content — on ZFS backends, stopped containers
	// or missing datasets result in an empty mount that clamdscan scans instantly,
	// producing a false "clean" with 0s duration.
	lsOut, _, _ := s.scanExec().ExecWithOutput(SecurityContainerName, []string{
		"ls", mountPath,
	})
	if strings.TrimSpace(lsOut) == "" {
		return fmt.Errorf("mount path %s is empty — container rootfs not accessible (container may be stopped or storage backend not mounted)", mountPath)
	}

	// Run clamdscan (uses the resident clamd daemon which keeps the virus DB in
	// memory, avoiding the expensive DB reload that clamscan performs on each
	// invocation). Directory exclusions are configured in clamd.conf ExcludePath.
	startTime := time.Now()
	stdout, stderr, scanErr := s.scanExec().ExecWithOutput(SecurityContainerName, []string{
		"clamdscan", "--infected", "--no-summary", "--multiscan",
		mountPath,
	})
	scanDuration := time.Since(startTime)

	// clamdscan exits 1 when infections are found (not an error) but 2 on a
	// scan error, whose stdout has no FOUND lines — so stdout alone would read
	// "clean". Classify on the exit error too (#2496).
	status, findingsCount, findings := ClassifyClamScan(stdout, stderr, scanErr)
	if status == ScanStatusIncomplete {
		log.Printf("Warning: clamdscan did not complete for %s: %v", containerName, scanErr)
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

	if err := s.reportSaver().SaveReport(ctx, report); err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	switch status {
	case ScanStatusInfected:
		log.Printf("Security scan: %s (%s) INFECTED - %d findings", containerName, username, findingsCount)
	case ScanStatusIncomplete:
		log.Printf("Security scan: %s (%s) INCOMPLETE - not reported clean (took %s)", containerName, username, scanDuration.Truncate(time.Second))
	default:
		log.Printf("Security scan: %s (%s) clean (took %s)", containerName, username, scanDuration.Truncate(time.Second))
	}

	// Auto-quarantine hook (#659): block/release the tenant's egress on
	// infected/clean. No-op unless the daemon wired it (opt-in).
	if s.onScanResult != nil {
		s.onScanResult(containerName, username, status)
	}

	return nil
}
