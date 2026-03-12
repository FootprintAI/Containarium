package audit

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/incus"
)

// SSHCollector periodically reads auth.log from containers to capture SSH login events.
type SSHCollector struct {
	incusClient *incus.Client
	store       *Store
	interval    time.Duration
	lastSeen    map[string]time.Time // per-container high-water mark
	mu          sync.Mutex
	cancel      context.CancelFunc
}

// NewSSHCollector creates a new SSH login collector.
func NewSSHCollector(incusClient *incus.Client, store *Store) *SSHCollector {
	return &SSHCollector{
		incusClient: incusClient,
		store:       store,
		interval:    2 * time.Minute,
		lastSeen:    make(map[string]time.Time),
	}
}

// Start begins the background collection loop.
func (sc *SSHCollector) Start(ctx context.Context) {
	ctx, sc.cancel = context.WithCancel(ctx)

	go func() {
		// First run after a short delay
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				sc.collectAll(ctx)
				timer.Reset(sc.interval)
			}
		}
	}()

	log.Printf("SSH login collector started (interval: %v)", sc.interval)
}

// Stop cancels the background collection loop.
func (sc *SSHCollector) Stop() {
	if sc.cancel != nil {
		sc.cancel()
	}
	log.Printf("SSH login collector stopped")
}

// collectAll iterates all running user containers and collects SSH login entries.
func (sc *SSHCollector) collectAll(ctx context.Context) {
	containers, err := sc.incusClient.ListContainers()
	if err != nil {
		log.Printf("SSH collector: failed to list containers: %v", err)
		return
	}

	for _, c := range containers {
		if c.State != "Running" || c.Role.IsCoreRole() {
			continue
		}

		username := c.Name
		if strings.HasSuffix(c.Name, "-container") {
			username = strings.TrimSuffix(c.Name, "-container")
		}

		if err := sc.collectFromContainer(ctx, c.Name, username); err != nil {
			log.Printf("SSH collector: %s: %v", c.Name, err)
		}
	}
}

// collectFromContainer reads auth.log from a single container and writes audit entries.
func (sc *SSHCollector) collectFromContainer(ctx context.Context, containerName, username string) error {
	stdout, _, err := sc.incusClient.ExecWithOutput(containerName, []string{
		"grep", "Accepted", "/var/log/auth.log",
	})
	if err != nil {
		// grep exits 1 when no matches — not an error
		if strings.Contains(err.Error(), "exited with code 1") {
			return nil
		}
		return fmt.Errorf("failed to read auth.log: %w", err)
	}

	if strings.TrimSpace(stdout) == "" {
		return nil
	}

	sc.mu.Lock()
	highWater := sc.lastSeen[containerName]
	sc.mu.Unlock()

	year := time.Now().Year()
	var maxTS time.Time
	lines := strings.Split(strings.TrimSpace(stdout), "\n")

	for _, line := range lines {
		ts, sshUser, sourceIP, method, ok := parseAuthLogLine(line, year)
		if !ok {
			continue
		}

		// Skip entries we've already seen
		if !ts.After(highWater) {
			continue
		}

		if ts.After(maxTS) {
			maxTS = ts
		}

		entry := &AuditEntry{
			Timestamp:    ts,
			Username:     username,
			Action:       "ssh_login",
			ResourceType: "container",
			ResourceID:   containerName,
			Detail:       fmt.Sprintf("method=%s user=%s", method, sshUser),
			SourceIP:     sourceIP,
			StatusCode:   0,
		}

		if err := sc.store.Log(ctx, entry); err != nil {
			log.Printf("SSH collector: failed to log entry for %s: %v", containerName, err)
		}
	}

	if !maxTS.IsZero() {
		sc.mu.Lock()
		sc.lastSeen[containerName] = maxTS
		sc.mu.Unlock()
	}

	return nil
}

// authLogPattern matches sshd "Accepted" lines in auth.log.
// Example: Mar 12 14:30:01 hostname sshd[12345]: Accepted publickey for alice from 10.100.0.1 port 54321 ssh2
var authLogPattern = regexp.MustCompile(
	`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+\d+`,
)

// parseAuthLogLine parses a single auth.log "Accepted" line.
// Returns timestamp, sshUser, sourceIP, method, and whether parsing succeeded.
func parseAuthLogLine(line string, year int) (time.Time, string, string, string, bool) {
	matches := authLogPattern.FindStringSubmatch(line)
	if matches == nil {
		return time.Time{}, "", "", "", false
	}

	// matches[1] = "Mar 12 14:30:01"
	// matches[2] = method (publickey, password, etc.)
	// matches[3] = SSH username
	// matches[4] = source IP

	tsStr := fmt.Sprintf("%d %s", year, matches[1])
	ts, err := time.Parse("2006 Jan  2 15:04:05", tsStr)
	if err != nil {
		// Try single-digit day without leading space
		ts, err = time.Parse("2006 Jan 2 15:04:05", tsStr)
		if err != nil {
			return time.Time{}, "", "", "", false
		}
	}

	return ts, matches[3], matches[4], matches[2], true
}
