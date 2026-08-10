package audit

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// SSHCollector periodically reads each box's session log to capture SSH
// login events.
//
// Backend-neutral since #1189: it holds a SessionSource rather than an
// *incus.Client, because K8s boxes keep their session log somewhere else
// (a pod's stderr, not /var/log/auth.log) and write it in a different
// format (dropbear, not OpenSSH).
type SSHCollector struct {
	source   SessionSource
	store    entryLogger
	interval time.Duration
	lastSeen map[string]time.Time // per-box high-water mark
	mu       sync.Mutex
	cancel   context.CancelFunc
}

// NewSSHCollector creates a collector over the LXC session source.
//
// Kept for the existing call site; NewSSHCollectorWithSource is the general
// form.
// entryLogger is the only thing the collector needs from the audit store.
// Narrowed so the collection logic is testable without Postgres — *Store
// satisfies it, so no call site changes.
type entryLogger interface {
	Log(ctx context.Context, entry *AuditEntry) error
}

func NewSSHCollector(incusClient *incus.Client, store *Store) *SSHCollector {
	return NewSSHCollectorWithSource(NewIncusSessionSource(incusClient), store)
}

// NewSSHCollectorWithSource creates a collector over any session source.
func NewSSHCollectorWithSource(source SessionSource, store entryLogger) *SSHCollector {
	return &SSHCollector{
		source:   source,
		store:    store,
		interval: 2 * time.Minute,
		lastSeen: make(map[string]time.Time),
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

// collectAll iterates every box the source reports and collects its logins.
func (sc *SSHCollector) collectAll(ctx context.Context) {
	boxes, err := sc.source.Boxes(ctx)
	if err != nil {
		log.Printf("SSH collector: failed to list boxes: %v", err)
		return
	}

	for _, b := range boxes {
		if err := sc.collectFromBox(ctx, b); err != nil {
			log.Printf("SSH collector: %s: %v", b.Name, err)
		}
	}
}

// collectFromBox reads one box's session log and writes audit entries.
func (sc *SSHCollector) collectFromBox(ctx context.Context, box SessionBox) error {
	containerName, username := box.Name, box.Username

	stdout, err := sc.source.ReadSessions(ctx, box)
	if err != nil {
		return fmt.Errorf("read session log: %w", err)
	}

	if strings.TrimSpace(stdout) == "" {
		return nil
	}

	sc.mu.Lock()
	highWater := sc.lastSeen[containerName]
	sc.mu.Unlock()

	year := time.Now().Year()
	// Used for sources whose lines carry no timestamp of their own.
	readAt := time.Now()
	var maxTS time.Time
	lines := strings.Split(strings.TrimSpace(stdout), "\n")

	for _, line := range lines {
		ts, sshUser, sourceIP, method, ok := sc.source.ParseLine(line, year, readAt)
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
