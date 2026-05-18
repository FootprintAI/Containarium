package autosleep

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// DefaultInterval is the tick cadence — once a minute is plenty when
// the cheapest threshold is in the single-digit-minutes range.
const DefaultInterval = 60 * time.Second

// IncusClient is the slice of *incus.Client the manager actually
// touches. ListContainers gives us the per-container Role / AutoSleep /
// IdleThreshold / LastStartedAt that Phase 1 already populates on the
// read paths.
type IncusClient interface {
	ListContainers() ([]incus.ContainerInfo, error)
}

// TrafficSource yields the most recent network-activity timestamp for a
// given Incus container name. Implementations may return the zero time
// to mean "no traffic ever recorded" — Decide handles the zero
// explicitly so callers don't need to distinguish error from absence.
type TrafficSource interface {
	LastNetworkActivity(ctx context.Context, containerName string) (time.Time, error)
}

// Stopper invokes the existing StopContainer plumbing under an
// auto-sleep banner. The implementation is responsible for emitting any
// daemon-level events (e.g. EmitContainerStopped) so observers see the
// same shape as a manual stop.
type Stopper interface {
	StopForAutoSleep(ctx context.Context, username string, reason string, idleMinutes int) error
}

// AuditLogger writes one structured record per sleep so operators can
// query "all auto-sleeps in the last 24h". Nil is accepted by the
// manager; it falls back to log.Printf so the daemon never silently
// loses the audit trail.
type AuditLogger interface {
	Log(event string, fields map[string]any)
}

// Manager owns the tick loop. One Manager per daemon; constructed in
// DualServer.NewDualServer wiring and started by DualServer.Start.
type Manager struct {
	incus    IncusClient
	traffic  TrafficSource // may be nil → "no network signal"
	stopper  Stopper
	audit    AuditLogger // may be nil → log.Printf fallback
	interval time.Duration
	clock    func() time.Time

	mu     sync.Mutex
	stopCh chan struct{}
	done   chan struct{}
}

// Options bundles the optional knobs. Production callers should pass
// zero values for Interval/Clock to get DefaultInterval and time.Now.
type Options struct {
	Interval time.Duration
	Clock    func() time.Time
}

// NewManager constructs a manager. Both Traffic and Audit may be nil:
// Traffic-nil falls back to Decide's "no network signal" branch (which
// can still sleep on since-start). Audit-nil falls back to log.Printf.
func NewManager(inc IncusClient, traffic TrafficSource, stopper Stopper, audit AuditLogger, opts Options) *Manager {
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	return &Manager{
		incus:    inc,
		traffic:  traffic,
		stopper:  stopper,
		audit:    audit,
		interval: opts.Interval,
		clock:    opts.Clock,
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start spawns the tick loop. Returns immediately. Safe to call once;
// subsequent calls before Stop are a no-op.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.done == nil {
		// Stop closed us already; refuse to restart on a poisoned manager.
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	go m.run(ctx)
	log.Printf("[autosleep] ticker started (interval=%s)", m.interval)
}

// Stop signals the loop to exit. Idempotent.
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.stopCh == nil {
		m.mu.Unlock()
		return
	}
	close(m.stopCh)
	m.stopCh = nil
	done := m.done
	m.mu.Unlock()

	if done != nil {
		<-done
	}
}

func (m *Manager) run(ctx context.Context) {
	defer func() {
		m.mu.Lock()
		if m.done != nil {
			close(m.done)
			m.done = nil
		}
		m.mu.Unlock()
	}()

	t := time.NewTicker(m.interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan():
			return
		case <-t.C:
			m.tick(ctx)
		}
	}
}

// stopChan returns the current stop channel under the lock. A nil
// channel blocks forever in select, which is the right behavior after
// Stop() has nil'd it out (run is already exiting via the close).
func (m *Manager) stopChan() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopCh
}

// tick evaluates every container once. Errors are logged and the loop
// continues — a single misbehaving container shouldn't halt the
// ticker for everyone else.
func (m *Manager) tick(ctx context.Context) {
	containers, err := m.incus.ListContainers()
	if err != nil {
		log.Printf("[autosleep] list containers: %v", err)
		return
	}
	now := m.clock()
	for _, c := range containers {
		if c.Role.IsCoreRole() {
			continue
		}
		if !c.AutoSleepEnabled {
			continue
		}

		username := strings.TrimSuffix(c.Name, "-container")

		var lastNet time.Time
		if m.traffic != nil {
			lastNet, err = m.traffic.LastNetworkActivity(ctx, c.Name)
			if err != nil {
				log.Printf("[autosleep] last activity for %s: %v", c.Name, err)
				// Treat error as no signal — fall through with zero time.
				lastNet = time.Time{}
			}
		}

		in := DecideInput{
			Username:             username,
			State:                c.State,
			AutoSleepEnabled:     c.AutoSleepEnabled,
			IdleThresholdMinutes: c.IdleThresholdMinutes,
			IsCoreRole:           c.Role.IsCoreRole(),
			LastStartedAt:        c.LastStartedAt,
			LastNetworkActivity:  lastNet,
			Now:                  now,
		}
		d := Decide(in)
		if d.Action != ActionSleep {
			continue
		}

		if err := m.stopper.StopForAutoSleep(ctx, username, d.Reason, d.IdleMinutes); err != nil {
			log.Printf("[autosleep] stop %s: %v", username, err)
			continue
		}
		m.logSleep(ctx, username, d)
	}
}

func (m *Manager) logSleep(_ context.Context, username string, d Decision) {
	fields := map[string]any{
		"username":     username,
		"reason":       d.Reason,
		"idle_minutes": d.IdleMinutes,
	}
	if m.audit != nil {
		m.audit.Log("autosleep.stopped", fields)
		return
	}
	log.Printf("[autosleep] stopped username=%s reason=%q idle_minutes=%d", username, d.Reason, d.IdleMinutes)
}
