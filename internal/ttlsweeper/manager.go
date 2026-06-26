package ttlsweeper

import (
	"context"
	"log"
	"sync"
	"time"
)

// DefaultInterval is the tick cadence. Once a minute keeps the
// deletion latency tight (max ~1m past TTL plus graceMargin) without
// flooding incusd with list calls — the typical Containarium daemon
// owns dozens of containers, not thousands.
const DefaultInterval = 60 * time.Second

const (
	// failBackoffBase is the wait after a container's first failed delete; it
	// doubles each consecutive failure up to failBackoffMax. A delete can fail
	// permanently (e.g. a leaked scan mount pinning the ZFS dataset →
	// "dataset is busy", #832) and Decide keeps returning the still-expired
	// box every tick — without backoff the sweeper retries every 60s forever,
	// flooding the journal and never progressing (#831). Backoff turns that
	// into 1m, 2m, 4m, … so one wedged box is near-silent and can't starve the
	// loop.
	failBackoffBase = 1 * time.Minute
	failBackoffMax  = 1 * time.Hour
	// quarantineAfter is the consecutive-failure count past which the sweeper
	// parks the box at failBackoffMax and logs ONCE at WARN — a permanently
	// stuck delete becomes a single actionable line instead of an infinite
	// loop. It still retries hourly in case the blocker clears on its own.
	quarantineAfter = 10
	// maxBackoffShift caps the exponent so failBackoffBase << shift can't
	// overflow on a long-lived stuck entry (the result is clamped to
	// failBackoffMax regardless).
	maxBackoffShift = 16
)

// failState tracks one container's consecutive delete failures so the sweeper
// can back off instead of hammering an undeletable box every tick (#831).
type failState struct {
	count       int
	nextAttempt time.Time
	quarantined bool
}

// IncusClient is the narrow slice of the daemon's container source
// the sweeper actually needs. The wiring PR adapts the real
// *incus.Client (or whatever persists TTL — Incus user.* config,
// SQLite, etc.) into ContainerView records on the way through.
//
// Kept as a one-method interface so the daemon-side implementation
// has zero coupling beyond "produce a slice of view records on
// demand"; tests use a literal fake without mockgen.
type IncusClient interface {
	ListContainers() ([]ContainerView, error)
}

// Deleter is the action seam. The wiring PR provides an
// implementation that invokes the existing DeleteContainer plumbing
// with the right audit-event banner. The sweeper itself does not
// know how a container gets deleted — only that it should be.
//
// reason is a short human-readable string (e.g. "ttl_expired
// 2026-05-23T13:00:00Z") that the implementation may log and/or
// surface in the audit trail. Errors are logged and the loop
// continues — one bad container should not poison the rest of the
// tick.
type Deleter interface {
	DeleteContainer(ctx context.Context, name string, reason string) error
}

// Manager owns the tick loop. One Manager per daemon. Mirrors the
// shape of internal/autosleep/manager.Manager so the two ticker
// goroutines have the same lifecycle story (Start spawns, Stop
// signals + waits, both idempotent).
type Manager struct {
	incus    IncusClient
	deleter  Deleter
	interval time.Duration
	clock    func() time.Time

	stopCh   chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	// failures tracks per-container consecutive delete failures for backoff
	// (#831). Only ever touched from the single run goroutine's tick, so it
	// needs no lock.
	failures map[string]*failState
}

// Options bundles the optional knobs. Production callers should pass
// zero values for Interval/Clock to get DefaultInterval and time.Now.
type Options struct {
	Interval time.Duration
	Clock    func() time.Time
}

// NewManager constructs a manager. Neither IncusClient nor Deleter
// may be nil — the sweeper has nothing useful to do without both, and
// silently degrading would hide a wiring bug in the daemon's startup.
// The follow-up wiring PR is expected to construct exactly one of
// these in main and Start it alongside the other ticker managers.
func NewManager(inc IncusClient, deleter Deleter, opts Options) *Manager {
	if inc == nil {
		panic("ttlsweeper: nil IncusClient")
	}
	if deleter == nil {
		panic("ttlsweeper: nil Deleter")
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	return &Manager{
		incus:    inc,
		deleter:  deleter,
		interval: opts.Interval,
		clock:    opts.Clock,
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
		failures: make(map[string]*failState),
	}
}

// Start spawns the tick loop. Returns immediately. The loop exits on
// either ctx cancellation or Stop being called, whichever comes
// first.
func (m *Manager) Start(ctx context.Context) {
	go m.run(ctx)
	log.Printf("[ttlsweeper] ticker started (interval=%s)", m.interval)
}

// Stop signals the loop to exit and waits for it to finish.
// Idempotent — safe to call from multiple goroutines or multiple
// times.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
	<-m.done
}

func (m *Manager) run(ctx context.Context) {
	defer close(m.done)

	t := time.NewTicker(m.interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-t.C:
			m.tick(ctx)
		}
	}
}

// tick evaluates one round: list containers, ask Decide which are
// expired, delete each one. Errors are logged and the loop continues
// — a single misbehaving container shouldn't halt the ticker for
// everyone else (mirrors the autosleep manager's per-container
// failure isolation).
func (m *Manager) tick(ctx context.Context) {
	containers, err := m.incus.ListContainers()
	if err != nil {
		log.Printf("[ttlsweeper] list containers: %v", err)
		return
	}
	now := m.clock()
	expired := Decide(containers, now)

	// Prune failure entries for boxes no longer expired (deleted elsewhere,
	// woken, protected) so the map can't grow unbounded and a recreated box
	// reusing the name starts with a clean slate. Done before the empty-expired
	// early return so a box that vanishes entirely is still cleaned up.
	m.pruneFailures(expired)

	if len(expired) == 0 {
		return
	}

	// Build a lookup of name → expiry so the audit message can
	// include the exact TTL we acted on. Tiny — the typical daemon
	// has a few dozen containers, so the O(N) build cost is moot.
	expiryByName := make(map[string]time.Time, len(containers))
	for _, c := range containers {
		if c.TTLExpiresAt != nil {
			expiryByName[c.Name] = *c.TTLExpiresAt
		}
	}

	for _, name := range expired {
		// Honor backoff: a box whose delete keeps failing is retried on an
		// exponential schedule, not every tick (#831).
		if fs := m.failures[name]; fs != nil && now.Before(fs.nextAttempt) {
			continue
		}
		reason := "ttl_expired"
		if exp, ok := expiryByName[name]; ok {
			reason = "ttl_expired at " + exp.UTC().Format(time.RFC3339)
		}
		if err := m.deleter.DeleteContainer(ctx, name, reason); err != nil {
			m.recordFailure(name, err, now)
			continue
		}
		delete(m.failures, name)
		log.Printf("[ttlsweeper] deleted name=%s reason=%q", name, reason)
	}
}

// pruneFailures drops failure records for any container not in the current
// expired set — it was deleted elsewhere, woken, or protected, so its backoff
// state is stale. Keeps the map bounded and lets a recreated box reusing the
// name start clean.
func (m *Manager) pruneFailures(expired []string) {
	if len(m.failures) == 0 {
		return
	}
	stillExpired := make(map[string]struct{}, len(expired))
	for _, name := range expired {
		stillExpired[name] = struct{}{}
	}
	for name := range m.failures {
		if _, ok := stillExpired[name]; !ok {
			delete(m.failures, name)
		}
	}
}

// recordFailure bumps a container's consecutive-failure count and schedules
// the next attempt with exponential backoff, quarantining (parking at
// failBackoffMax + a single WARN) once it crosses quarantineAfter (#831).
func (m *Manager) recordFailure(name string, err error, now time.Time) {
	fs := m.failures[name]
	if fs == nil {
		fs = &failState{}
		m.failures[name] = fs
	}
	fs.count++

	shift := fs.count - 1
	if shift > maxBackoffShift {
		shift = maxBackoffShift
	}
	backoff := failBackoffBase << uint(shift)
	if backoff > failBackoffMax {
		backoff = failBackoffMax
	}
	fs.nextAttempt = now.Add(backoff)

	if fs.count >= quarantineAfter {
		if !fs.quarantined {
			fs.quarantined = true
			log.Printf("[ttlsweeper] delete %s: %v — failed %d times, quarantining (retry every %s); manual cleanup likely needed",
				name, err, fs.count, failBackoffMax)
		}
		return // already logged the once; stay quiet at the hourly cadence
	}
	log.Printf("[ttlsweeper] delete %s: %v (attempt %d, retry in %s)", name, err, fs.count, backoff)
}
