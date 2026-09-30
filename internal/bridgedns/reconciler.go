// Package bridgedns keeps the Incus bridge's raw.dnsmasq record equal to what
// the daemon would write for core-caddy's live address (#2188).
//
// With app hosting the daemon writes a wildcard record that resolves the base
// domain to core-caddy, but only once, at start-up. If core-caddy's address
// later changes, or the start-up write failed (it is a warning log line), every
// box on the bridge resolves the base domain to an address nothing answers on.
// The reconciler closes that gap: it re-reads core-caddy's live address and the
// bridge's current value on a timer and on container events, and rewrites the
// value only when it differs from what the daemon would render.
//
// The daemon owns the whole value: drift, including a hand edit, is restored
// and logged, exactly as the start-up write already replaces whatever was there.
package bridgedns

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// dnsmasqKey is the Incus network config key the record lives under.
const dnsmasqKey = "raw.dnsmasq"

// DefaultInterval is the steady-state reconcile cadence; container events
// converge sooner.
const DefaultInterval = 60 * time.Second

// Backend is the slice of the Incus client the reconciler needs.
type Backend interface {
	GetContainer(name string) (*incus.ContainerInfo, error)
	GetNetworkConfigValue(network, key string) (string, error)
	SetNetworkConfigValue(network, key, value string) error
}

// Config is the reconciler's static wiring.
type Config struct {
	// Bridge is the Incus managed network whose raw.dnsmasq is reconciled
	// (e.g. incusbr0).
	Bridge string
	// CaddyContainer is the core-caddy container whose live address the
	// record points at.
	CaddyContainer string
	// Render builds the desired raw.dnsmasq value for a core-caddy address.
	// It is the same function the start-up write uses, so the two can never
	// disagree about what "correct" is.
	Render func(caddyIP string) string
	// Interval overrides DefaultInterval (tests).
	Interval time.Duration
}

// Status is the reconciler's last-pass snapshot, for the status surface.
type Status struct {
	Bridge  string
	CaddyIP string
	// Desired is the value the last pass wanted; Current is what the bridge
	// held after it (the desired value once a write succeeded).
	Desired string
	Current string
	// InSync is true when the bridge held the desired value at the end of
	// the last pass.
	InSync bool
	// LastPass is when the last pass finished; LastError is why it could not
	// converge, empty when it did.
	LastPass  time.Time
	LastError string
	// DriftCount is the number of passes that found the record different
	// from the desired value; LastApplied is the last successful rewrite.
	DriftCount  int
	LastApplied time.Time
}

// Reconciler keeps the bridge record equal to the rendered value. It only ever
// writes on drift.
type Reconciler struct {
	be  Backend
	cfg Config

	mu     sync.Mutex
	status Status
}

// NewReconciler wires a reconciler; nothing runs until ReconcileOnce or Run.
func NewReconciler(be Backend, cfg Config) *Reconciler {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	return &Reconciler{be: be, cfg: cfg, status: Status{Bridge: cfg.Bridge}}
}

// Status returns a copy of the last-pass snapshot.
func (r *Reconciler) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

func (r *Reconciler) update(f func(*Status)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(&r.status)
}

// fail records why a pass could not converge and returns the error. No write
// has happened by the time it is called on the read paths.
func (r *Reconciler) fail(err error) error {
	r.update(func(s *Status) {
		s.InSync = false
		s.LastError = err.Error()
		s.LastPass = time.Now()
	})
	return err
}

// Run reconciles at start-up, on every event, and every Interval, until ctx is
// done. events is optional: a nil channel simply never fires. Errors are
// logged when they change, not on every tick, so a persistent fault does not
// flood the log.
func (r *Reconciler) Run(ctx context.Context, events <-chan struct{}) {
	var lastLogged string
	pass := func() {
		err := r.ReconcileOnce(ctx)
		switch {
		case err != nil && err.Error() != lastLogged:
			lastLogged = err.Error()
			log.Printf("[bridgedns] reconcile: %v", err)
		case err == nil && lastLogged != "":
			lastLogged = ""
			log.Printf("[bridgedns] reconcile recovered: %s in sync", r.cfg.Bridge)
		}
	}
	pass()
	tick := time.NewTicker(r.cfg.Interval)
	defer tick.Stop()
	log.Printf("[bridgedns] started (bridge=%s, interval=%s)", r.cfg.Bridge, r.cfg.Interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-events:
		}
		pass()
	}
}

// ReconcileOnce performs one read → compare → write pass.
//
// Fail-safe shape: an address that cannot be established (lookup error, not
// running, no address yet) or a current value that cannot be read returns with
// zero writes, so the record is never built from a guess.
func (r *Reconciler) ReconcileOnce(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := r.be.GetContainer(r.cfg.CaddyContainer)
	if err != nil {
		return r.fail(fmt.Errorf("bridgedns: look up %s: %w", r.cfg.CaddyContainer, err))
	}
	if info.State != "Running" {
		return r.fail(fmt.Errorf("bridgedns: %s is %q, not Running; leaving %s alone", r.cfg.CaddyContainer, info.State, dnsmasqKey))
	}
	if info.IPAddress == "" {
		return r.fail(fmt.Errorf("bridgedns: %s has no address yet; leaving %s alone", r.cfg.CaddyContainer, dnsmasqKey))
	}

	desired := r.cfg.Render(info.IPAddress)
	current, err := r.be.GetNetworkConfigValue(r.cfg.Bridge, dnsmasqKey)
	if err != nil {
		return r.fail(fmt.Errorf("bridgedns: read %s.%s: %w", r.cfg.Bridge, dnsmasqKey, err))
	}

	// Incus may store the value with different surrounding whitespace than
	// was sent; that is not drift and must not cause a rewrite every pass.
	if strings.TrimSpace(current) == strings.TrimSpace(desired) {
		r.update(func(s *Status) {
			s.CaddyIP, s.Desired, s.Current = info.IPAddress, desired, current
			s.InSync, s.LastError, s.LastPass = true, "", time.Now()
		})
		return nil
	}

	log.Printf("[bridgedns] drift on %s: %s = %q, want %q (%s at %s); re-applying",
		r.cfg.Bridge, dnsmasqKey, current, desired, r.cfg.CaddyContainer, info.IPAddress)
	r.update(func(s *Status) {
		s.CaddyIP, s.Desired, s.Current = info.IPAddress, desired, current
		s.DriftCount++
	})
	if err := r.be.SetNetworkConfigValue(r.cfg.Bridge, dnsmasqKey, desired); err != nil {
		return r.fail(fmt.Errorf("bridgedns: write %s.%s: %w", r.cfg.Bridge, dnsmasqKey, err))
	}
	r.update(func(s *Status) {
		s.Current = desired
		s.InSync, s.LastError = true, ""
		s.LastApplied, s.LastPass = time.Now(), time.Now()
	})
	return nil
}
