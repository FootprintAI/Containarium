// Package sshgate provides bounded, shared admission for backend SSH setup.
package sshgate

import (
	"errors"
	"math"
	"sort"
	"sync"
	"time"
)

// Key identifies the stable backend and its backend-visible source/egress group.
type Key struct{ Backend, Egress string }

// Policy contains explicit operator-profile limits, not inferred jail defaults.
type Policy struct {
	InitialDelay, MaxDelay, Window, LeaseTimeout time.Duration
	Budget, MaxBackends, MaxPending              int
	Jitter                                       float64
}

// Outcome classifies verified setup results; ordinary session closure is absent.
type Outcome uint8

const (
	// SetupSucceeded means SSH authentication/setup completed, not TCP readiness.
	SetupSucceeded Outcome = iota + 1
	// DialRefused means verified TCP refusal before backend SSH could run.
	DialRefused
	// SetupFailed conservatively retains risk for an unclassified setup failure.
	SetupFailed
	// ProxyAuthRejected identifies rejection of the configured proxy credential.
	ProxyAuthRejected
	// ClientAuthRejected retains jail risk without declaring a healthy backend down.
	ClientAuthRejected
)

// Lease binds one admitted setup to its route, incident and absolute deadline.
type Lease struct {
	Key       Key
	ID, Route uint64
	Deadline  time.Time
	Probe     bool
	epoch     uint64
	owner     *Gate
}

// Reason distinguishes admission failures without parsing error messages.
type Reason uint8

const (
	UnknownBackend Reason = iota + 1
	StaleRoute
	InvalidCost
	Cooldown
	ProbeBusy
	BudgetExhausted
	Capacity
)

// Denied describes a prompt rejection and its conservative retry deadline.
type Denied struct {
	Reason  Reason
	RetryAt time.Time
}

// Error satisfies error while leaving Reason as the authoritative discriminator.
func (d *Denied) Error() string { return "backend SSH admission denied" }

// Gate is the process-shared admission controller for trusted registered keys.
type Gate struct {
	mu      sync.Mutex
	policy  Policy
	now     func() time.Time
	random  func() float64
	entries map[Key]*backend
	serial  uint64
}

// charge retains conservative jail risk until its complete rolling window ends.
type charge struct {
	at   time.Time
	cost int
}

// reservation holds the immutable lease and its trusted profile's risk weight.
type reservation struct {
	lease Lease
	cost  int
}

// backend holds bounded setup history across clients, listeners and route changes.
type backend struct {
	route, epoch uint64
	next         time.Time
	delay        time.Duration
	blocked      bool
	probe        uint64
	pending      map[uint64]reservation
	charges      []charge
}

// New validates explicit policy and accepts clock/random hooks for deterministic tests.
func New(p Policy, now func() time.Time, random func() float64) (*Gate, error) {
	if p.InitialDelay <= 0 || p.MaxDelay < p.InitialDelay || p.Window <= 0 || p.LeaseTimeout <= 0 || p.Budget <= 0 || p.MaxBackends <= 0 || p.MaxPending <= 0 || math.IsNaN(p.Jitter) || p.Jitter < 0 || p.Jitter > 1 || (p.Jitter > 0 && random == nil) {
		return nil, errors.New("invalid explicit SSH gate policy")
	}
	if now == nil {
		now = time.Now
	}
	return &Gate{policy: p, now: now, random: random, entries: make(map[Key]*backend)}, nil
}

// Register adds trusted inventory or updates a monotonically increasing route.
func (g *Gate) Register(key Key, route uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if key.Backend == "" || key.Egress == "" || route == 0 {
		return errors.New("canonical backend/egress and positive route generation required")
	}
	if e := g.entries[key]; e != nil {
		if route < e.route {
			return &Denied{Reason: StaleRoute}
		}
		if route > e.route {
			e.route = route
			e.epoch++
		}
		return nil
	}
	if len(g.entries) >= g.policy.MaxBackends {
		return &Denied{Reason: Capacity}
	}
	g.entries[key] = &backend{route: route, pending: make(map[uint64]reservation)}
	return nil
}

// Acquire reserves weighted setup risk and, during recovery, the single probe.
func (g *Gate) Acquire(key Key, route uint64, cost int) (Lease, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entries[key]
	if e == nil {
		return Lease{}, &Denied{Reason: UnknownBackend}
	}
	if route != e.route {
		return Lease{}, &Denied{Reason: StaleRoute}
	}
	if cost <= 0 || cost > g.policy.Budget {
		return Lease{}, &Denied{Reason: InvalidCost}
	}
	now := g.now()
	g.reap(e, now)
	if e.probe != 0 {
		return Lease{}, &Denied{Reason: ProbeBusy, RetryAt: e.pending[e.probe].lease.Deadline}
	}
	if e.blocked && now.Before(e.next) {
		return Lease{}, &Denied{Reason: Cooldown, RetryAt: e.next}
	}
	if len(e.pending) >= g.policy.MaxPending {
		var retry time.Time
		for _, r := range e.pending {
			if retry.IsZero() || r.lease.Deadline.Before(retry) {
				retry = r.lease.Deadline
			}
		}
		return Lease{}, &Denied{Reason: Capacity, RetryAt: retry}
	}
	used := 0
	for _, c := range e.charges {
		used += c.cost
	}
	for _, r := range e.pending {
		used += r.cost
	}
	if used > g.policy.Budget-cost {
		return Lease{}, &Denied{Reason: BudgetExhausted, RetryAt: g.budgetRetry(e, cost-(g.policy.Budget-used))}
	}
	if g.serial == ^uint64(0) {
		return Lease{}, &Denied{Reason: Capacity}
	}
	g.serial++
	l := Lease{Key: key, ID: g.serial, Route: route, Deadline: now.Add(g.policy.LeaseTimeout), Probe: e.blocked, epoch: e.epoch, owner: g}
	e.pending[l.ID] = reservation{lease: l, cost: cost}
	if l.Probe {
		e.probe = l.ID
	}
	return l, nil
}

// Complete settles exactly one verified lease outcome, ignoring stale callbacks.
func (g *Gate) Complete(l Lease, outcome Outcome) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if outcome < SetupSucceeded || outcome > ClientAuthRejected {
		return false
	}
	e := g.entries[l.Key]
	if e == nil {
		return false
	}
	now := g.now()
	g.reap(e, now)
	r, ok := e.pending[l.ID]
	if !ok || r.lease != l {
		return false
	}
	delete(e.pending, l.ID)
	if outcome == SetupFailed || outcome == ProxyAuthRejected || outcome == ClientAuthRejected {
		e.charges = append(e.charges, charge{at: now, cost: r.cost})
	}
	if outcome == ClientAuthRejected && !l.Probe {
		return true
	}
	g.settle(e, r, outcome == SetupSucceeded, now)
	return true
}

// HintRecovery advances a cooldown deadline without granting budget or a lease.
func (g *Gate) HintRecovery(key Key, route uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entries[key]
	if e == nil || route != e.route {
		return false
	}
	now := g.now()
	g.reap(e, now)
	if !e.blocked || e.probe != 0 {
		return false
	}
	e.next = now
	return true
}

// Forget removes idle inventory only after all reservations/history have drained.
func (g *Gate) Forget(key Key, route uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entries[key]
	if e == nil || route != e.route {
		return false
	}
	now := g.now()
	g.reap(e, now)
	if len(e.pending) != 0 || len(e.charges) != 0 || (e.blocked && now.Before(e.next)) {
		return false
	}
	delete(g.entries, key)
	return true
}

// reap expires setup leases conservatively and drops elapsed jail-risk records.
func (g *Gate) reap(e *backend, now time.Time) {
	for id, r := range e.pending {
		if !now.Before(r.lease.Deadline) {
			delete(e.pending, id)
			e.charges = append(e.charges, charge{at: r.lease.Deadline, cost: r.cost})
			g.settle(e, r, false, r.lease.Deadline)
		}
	}
	live := e.charges[:0]
	for _, c := range e.charges {
		if now.Before(c.at.Add(g.policy.Window)) {
			live = append(live, c)
		}
	}
	e.charges = live
}

// settle changes outage state only for the current route and incident epoch.
func (g *Gate) settle(e *backend, r reservation, success bool, at time.Time) {
	if e.probe == r.lease.ID {
		e.probe = 0
	}
	if r.lease.Route != e.route || r.lease.epoch != e.epoch {
		return
	}
	if success {
		if r.lease.Probe {
			e.blocked, e.delay, e.next = false, 0, time.Time{}
			e.epoch++
		}
		return
	}
	e.blocked = true
	e.epoch++
	if e.delay == 0 {
		e.delay = g.policy.InitialDelay
	} else if e.delay >= g.policy.MaxDelay-e.delay {
		e.delay = g.policy.MaxDelay
	} else {
		e.delay *= 2
	}
	delay := e.delay
	if g.policy.Jitter > 0 {
		sample := g.random()
		if math.IsNaN(sample) || sample < 0 {
			sample = 0
		} else if sample > 1 {
			sample = 1
		}
		extra := float64(delay) * g.policy.Jitter * sample
		if extra >= float64(g.policy.MaxDelay-delay) {
			delay = g.policy.MaxDelay
		} else {
			delay += time.Duration(extra)
		}
	}
	e.next = at.Add(delay)
}

// budgetRetry computes weighted releases, conservatively assuming pending timeout.
func (g *Gate) budgetRetry(e *backend, needed int) time.Time {
	events := make([]charge, 0, len(e.charges)+len(e.pending))
	for _, c := range e.charges {
		events = append(events, charge{at: c.at.Add(g.policy.Window), cost: c.cost})
	}
	for _, r := range e.pending {
		events = append(events, charge{at: r.lease.Deadline.Add(g.policy.Window), cost: r.cost})
	}
	sort.Slice(events, func(i, j int) bool { return events[i].at.Before(events[j].at) })
	for _, event := range events {
		needed -= event.cost
		if needed <= 0 {
			return event.at
		}
	}
	return time.Time{}
}
