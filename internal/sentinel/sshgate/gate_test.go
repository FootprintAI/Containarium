package sshgate

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gateFixture owns a deterministic clock and a single registered backend.
type gateFixture struct {
	g   *Gate
	now time.Time
	key Key
}

// newGateFixture supplies explicit synthetic limits, unrelated to production defaults.
func newGateFixture(t *testing.T, change ...func(*Policy)) *gateFixture {
	t.Helper()
	f := &gateFixture{now: time.Unix(1000, 0), key: Key{"backend-a", "egress-a"}}
	p := Policy{InitialDelay: time.Second, MaxDelay: 8 * time.Second, Window: time.Minute, LeaseTimeout: 5 * time.Second, Budget: 8, MaxBackends: 2, MaxPending: 8}
	for _, apply := range change {
		apply(&p)
	}
	var err error
	f.g, err = New(p, func() time.Time { return f.now }, func() float64 { return 0.5 })
	if err != nil {
		t.Fatal(err)
	}
	if err := f.g.Register(f.key, 1); err != nil {
		t.Fatal(err)
	}
	return f
}

// take requires admission without reaching into the controller's internal state.
func (f *gateFixture) take(t *testing.T, cost int) Lease {
	t.Helper()
	l, err := f.g.Acquire(f.key, 1, cost)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// denied checks typed failure and exposes the reported retry boundary.
func denied(t *testing.T, g *Gate, key Key, route uint64, cost int, reason Reason) *Denied {
	t.Helper()
	_, err := g.Acquire(key, route, cost)
	var d *Denied
	if !errors.As(err, &d) || d.Reason != reason {
		t.Fatalf("reason=%v, error=%v; want %v", d, err, reason)
	}
	return d
}

// TestGateBackoffAndSSHProbe preserves one probe and ignores an old healthy setup.
func TestGateBackoffAndSSHProbe(t *testing.T) {
	f := newGateFixture(t)
	first, old := f.take(t, 1), f.take(t, 1)
	if !f.g.Complete(first, DialRefused) || !f.g.Complete(old, SetupSucceeded) {
		t.Fatal("normal setup completion rejected")
	}
	for _, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second} {
		d := denied(t, f.g, f.key, 1, 1, Cooldown)
		if d.RetryAt.Sub(f.now) != delay {
			t.Fatalf("delay=%s want %s", d.RetryAt.Sub(f.now), delay)
		}
		f.now = d.RetryAt
		probe := f.take(t, 1)
		if !probe.Probe {
			t.Fatal("recovery admission is not a probe")
		}
		denied(t, f.g, f.key, 1, 1, ProbeBusy)
		if !f.g.Complete(probe, DialRefused) {
			t.Fatal("probe failure rejected")
		}
	}
	f.g.HintRecovery(f.key, 1)
	probe := f.take(t, 1)
	// There is deliberately no TCP-ready transition: the lease remains held.
	denied(t, f.g, f.key, 1, 1, ProbeBusy)
	if !f.g.Complete(probe, SetupSucceeded) || f.g.Complete(probe, SetupFailed) {
		t.Fatal("SSH-ready promotion/duplicate result broken")
	}
	if f.take(t, 1).Probe {
		t.Fatal("healthy admission remains a probe")
	}
}

// TestGateBudgetSurvivesRecovery keeps weighted failures through healthy success.
func TestGateBudgetSurvivesRecovery(t *testing.T) {
	f := newGateFixture(t, func(p *Policy) { p.Budget = 3 })
	start := f.now
	f.g.Complete(f.take(t, 1), ProxyAuthRejected)
	f.now = start.Add(time.Second)
	f.g.Complete(f.take(t, 1), SetupSucceeded)
	second := f.take(t, 2)
	denied(t, f.g, f.key, 1, 1, BudgetExhausted)
	f.g.Complete(second, SetupFailed)
	f.now = f.now.Add(10 * time.Second)
	f.g.HintRecovery(f.key, 1)
	d := denied(t, f.g, f.key, 1, 1, BudgetExhausted)
	if !d.RetryAt.Equal(start.Add(time.Minute)) {
		t.Fatalf("budget retry=%v, want first failure window edge", d.RetryAt)
	}
	f.now = d.RetryAt
	f.g.Complete(f.take(t, 1), SetupSucceeded)
	denied(t, f.g, f.key, 1, 2, BudgetExhausted)
	f.now = start.Add(time.Minute + time.Second)
	_ = f.take(t, 2)
}

// TestGateRefusalRefundAndExpiry distinguishes proven refusal from unknown timeout.
func TestGateRefusalRefundAndExpiry(t *testing.T) {
	f := newGateFixture(t, func(p *Policy) { p.Budget = 1 })
	for range 12 {
		l := f.take(t, 1)
		f.g.Complete(l, DialRefused)
		f.g.HintRecovery(f.key, 1)
	}
	lost := f.take(t, 1)
	f.now = lost.Deadline
	denied(t, f.g, f.key, 1, 1, Cooldown)
	if f.g.Complete(lost, SetupSucceeded) {
		t.Fatal("expired setup reopened the gate")
	}
	f.g.HintRecovery(f.key, 1)
	d := denied(t, f.g, f.key, 1, 1, BudgetExhausted)
	if !d.RetryAt.Equal(lost.Deadline.Add(time.Minute)) {
		t.Fatalf("expiry charge must start at setup deadline: %v", d.RetryAt)
	}
	f.now = d.RetryAt
	_ = f.take(t, 1)
}

// TestGateRouteUpdatesRetainBudget prevents a new route from clearing jail history.
func TestGateRouteUpdatesRetainBudget(t *testing.T) {
	f := newGateFixture(t, func(p *Policy) { p.Budget = 2 })
	old := f.take(t, 1)
	f.g.Complete(f.take(t, 1), ProxyAuthRejected)
	if err := f.g.Register(f.key, 2); err != nil {
		t.Fatal(err)
	}
	denied(t, f.g, f.key, 1, 1, StaleRoute)
	if f.g.HintRecovery(f.key, 1) || f.g.Forget(f.key, 2) {
		t.Fatal("stale hint or removal bypassed retained history")
	}
	if !f.g.Complete(old, SetupSucceeded) {
		t.Fatal("old outcome should settle its reservation")
	}
	denied(t, f.g, f.key, 2, 1, Cooldown)
	f.now = f.now.Add(time.Second)
	l, err := f.g.Acquire(f.key, 2, 1)
	if err != nil || !l.Probe {
		t.Fatalf("new generation probe: %v", err)
	}
	f.g.Complete(l, SetupFailed)
	f.g.HintRecovery(f.key, 2)
	denied(t, f.g, f.key, 2, 1, BudgetExhausted)
}

// TestGateStaleProbeRetainsExclusion settles old probes without reopening a route.
func TestGateStaleProbeRetainsExclusion(t *testing.T) {
	f := newGateFixture(t)
	f.g.Complete(f.take(t, 1), DialRefused)
	f.g.HintRecovery(f.key, 1)
	old := f.take(t, 1)
	if err := f.g.Register(f.key, 2); err != nil {
		t.Fatal(err)
	}
	denied(t, f.g, f.key, 2, 1, ProbeBusy)
	if f.g.HintRecovery(f.key, 2) {
		t.Fatal("recovery hint bypassed an active old probe")
	}
	f.g.Complete(old, SetupSucceeded)
	l, err := f.g.Acquire(f.key, 2, 1)
	if err != nil || !l.Probe {
		t.Fatalf("stale success must allow only another probe: %+v %v", l, err)
	}
}

// TestGateRejectsForeignLease binds otherwise identical leases to their controller.
func TestGateRejectsForeignLease(t *testing.T) {
	f, other := newGateFixture(t), newGateFixture(t)
	l, foreign := f.take(t, 1), other.take(t, 1)
	if f.g.Complete(foreign, SetupSucceeded) || !f.g.Complete(l, SetupSucceeded) {
		t.Fatal("a different controller's lease settled this reservation")
	}
}

// TestGateConcurrentAdmissionAndCompletion bounds shared reservations atomically.
func TestGateConcurrentAdmissionAndCompletion(t *testing.T) {
	f := newGateFixture(t, func(p *Policy) { p.Budget = 4 })
	leases := make(chan Lease, 40)
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			if l, err := f.g.Acquire(f.key, 1, 1); err == nil {
				leases <- l
			}
		})
	}
	wg.Wait()
	close(leases)
	if len(leases) != 4 {
		t.Fatalf("admitted %d concurrent setups, want four", len(leases))
	}
	var settled atomic.Int32
	for l := range leases {
		for range 4 {
			wg.Go(func() {
				if f.g.Complete(l, SetupSucceeded) {
					settled.Add(1)
				}
			})
		}
	}
	wg.Wait()
	if settled.Load() != 4 {
		t.Fatal("duplicate completion settled a reservation more than once")
	}
	f.g.Complete(f.take(t, 1), DialRefused)
	f.now = f.now.Add(time.Second)
	var probes atomic.Int32
	for range 40 {
		wg.Go(func() {
			if l, err := f.g.Acquire(f.key, 1, 1); err == nil && l.Probe {
				probes.Add(1)
			}
		})
	}
	wg.Wait()
	if probes.Load() != 1 {
		t.Fatalf("admitted %d recovery probes", probes.Load())
	}
}

// TestGateIsolationCapacityAndTampering retains trusted inventory and lease bounds.
func TestGateIsolationCapacityAndTampering(t *testing.T) {
	f := newGateFixture(t, func(p *Policy) { p.MaxPending = 1 })
	other := Key{"backend-b", "egress-a"}
	denied(t, f.g, other, 1, 1, UnknownBackend)
	if err := f.g.Register(other, 1); err != nil {
		t.Fatal(err)
	}
	if err := f.g.Register(Key{"backend-c", "egress-a"}, 1); err == nil {
		t.Fatal("unbounded backend inventory")
	}
	l := f.take(t, 1)
	denied(t, f.g, f.key, 1, 1, Capacity)
	forged := l
	forged.Deadline = forged.Deadline.Add(time.Second)
	if f.g.Complete(forged, SetupSucceeded) || f.g.Complete(l, Outcome(99)) || f.g.Forget(f.key, 1) {
		t.Fatal("invalid completion or live-lease removal accepted")
	}
	f.g.Complete(l, SetupFailed)
	if _, err := f.g.Acquire(other, 1, 1); err != nil {
		t.Fatal("unhealthy backend suppressed healthy backend")
	}
	if f.g.Forget(f.key, 1) {
		t.Fatal("forgot retained jail risk")
	}
	f.now = f.now.Add(time.Minute)
	if !f.g.Forget(f.key, 1) {
		t.Fatal("expired idle inventory cannot be removed")
	}
}

// TestGateValidationAndJitter rejects undefined policies and caps positive jitter.
func TestGateValidationAndJitter(t *testing.T) {
	valid := Policy{InitialDelay: time.Second, MaxDelay: 2 * time.Second, Window: time.Minute, LeaseTimeout: time.Second, Budget: 1, MaxBackends: 1, MaxPending: 1}
	for _, mutate := range []func(*Policy){
		func(p *Policy) { p.Budget = 0 }, func(p *Policy) { p.Window = 0 },
		func(p *Policy) { p.LeaseTimeout = 0 }, func(p *Policy) { p.MaxBackends = 0 },
		func(p *Policy) { p.MaxPending = 0 }, func(p *Policy) { p.InitialDelay = 0 },
		func(p *Policy) { p.MaxDelay = p.InitialDelay - 1 }, func(p *Policy) { p.Jitter = -1 },
		func(p *Policy) { p.Jitter = math.NaN() }, func(p *Policy) { p.Jitter = 2 },
		func(p *Policy) { p.Jitter = 0.5 },
	} {
		p := valid
		mutate(&p)
		if _, err := New(p, time.Now, nil); err == nil {
			t.Fatalf("accepted invalid policy: %+v", p)
		}
	}
	f := newGateFixture(t, func(p *Policy) { p.Jitter = 0.5; p.MaxDelay = 2 * time.Second })
	if err := f.g.Register(Key{}, 1); err == nil {
		t.Fatal("accepted an empty canonical key")
	}
	if err := f.g.Register(f.key, 0); err == nil {
		t.Fatal("accepted a stale route generation")
	}
	denied(t, f.g, f.key, 1, 0, InvalidCost)
	denied(t, f.g, f.key, 1, 9, InvalidCost)
	for range 4 {
		f.g.Complete(f.take(t, 1), DialRefused)
		d := denied(t, f.g, f.key, 1, 1, Cooldown)
		delay := d.RetryAt.Sub(f.now)
		if delay < time.Second || delay > 2*time.Second || (f.now.Unix() == 1000 && delay == time.Second) {
			t.Fatalf("jitter/cap violated: %s", delay)
		}
		f.now = d.RetryAt
	}
}
