//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// #3326: a shared late-install helper for Postgres-backed store families.
// With Postgres down at startup a registered family is NOT_SERVING; the
// helper owns ONE pool and ONE backoff loop for every pending family, retries
// each family's install until it succeeds (then never again), swaps the store
// in atomically, turns the family SERVING, and holds the opt-in self-restart
// watcher (#2824) while anything is still pending. No daemon restart.

// fakeStore is the store type a fake family serves through its slot.
type fakeStore struct{ name string }

// fakeFamily is a registered family under test: a slot holding a stand-in,
// an install that fails `failures` times before swapping the durable store
// in, and a record of every pool it was handed.
type fakeFamily struct {
	mu       sync.Mutex
	slot     *storeSlot[*fakeStore]
	failures int
	installs int
	pools    []*pgxpool.Pool
}

func newFakeFamily(failures int) *fakeFamily {
	return &fakeFamily{slot: newStoreSlot(&fakeStore{name: "stand-in"}), failures: failures}
}

func (f *fakeFamily) open(_ context.Context, pool *pgxpool.Pool) (*fakeStore, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installs++
	f.pools = append(f.pools, pool)
	if f.installs <= f.failures {
		return nil, fmt.Errorf("create table: attempt %d failed", f.installs)
	}
	return &fakeStore{name: "durable"}, nil
}

func (f *fakeFamily) family(service string) storeFamily {
	return storeFamily{
		Service: service,
		Display: service + " store",
		Install: installInto(f.slot, f.open),
	}
}

func (f *fakeFamily) installCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.installs
}

func (f *fakeFamily) seenPools() []*pgxpool.Pool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pgxpool.Pool(nil), f.pools...)
}

// fakePostgres is down for the first `downFor` dials, then answers every
// dial with a fresh pool pointer, so a shared pool is distinguishable from a
// re-dial.
type fakePostgres struct {
	mu      sync.Mutex
	downFor int
	dials   int
}

func (p *fakePostgres) connect(context.Context) (*pgxpool.Pool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dials++
	if p.dials <= p.downFor {
		return nil, errors.New("dial tcp: connection refused")
	}
	return new(pgxpool.Pool), nil
}

func (p *fakePostgres) dialCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dials
}

// readinessRecorder stands in for the policyreadiness registry.
type readinessRecorder struct {
	mu      sync.Mutex
	entries map[string]string
}

func (r *readinessRecorder) publish(service, display string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = map[string]string{}
	}
	r.entries[service] = display
}

type storeRecoveryFixture struct {
	health    *health.Server
	clock     *retryClock
	logs      *retryLogSink
	pg        *fakePostgres
	readiness *readinessRecorder
	r         *storeRecovery
	ctx       context.Context
}

func newStoreRecoveryFixture(t *testing.T, pg *fakePostgres) *storeRecoveryFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &storeRecoveryFixture{
		health:    health.NewServer(),
		clock:     &retryClock{cancel: cancel},
		logs:      &retryLogSink{},
		pg:        pg,
		readiness: &readinessRecorder{},
		ctx:       ctx,
	}
	f.r = newStoreRecovery(f.health, func() string { return "postgres://unused" })
	f.r.after = f.clock.after
	f.r.logf = f.logs.logf
	f.r.connect = pg.connect
	f.r.publish = f.readiness.publish
	return f
}

func (f *storeRecoveryFixture) status(t *testing.T, svc string) healthpb.HealthCheckResponse_ServingStatus {
	t.Helper()
	resp, err := f.health.Check(context.Background(), &healthpb.HealthCheckRequest{Service: svc})
	if err != nil {
		t.Fatalf("health.Check(%s): %v", svc, err)
	}
	return resp.GetStatus()
}

// runToCompletion runs the loop and fails the test if it does not return.
func (f *storeRecoveryFixture) runToCompletion(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	done := make(chan struct{})
	go func() { f.r.Run(f.ctx, pool); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after every family was installed")
	}
}

// AC1: Postgres down then up; a registered family goes NOT_SERVING ->
// SERVING with no restart; its install is retried with backoff and, once it
// succeeds, never runs again.
func TestStoreRecovery_FamilyRecoversWithBackoffAndInstallsOnce(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 2})
	fam := newFakeFamily(1) // first install over the live pool fails, second succeeds
	f.r.Register(fam.family("containarium.fake_family"))

	if got := f.status(t, "containarium.fake_family"); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness before recovery = %v, want NOT_SERVING", got)
	}
	if st := fam.slot.Load(); st.name != "stand-in" {
		t.Fatalf("slot before recovery = %q, want the stand-in", st.name)
	}
	if !f.r.pending() {
		t.Fatal("pending() = false with a registered family not installed")
	}

	f.runToCompletion(t, nil)

	// Attempt 1 and 2: dial refused. Attempt 3: dial ok, install fails.
	// Attempt 4: install ok. Backoff 5 s doubling between them.
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second}
	if got := f.clock.recorded(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("waits = %v, want %v", got, want)
	}
	if n := f.pg.dialCount(); n != 3 {
		t.Errorf("dials = %d, want 3 (one per attempt until Postgres answered, none after)", n)
	}
	if n := fam.installCount(); n != 2 {
		t.Errorf("install ran %d times, want 2 (retried once, then never again)", n)
	}
	if got := f.status(t, "containarium.fake_family"); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("readiness after recovery = %v, want SERVING", got)
	}
	if st := fam.slot.Load(); st.name != "durable" {
		t.Errorf("slot after recovery = %q, want the durable store swapped in", st.name)
	}
	if f.r.pending() {
		t.Error("pending() = true after every family was installed")
	}
	logs := f.logs.all()
	if len(logs) < 3 || !strings.Contains(logs[0], "connection refused") || !strings.Contains(logs[0], "10s") {
		t.Errorf("logs = %q, want one line per failed attempt naming the error and the next interval", logs)
	}
	if last := logs[len(logs)-1]; !strings.Contains(last, "containarium.fake_family") || !strings.Contains(last, "recovered") {
		t.Errorf("last log = %q, want the recovered family named", last)
	}
}

// AC2: two registered families share one pool and one retry loop: a single
// dial per attempt while Postgres is down, none once the pool is open, and
// both installs see the same pool.
func TestStoreRecovery_TwoFamiliesShareOnePoolAndOneDial(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 1})
	a := newFakeFamily(1) // attempt 2: fail, attempt 3: ok
	b := newFakeFamily(2) // attempt 2: fail, attempt 3: fail, attempt 4: ok
	f.r.Register(a.family("containarium.fake_a"))
	f.r.Register(b.family("containarium.fake_b"))

	f.runToCompletion(t, nil)

	if n := f.pg.dialCount(); n != 2 {
		t.Fatalf("dials = %d, want 2 (one refused, one that opened the shared pool)", n)
	}
	if n := len(f.clock.recorded()); n != 4 {
		t.Fatalf("attempts = %d, want 4 (one loop drives both families)", n)
	}
	if got, want := a.installCount(), 2; got != want {
		t.Errorf("family a install ran %d times, want %d (not re-run after it succeeded)", got, want)
	}
	if got, want := b.installCount(), 3; got != want {
		t.Errorf("family b install ran %d times, want %d", got, want)
	}
	pools := append(a.seenPools(), b.seenPools()...)
	for i, p := range pools {
		if p == nil || p != pools[0] {
			t.Fatalf("install %d got pool %p, want every install to share pool %p", i, p, pools[0])
		}
	}
	for _, svc := range []string{"containarium.fake_a", "containarium.fake_b"} {
		if got := f.status(t, svc); got != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("readiness(%s) = %v, want SERVING", svc, got)
		}
	}
	// Per-family progress is visible in the log: one pending line per failed
	// attempt (three), and after attempt 3 only b is still pending.
	var pendingLines []string
	for _, l := range f.logs.all() {
		if strings.Contains(l, "pending in-process recovery") {
			pendingLines = append(pendingLines, l)
		}
	}
	if len(pendingLines) != 3 {
		t.Fatalf("pending log lines = %d, want 3 (one per failed attempt):\n%s", len(pendingLines), strings.Join(pendingLines, "\n"))
	}
	if l := pendingLines[2]; !strings.Contains(l, "containarium.fake_b") || strings.Contains(l, "containarium.fake_a") {
		t.Errorf("pending line after attempt 3 = %q, want only family b named", l)
	}
}

// AC3: the opt-in self-restart watcher does not fire while a registered
// family is pending; once nothing is pending it is the fallback again for
// families that do not recover in-process.
func TestStoreRecovery_HoldsSelfRestartWhileFamilyPending(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	fam := newFakeFamily(0)
	f.r.Register(fam.family("containarium.fake_family"))

	clk := &pgFakeClock{t: time.Unix(0, 0)}
	pinger := &pgScriptedPinger{script: []error{nil}} // Postgres answers every ping
	w := newTestPGWatcher(clk, pinger, 0)
	w.holdWhile = f.r.pending

	// Postgres is back and the flap guard is satisfied, but the family is
	// still pending: the watcher must keep waiting instead of restarting.
	ctx, cancel := context.WithCancel(context.Background())
	pings := 0
	w.ping = func(c context.Context) error {
		pings++
		if pings == 10 {
			cancel()
		}
		return pinger.ping(c)
	}
	if w.run(ctx) {
		t.Fatal("watcher decided to restart while a registered family was pending")
	}
	if pings < 10 {
		t.Fatalf("watcher stopped after %d pings without a restart decision or a cancel", pings)
	}

	// The family installs in-process; with nothing pending the watcher is
	// free to restart for the families that still need it.
	f.runToCompletion(t, nil)
	if f.r.pending() {
		t.Fatal("pending() = true after the family installed")
	}
	if !w.run(context.Background()) {
		t.Fatal("watcher did not restart once no family was pending")
	}
}

// A family installed at startup is registered SERVING and never retried; a
// pending family handed the startup pool is installed over it without a
// dial; readiness entries are published to the registry; with nothing
// pending, Run returns without waiting.
func TestStoreRecovery_RegistryAndStartupPool(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	ready := newFakeFamily(0)
	f.r.RegisterInstalled(ready.family("containarium.fake_ready"))
	if got := f.status(t, "containarium.fake_ready"); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness of a startup-installed family = %v, want SERVING", got)
	}
	if f.r.pending() {
		t.Fatal("pending() = true with only an installed family registered")
	}
	f.r.Run(f.ctx, nil)
	if n := len(f.clock.recorded()); n != 0 {
		t.Fatalf("waits = %d with nothing pending, want 0", n)
	}
	if n := ready.installCount(); n != 0 {
		t.Fatalf("installed family's install ran %d times, want 0", n)
	}

	late := newFakeFamily(0)
	f.r.Register(late.family("containarium.fake_late"))
	startupPool := new(pgxpool.Pool)
	f.runToCompletion(t, startupPool)
	if n := f.pg.dialCount(); n != 0 {
		t.Errorf("dials = %d, want 0 (the startup pool is reused)", n)
	}
	if pools := late.seenPools(); len(pools) != 1 || pools[0] != startupPool {
		t.Errorf("late family installed over %v, want the startup pool %p", pools, startupPool)
	}
	if got := f.status(t, "containarium.fake_late"); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("readiness(late) = %v, want SERVING", got)
	}

	want := map[string]string{
		"containarium.fake_ready": "containarium.fake_ready store",
		"containarium.fake_late":  "containarium.fake_late store",
	}
	f.readiness.mu.Lock()
	defer f.readiness.mu.Unlock()
	if fmt.Sprint(f.readiness.entries) != fmt.Sprint(want) {
		t.Errorf("readiness registry = %v, want %v", f.readiness.entries, want)
	}
}

// Registering the same service twice is a programming error in startup
// wiring, caught at once rather than by two loops installing one store.
func TestStoreRecovery_DuplicateServicePanics(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	fam := newFakeFamily(0)
	f.r.Register(fam.family("containarium.fake_family"))
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("registering the same service twice did not panic")
		}
	}()
	f.r.Register(fam.family("containarium.fake_family"))
}

// The production constructor wires the real registry and the real dial.
func TestNewStoreRecovery_Defaults(t *testing.T) {
	r := newStoreRecovery(health.NewServer(), func() string { return "postgres://unused" })
	if r.connect == nil || r.publish == nil || r.after == nil || r.logf == nil {
		t.Fatal("newStoreRecovery left a hook nil")
	}
	if r.initial != policyStoreRetryInitial || r.max != policyStoreRetryMax {
		t.Errorf("backoff = %s..%s, want the #2483 cadence %s..%s", r.initial, r.max, policyStoreRetryInitial, policyStoreRetryMax)
	}
}
