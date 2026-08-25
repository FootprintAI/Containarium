package pool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sandbox/ipam"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeBackend is the pool.Backend test double — the "Incus layer" the
// design note's own test list calls for, fast and deterministic, no host.
type fakeBackend struct {
	mu sync.Mutex

	created []string
	started []string
	stopped []string
	deleted []string

	// createErr, when set, is returned by CreateContainer for names
	// matching failFor (empty failFor = fail every create).
	createErr error
	failFor   map[string]bool // nil = fail everything if createErr != nil

	// gate, if non-nil, blocks CreateContainer until closed — lets a test
	// observe a member mid-warm before it becomes ready.
	gate chan struct{}
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{}
}

func (b *fakeBackend) CreateContainer(config incus.ContainerConfig) error {
	if b.gate != nil {
		<-b.gate
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.createErr != nil && (b.failFor == nil || b.failFor[config.Name]) {
		return b.createErr
	}
	b.created = append(b.created, config.Name)
	return nil
}

func (b *fakeBackend) StartContainer(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.started = append(b.started, name)
	return nil
}

func (b *fakeBackend) StopContainer(name string, _ bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = append(b.stopped, name)
	return nil
}

func (b *fakeBackend) DeleteContainer(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deleted = append(b.deleted, name)
	return nil
}

func (b *fakeBackend) deleteCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.deleted)
}

func testAllocator(t *testing.T) *ipam.Allocator {
	t.Helper()
	a, err := ipam.New("10.100.0.10", "10.100.0.250", "10.100.0.1", 0)
	if err != nil {
		t.Fatalf("ipam.New: %v", err)
	}
	return a
}

func testConfig(minWarm int) Config {
	return Config{
		MinWarm:    map[pb.SandboxTemplate]int{pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE: minWarm},
		Image:      map[pb.SandboxTemplate]string{pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE: "images:ubuntu/24.04"},
		NICNetwork: "incusbr0",
	}
}

// ---- Claim -----------------------------------------------------------

func TestClaim_EmptyPoolReturnsErrPoolExhausted(t *testing.T) {
	p := New(newFakeBackend(), testAllocator(t), testConfig(0))

	_, err := p.Claim(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE)
	if !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("Claim on empty pool = %v, want ErrPoolExhausted", err)
	}
}

func TestClaim_OneReadyMemberClaimedAndRemoved(t *testing.T) {
	backend := newFakeBackend()
	p := New(backend, testAllocator(t), testConfig(1))

	p.Reconcile(context.Background())
	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 1 {
		t.Fatalf("ReadyCount after warming to 1 = %d, want 1", got)
	}

	m, err := p.Claim(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if m.ID == "" || m.IP == "" {
		t.Errorf("claimed member incomplete: %+v", m)
	}
	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 0 {
		t.Errorf("ReadyCount after claiming the only member = %d, want 0", got)
	}

	if _, err := p.Claim(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("second Claim = %v, want ErrPoolExhausted", err)
	}
}

// TestClaim_ConcurrentClaimsEachMemberExactlyOnce pins the design note's
// own test requirement, run under -race with 100 goroutines against a
// pool of exactly 100 ready members.
func TestClaim_ConcurrentClaimsEachMemberExactlyOnce(t *testing.T) {
	const n = 100
	backend := newFakeBackend()
	p := New(backend, testAllocator(t), testConfig(n))
	p.Reconcile(context.Background())
	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != n {
		t.Fatalf("ReadyCount after warming = %d, want %d", got, n)
	}

	var wg sync.WaitGroup
	claimed := make([]*Member, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			claimed[i], errs[i] = p.Claim(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE)
		}(i)
	}
	wg.Wait()

	seen := make(map[string]int, n)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
		seen[claimed[i].ID]++
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct members claimed, want %d", len(seen), n)
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("member %s claimed %d times", id, count)
		}
	}
	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 0 {
		t.Errorf("ReadyCount after claiming everything = %d, want 0", got)
	}
}

// TestClaimDuringReconcile_NoTornState hammers Claim and Reconcile
// concurrently (run with -race) — the requirement is no data race and no
// double-claim, not any particular interleaving outcome.
func TestClaimDuringReconcile_NoTornState(t *testing.T) {
	backend := newFakeBackend()
	// A generous range: this test's claim loop never Releases what it
	// claims (by design — it's only checking for torn state, not
	// exercising the release path), so claimed addresses are gone for
	// good for the test's duration. A small range would legitimately
	// exhaust under the stress loop's address churn and spam the log
	// with "address range exhausted" — noise, not a bug.
	allocator, err := ipam.New("10.100.0.1", "10.100.255.254", "10.101.0.1", 0)
	if err != nil {
		t.Fatalf("ipam.New: %v", err)
	}
	p := New(backend, allocator, testConfig(20))

	var wg sync.WaitGroup
	stop := make(chan struct{})
	claimedIDs := make(chan string, 10000)

	// Reconcile loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				p.Reconcile(context.Background())
			}
		}
	}()

	// Claim loop, several concurrent claimers.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if m, err := p.Claim(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); err == nil {
						claimedIDs <- m.ID
					}
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	close(claimedIDs)

	seen := make(map[string]bool)
	for id := range claimedIDs {
		if seen[id] {
			t.Fatalf("member %s claimed more than once — torn state under concurrent Claim/Reconcile", id)
		}
		seen[id] = true
	}
}

// ---- Reconcile ---------------------------------------------------------

func TestReconcile_BelowMinWarmWarmsTheDifference(t *testing.T) {
	backend := newFakeBackend()
	p := New(backend, testAllocator(t), testConfig(3))

	p.Reconcile(context.Background())

	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 3 {
		t.Fatalf("ReadyCount = %d, want 3", got)
	}
	backend.mu.Lock()
	gotCreated, gotStarted := len(backend.created), len(backend.started)
	backend.mu.Unlock()
	if gotCreated != 3 || gotStarted != 3 {
		t.Errorf("created=%d started=%d, want 3/3", gotCreated, gotStarted)
	}

	// A second Reconcile at the same target is a no-op — already at
	// min_warm, nothing more to warm.
	p.Reconcile(context.Background())
	backend.mu.Lock()
	gotCreated2 := len(backend.created)
	backend.mu.Unlock()
	if gotCreated2 != 3 {
		t.Errorf("created after a second Reconcile at steady state = %d, want still 3", gotCreated2)
	}
}

func TestReconcile_AboveMinWarmTrimsIdle(t *testing.T) {
	backend := newFakeBackend()
	p := New(backend, testAllocator(t), testConfig(5))
	p.Reconcile(context.Background())
	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 5 {
		t.Fatalf("ReadyCount after warming to 5 = %d, want 5", got)
	}

	// Lower the target and reconcile again — the pool must trim down to
	// the new target, destroying the excess.
	p.cfg.MinWarm[pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE] = 2
	p.Reconcile(context.Background())

	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 2 {
		t.Fatalf("ReadyCount after trimming to 2 = %d, want 2", got)
	}
	if got := backend.deleteCount(); got != 3 {
		t.Errorf("deleted %d members, want exactly the 3 trimmed", got)
	}
}

// TestReconcile_WarmingMemberNeverEntersReadyRing gates CreateContainer so
// a warm is provably still in flight, and checks ReadyCount is 0 for the
// entire time the gate is held closed.
func TestReconcile_WarmingMemberNeverEntersReadyRing(t *testing.T) {
	backend := newFakeBackend()
	backend.gate = make(chan struct{})
	p := New(backend, testAllocator(t), testConfig(1))

	done := make(chan struct{})
	go func() {
		p.Reconcile(context.Background())
		close(done)
	}()

	// The warm is blocked on backend.gate — give the goroutine a moment to
	// actually reach CreateContainer, then assert it hasn't shown up ready.
	time.Sleep(50 * time.Millisecond)
	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 0 {
		t.Fatalf("ReadyCount while warm is still gated = %d, want 0 (a WARMING member must not be claimable)", got)
	}
	if _, err := p.Claim(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("Claim while warm is still gated = %v, want ErrPoolExhausted", err)
	}

	close(backend.gate)
	<-done

	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 1 {
		t.Errorf("ReadyCount after the gated warm completed = %d, want 1", got)
	}
}

// TestReconcile_FailedWarmRetriedNextTick_DoesNotWedgeReconciler pins two
// requirements at once: a failed warm doesn't block reconciling other
// templates in the SAME tick, and is simply retried by the NEXT tick
// rather than needing any per-member retry state.
func TestReconcile_FailedWarmRetriedNextTick_DoesNotWedgeReconciler(t *testing.T) {
	backend := newFakeBackend()
	backend.createErr = errors.New("incus: simulated create failure")

	p := New(backend, testAllocator(t), testConfig(2))
	p.Reconcile(context.Background())

	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 0 {
		t.Fatalf("ReadyCount after every warm failed = %d, want 0", got)
	}

	// Next tick: the backend recovers. Reconcile must retry the shortfall
	// without any special "unwedge" call — this IS the retry mechanism.
	backend.mu.Lock()
	backend.createErr = nil
	backend.mu.Unlock()
	p.Reconcile(context.Background())

	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 2 {
		t.Fatalf("ReadyCount after the retrying tick = %d, want 2", got)
	}
}

// TestReconcile_OneTemplateFailingDoesNotBlockAnother is the "does not
// wedge the reconciler" half of the same requirement, from the angle of
// two templates reconciled in the same call.
func TestReconcile_OneTemplateFailingDoesNotBlockAnother(t *testing.T) {
	const goodTemplate = pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE
	const badTemplate = pb.SandboxTemplate(99) // no image configured -> every warm fails fast

	backend := newFakeBackend()
	p := New(backend, testAllocator(t), Config{
		MinWarm:    map[pb.SandboxTemplate]int{goodTemplate: 3, badTemplate: 3},
		Image:      map[pb.SandboxTemplate]string{goodTemplate: "images:ubuntu/24.04"}, // badTemplate deliberately has none
		NICNetwork: "incusbr0",
	})

	p.Reconcile(context.Background())

	if got := p.ReadyCount(goodTemplate); got != 3 {
		t.Errorf("good template ReadyCount = %d, want 3 (must not be blocked by the other template's failures)", got)
	}
	if got := p.ReadyCount(badTemplate); got != 0 {
		t.Errorf("bad template ReadyCount = %d, want 0", got)
	}
}

// ---- Release / isolation ------------------------------------------------

// TestDestroyOnRelease is the executable form of the design note's
// isolation argument: a released member is destroyed, never returned to
// the ready ring. This test's job is to fail loudly if anyone ever adds
// a reset-and-reuse path to Release.
func TestDestroyOnRelease(t *testing.T) {
	backend := newFakeBackend()
	p := New(backend, testAllocator(t), testConfig(1))
	p.Reconcile(context.Background())

	m, err := p.Claim(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	if err := p.Release(m); err != nil {
		t.Fatalf("Release: %v", err)
	}

	backend.mu.Lock()
	deleted := append([]string(nil), backend.deleted...)
	backend.mu.Unlock()
	if len(deleted) != 1 || deleted[0] != m.ID {
		t.Fatalf("deleted = %v, want exactly [%s]", deleted, m.ID)
	}
	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 0 {
		t.Fatalf("ReadyCount after Release = %d, want 0 (released member must NOT reappear in the ring)", got)
	}
}

func TestRelease_PropagatesDeleteFailure(t *testing.T) {
	backend := newFakeBackend()
	p := New(backend, testAllocator(t), testConfig(1))
	p.Reconcile(context.Background())
	m, err := p.Claim(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	// Swap in a backend whose DeleteContainer always fails, to prove
	// Release surfaces it rather than swallowing it (unlike the
	// reconciler's own best-effort trim).
	failing := &deleteFailingBackend{fakeBackend: backend, err: errors.New("incus: instance busy")}
	p.backend = failing

	if err := p.Release(m); err == nil {
		t.Fatal("Release should surface a real DeleteContainer failure")
	}
}

type deleteFailingBackend struct {
	*fakeBackend
	err error
}

func (b *deleteFailingBackend) DeleteContainer(name string) error {
	_ = b.fakeBackend.DeleteContainer(name)
	return b.err
}

// ---- misc ---------------------------------------------------------------

func TestNew_DoesNotRetainCallersConfigMaps(t *testing.T) {
	cfg := testConfig(1)
	p := New(newFakeBackend(), testAllocator(t), cfg)

	cfg.MinWarm[pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE] = 999
	if p.cfg.MinWarm[pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE] != 1 {
		t.Errorf("Pool's config was mutated by changing the caller's map after New — New must copy")
	}
}

func TestMember_TypedNotStringlyTyped(t *testing.T) {
	// Compile-time-flavored check that Member is a real struct, not
	// map[string]string — this test exists mostly so a future refactor
	// toward the wrong shape breaks a test, not just a code review.
	m := Member{
		ID:       "sandbox-abc123",
		Template: pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE,
		IP:       "10.100.0.10",
		WarmedAt: time.Now(),
	}
	if m.Template != pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE {
		t.Fatal("unreachable")
	}
	_ = fmt.Sprintf("%+v", m)
}

// ---- Status ---------------------------------------------------------

// TestStatus_ReportsReadyWarmingAndMinWarm exercises all three
// TemplateStatus fields at once: MinWarm=3, only 2 warmed so far because
// the third is gated mid-warm — so Ready must be 2 and Warming must be 1,
// not e.g. Ready=3 (which would mean a still-warming member leaked into
// the ready count Status reports) or Warming=0 (which would mean Status
// missed in-flight work entirely).
func TestStatus_ReportsReadyWarmingAndMinWarm(t *testing.T) {
	backend := newFakeBackend()
	backend.gate = make(chan struct{})
	p := New(backend, testAllocator(t), testConfig(3))

	done := make(chan struct{})
	go func() {
		p.Reconcile(context.Background())
		close(done)
	}()

	// Let 2 of the 3 warms clear the gate, then re-close it so the 3rd
	// stays wedged — fakeBackend's gate is read-once-per-call inside
	// CreateContainer (see newFakeBackend's doc comment / usage above),
	// so signal exactly twice.
	backend.gate <- struct{}{}
	backend.gate <- struct{}{}
	// Give the two released warms a moment to finish and update the ring
	// before asserting — Status must not race a still-settling Reconcile.
	deadline := time.Now().Add(2 * time.Second)
	for p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	statuses := p.Status()
	if len(statuses) != 1 {
		t.Fatalf("Status() returned %d entries, want 1 (one configured template)", len(statuses))
	}
	st := statuses[0]
	if st.Template != pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE {
		t.Errorf("Template = %v, want BASE", st.Template)
	}
	if st.MinWarm != 3 {
		t.Errorf("MinWarm = %d, want 3 (the configured floor)", st.MinWarm)
	}
	if st.Ready != 2 {
		t.Errorf("Ready = %d, want 2", st.Ready)
	}
	if st.Warming != 1 {
		t.Errorf("Warming = %d, want 1 (the still-gated 3rd member)", st.Warming)
	}

	close(backend.gate)
	<-done
}

// TestStatus_UnconfiguredTemplateReportsZeroesNotOmitted pins that Status
// still reports a template present in Config.MinWarm even when nothing
// has been reconciled yet — an operator diagnosing "why is my pool empty"
// needs zero counts against the configured floor, not an empty list that
// looks identical to "no pool configured at all".
func TestStatus_UnconfiguredTemplateReportsZeroesNotOmitted(t *testing.T) {
	p := New(newFakeBackend(), testAllocator(t), testConfig(5))

	statuses := p.Status()
	if len(statuses) != 1 {
		t.Fatalf("Status() returned %d entries, want 1", len(statuses))
	}
	if got := statuses[0]; got.Ready != 0 || got.Warming != 0 || got.MinWarm != 5 {
		t.Errorf("Status() before any Reconcile = %+v, want Ready=0 Warming=0 MinWarm=5", got)
	}
}

// TestStatus_NoConfiguredTemplatesReturnsEmpty pins the other end: a pool
// with an empty Config.MinWarm (the "pool exists but warms nothing"
// shape SpawnSandbox's own tests already use for pool-exhausted cases)
// reports no entries at all, not a spurious BASE row.
func TestStatus_NoConfiguredTemplatesReturnsEmpty(t *testing.T) {
	p := New(newFakeBackend(), testAllocator(t), Config{})
	if statuses := p.Status(); len(statuses) != 0 {
		t.Errorf("Status() on an unconfigured pool = %+v, want empty", statuses)
	}
}
