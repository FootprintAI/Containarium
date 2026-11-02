//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/secrets"
	"github.com/footprintai/containarium/internal/tracker"
)

// #3378 (Q9 on #3335): a family whose install is refused by configuration
// (CONTAINARIUM_REQUIRE_ENVELOPE with no KMS, say) stays pending and keeps
// being retried, but it does not hold the opt-in self-restart: a restart is
// what brings the families not yet migrated back, and waiting for a config
// change in-process would keep them off forever. A family whose last attempt
// failed on a connection or open error still holds it. The refusal is a typed
// result (storeConfigRefusal, matched with errors.As), never a string match.

// scriptedFamily is a family whose install returns script[i] on call i and
// nil once the script runs out.
type scriptedFamily struct {
	mu     sync.Mutex
	script []error
	calls  int
}

func (s *scriptedFamily) family(service string) storeFamily {
	return storeFamily{
		Service: service,
		Display: service + " store",
		Install: func(context.Context, *pgxpool.Pool) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			i := s.calls
			s.calls++
			if i < len(s.script) {
				return s.script[i]
			}
			return nil
		},
	}
}

var errFakeKMSMissing = errors.New("fake gate on but no KMS backend is configured")

func fakeRefusal() error { return &storeConfigRefusal{Err: errFakeKMSMissing} }

// errFakeOpen is an ordinary install failure: the open over the pool failed.
var errFakeOpen = errors.New("create table: connection reset by peer")

func (f *storeRecoveryFixture) attemptOnce(t *testing.T) {
	t.Helper()
	f.r.mu.Lock()
	if f.r.pool == nil {
		f.r.pool = new(pgxpool.Pool)
	}
	f.r.mu.Unlock()
	_ = f.r.attempt(f.ctx)
}

func countLines(lines []string, subs ...string) int {
	n := 0
	for _, l := range lines {
		all := true
		for _, s := range subs {
			if !strings.Contains(l, s) {
				all = false
			}
		}
		if all {
			n++
		}
	}
	return n
}

// The refusal type is matched through wrapping, and an ordinary error is not
// a refusal.
func TestStoreConfigRefusal_TypedAndWrapped(t *testing.T) {
	wrapped := fmt.Errorf("install: %w", fakeRefusal())
	if !isStoreConfigRefusal(wrapped) {
		t.Error("a wrapped storeConfigRefusal is not recognised as a config refusal")
	}
	if !errors.Is(wrapped, errFakeKMSMissing) {
		t.Error("storeConfigRefusal does not unwrap to its cause")
	}
	if isStoreConfigRefusal(errFakeOpen) || isStoreConfigRefusal(nil) {
		t.Error("an ordinary error (or nil) is reported as a config refusal")
	}
	if got := fakeRefusal().Error(); got != errFakeKMSMissing.Error() {
		t.Errorf("refusal message = %q, want the cause's message %q", got, errFakeKMSMissing.Error())
	}
}

// A pending family whose last attempt was a config refusal does not hold the
// restart; one whose last attempt failed on an open error, or that has not
// been attempted yet, does. Both stay pending and NOT_SERVING.
func TestStoreConfigRefusal_RefusedFamilyDoesNotHoldRestart(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	refused := &scriptedFamily{script: []error{fakeRefusal(), fakeRefusal(), fakeRefusal()}}
	f.r.Register(refused.family("containarium.fake_refused"))

	if !f.r.holdsRestart() {
		t.Fatal("holdsRestart() = false before any attempt; an unattempted family must hold")
	}
	f.attemptOnce(t)
	if !f.r.pending() {
		t.Fatal("pending() = false after a refused install; the family must stay pending and keep retrying")
	}
	if f.r.holdsRestart() {
		t.Fatal("holdsRestart() = true with only a config-refused family pending")
	}
	if got := f.status(t, "containarium.fake_refused"); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("readiness of a refused family = %v, want NOT_SERVING", got)
	}

	failing := &scriptedFamily{script: []error{errFakeOpen, errFakeOpen, errFakeOpen}}
	f.r.Register(failing.family("containarium.fake_failing"))
	f.attemptOnce(t)
	if !f.r.holdsRestart() {
		t.Fatal("holdsRestart() = false while a family's last attempt failed on an open error")
	}
	if refused.calls != 2 {
		t.Errorf("refused family install ran %d times, want 2 (retries continue after a refusal)", refused.calls)
	}
}

// The watcher, wired to holdsRestart, restarts when only refused families
// are pending and keeps waiting while a connection-failing one is.
func TestStoreConfigRefusal_WatcherNotHeldByRefusal(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	refused := &scriptedFamily{script: []error{fakeRefusal(), fakeRefusal()}}
	f.r.Register(refused.family("containarium.fake_refused"))
	f.attemptOnce(t)

	if !boundedWatcherRun(f.r.holdsRestart) {
		t.Fatal("watcher did not restart with only a config-refused family pending")
	}

	g := newStoreRecoveryFixture(t, &fakePostgres{})
	failing := &scriptedFamily{script: []error{fmt.Errorf("connect to Postgres: %w", errors.New("dial tcp: connection refused"))}}
	g.r.Register(failing.family("containarium.fake_failing"))
	g.attemptOnce(t)
	if boundedWatcherRun(g.r.holdsRestart) {
		t.Fatal("watcher restarted while a family's last attempt failed on a connection error")
	}
}

// boundedWatcherRun runs a watcher whose Postgres answers every ping, held by
// hold, and cancels it after 10 pings; it reports the restart decision.
func boundedWatcherRun(hold func() bool) bool {
	pinger := &pgScriptedPinger{script: []error{nil}}
	w := newTestPGWatcher(&pgFakeClock{t: time.Unix(0, 0)}, pinger, 0)
	w.holdWhile = hold
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pings := 0
	w.ping = func(c context.Context) error {
		pings++
		if pings == 10 {
			cancel()
		}
		return pinger.ping(c)
	}
	return w.run(ctx)
}

// The refusal is logged once per state change, not on every retry: entering
// the refusal logs once; repeated refusals log nothing more (and are not
// repeated in the per-attempt pending line); leaving it for an open error
// and coming back logs it again; a later success clears the state.
func TestStoreConfigRefusal_LoggedOncePerStateChangeAndClearedOnSuccess(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	f.clock.stopAfter = 0
	fam := &scriptedFamily{script: []error{
		fakeRefusal(), fakeRefusal(), fakeRefusal(), // refused x3: one log
		errFakeOpen,                  // leaves the refusal: holds again
		fakeRefusal(), fakeRefusal(), // refused again: one more log
		// then succeeds
	}}
	f.r.Register(fam.family("containarium.fake_family"))

	f.runToCompletion(t, nil)

	logs := f.logs.all()
	if n := countLines(logs, "containarium.fake_family", "refused by configuration"); n != 2 {
		t.Errorf("refusal log lines = %d, want 2 (one per entry into the refused state):\n%s", n, strings.Join(logs, "\n"))
	}
	if n := countLines(logs, errFakeKMSMissing.Error()); n != 2 {
		t.Errorf("lines naming the refusal cause = %d, want 2 (not repeated every retry):\n%s", n, strings.Join(logs, "\n"))
	}
	if n := countLines(logs, "pending in-process recovery", errFakeOpen.Error()); n != 1 {
		t.Errorf("pending lines naming the open error = %d, want 1:\n%s", n, strings.Join(logs, "\n"))
	}
	if f.r.pending() || f.r.holdsRestart() {
		t.Error("family still pending or holding after it installed")
	}
	if got := f.status(t, "containarium.fake_family"); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("readiness after the install succeeded = %v, want SERVING", got)
	}
	f.r.mu.Lock()
	defer f.r.mu.Unlock()
	if f.r.families[0].refused {
		t.Error("refused state not cleared by the successful install")
	}
}

// The secrets family reports CONTAINARIUM_REQUIRE_ENVELOPE with no KMS as a
// config refusal, so it does not hold the restart; readiness stays
// NOT_SERVING and the boot path still recognises the sentinel.
func TestStoreConfigRefusal_SecretsRequireEnvelopeWithoutKMS(t *testing.T) {
	t.Setenv("CONTAINARIUM_REQUIRE_ENVELOPE", "true")
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "none")
	keyPath := filepath.Join(t.TempDir(), "secrets.key")

	cs := &ContainerServer{}
	open := func(ctx context.Context, pool *pgxpool.Pool) (*secrets.Store, error) {
		return openSecretsStore(ctx, pool, cs, keyPath)
	}
	fam := secretsStoreFamily(cs, open)
	err := fam.Install(context.Background(), nil)
	if !isStoreConfigRefusal(err) {
		t.Fatalf("secrets install error = %v, want a config refusal", err)
	}
	if !errors.Is(err, errSecretsEnvelopeWithoutKMS) {
		t.Errorf("secrets refusal %v does not unwrap to errSecretsEnvelopeWithoutKMS (boot logs it as FATAL by that sentinel)", err)
	}

	f := newStoreRecoveryFixture(t, &fakePostgres{})
	f.r.Register(fam)
	f.attemptOnce(t)
	if !f.r.pending() || f.r.holdsRestart() {
		t.Errorf("after the refusal pending=%v holdsRestart=%v, want pending and not holding", f.r.pending(), f.r.holdsRestart())
	}
	if got := f.status(t, secretsStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("secrets readiness after the refusal = %v, want NOT_SERVING", got)
	}
	if cs.loadSecretsStore() != nil {
		t.Error("a secrets store was wired despite the refusal")
	}
}

// #3387: the degraded-start scenario of #3378 at the watcher — secrets
// refused by CONTAINARIUM_REQUIRE_ENVELOPE with no KMS and the tracker
// family waiting on it — restarts the daemon; the same pair with secrets
// failing on an open error keeps the watcher waiting.
func TestStoreConfigRefusal_WatcherRestartsWithTrackerWaitingOnRefusedSecrets(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	cs := &ContainerServer{}
	f.r.Register(secretsStoreFamily(cs, requireEnvelopeWithoutKMS(t, cs)))
	f.r.Register(f.trackerFamilyOver(cs, &AgentSkillServer{}, (&fakeTrackerOpen{store: &tracker.Store{}}).open))
	f.attemptOnce(t)
	if !boundedWatcherRun(f.r.holdsRestart) {
		t.Fatal("watcher did not restart with secrets config-refused and the tracker waiting on it")
	}

	g := newStoreRecoveryFixture(t, &fakePostgres{})
	gcs := &ContainerServer{}
	g.r.Register(secretsStoreFamily(gcs, func(context.Context, *pgxpool.Pool) (*secrets.Store, error) {
		return nil, errFakeOpen
	}))
	g.r.Register(g.trackerFamilyOver(gcs, &AgentSkillServer{}, (&fakeTrackerOpen{store: &tracker.Store{}}).open))
	g.attemptOnce(t)
	if boundedWatcherRun(g.r.holdsRestart) {
		t.Fatal("watcher restarted while the tracker waits on a secrets family that failed on an open error")
	}
}
