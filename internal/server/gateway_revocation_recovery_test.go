//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/modelgateway"
)

// #3365: three consumers of the JWT revocation list took the store only at
// startup, so after a degraded start and a late install (#3328) they stayed
// on their degraded fallback until a restart:
//
//  1. the model gateway's jti check (Config.Revocations) stayed nil, so a
//     revoked gateway token was accepted;
//  2. the gateway's owner cutoffs stayed in memory, and cutoffs recorded
//     during the window never reached Postgres;
//  3. the expired-row cleanup loop never started.
//
// Decision (Q10 on #3335): (a) a live jti checker via a per-call adapter,
// (b) the window's in-memory cutoffs copied into Postgres at install keeping
// the latest per owner, (c) the cleanup loop started from the install.

var gatewayRecoverySecret = []byte("model-gateway-recovery-test-secret-0123456789")

// fakeOwnerRevocationStore mirrors auth.PgOwnerRevocationStore's semantics:
// one cutoff per owner, and a revocation never narrows (the conditional
// upsert keeps the later cutoff).
type fakeOwnerRevocationStore struct {
	mu       sync.Mutex
	cutoff   map[string]time.Time
	reason   map[string]string
	failNext error
	writes   int
}

func newFakeOwnerRevocationStore() *fakeOwnerRevocationStore {
	return &fakeOwnerRevocationStore{cutoff: map[string]time.Time{}, reason: map[string]string{}}
}

func (s *fakeOwnerRevocationStore) RevokedBefore(_ context.Context, keyOwner string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cutoff[keyOwner], nil
}

func (s *fakeOwnerRevocationStore) RevokeOwner(_ context.Context, keyOwner string, at time.Time, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failNext; err != nil {
		s.failNext = nil
		return err
	}
	s.writes++
	if prev, ok := s.cutoff[keyOwner]; ok && !prev.Before(at) {
		return nil
	}
	s.cutoff[keyOwner] = at
	s.reason[keyOwner] = reason
	return nil
}

func (s *fakeOwnerRevocationStore) get(keyOwner string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cutoff[keyOwner]
}

// newRecoveryGateway builds a gateway the way dual_server.go does after a
// degraded start: its revocation reads are the live adapters, and a fake
// upstream answers 200 for every call that gets through.
func newRecoveryGateway(t *testing.T, gr *gatewayRevocations) func(tok string) int {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"model":"m","usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	t.Cleanup(up.Close)
	gw := modelgateway.New(modelgateway.Config{
		Secret:           gatewayRecoverySecret,
		Logger:           log.New(io.Discard, "", 0),
		Providers:        map[string]*modelgateway.Provider{"kafeido": modelgateway.NewOpenAICompatibleProvider("kafeido", up.URL)},
		ProviderKeys:     map[string]string{"kafeido": "sk-daemon-global"},
		Revocations:      gr.jti,
		OwnerRevocations: gr.owners,
	})
	return func(tok string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/model/kafeido/v1/chat/completions", strings.NewReader(`{"model":"m"}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
}

func mintRecoveryToken(t *testing.T, keyOwner string) (string, string) {
	t.Helper()
	tok, id, err := modelgateway.MintTokenWithID(gatewayRecoverySecret,
		modelgateway.GatewayClaims{Tenant: "a-box", Provider: "kafeido", KeyOwner: keyOwner}, time.Hour)
	if err != nil {
		t.Fatalf("MintTokenWithID: %v", err)
	}
	return tok, id.JTI
}

// (a) After a degraded start and a late install, a revoked gateway token is
// rejected with no restart, through the gateway the daemon built before the
// store existed.
func TestGatewayRevocationRecovery_RevokedTokenRejectedAfterLateInstall(t *testing.T) {
	f := newRevocationRecoveryFixture(t, &fakePostgres{downFor: 1})
	owners := newFakeOwnerRevocationStore()
	gr := newGatewayRevocations(func(context.Context, *pgxpool.Pool) (ownerRevocationStore, error) { return owners, nil })
	c := f.consumers()
	c.gateway = gr
	registerRevocationLateInstall(f.r, c, f.open)
	call := newRecoveryGateway(t, gr)

	revoked, revokedJTI := mintRecoveryToken(t, "")
	live, _ := mintRecoveryToken(t, "")
	// Revoked in Postgres before the outage: the store that installs late
	// already holds the row.
	if err := f.store.Revoke(context.Background(), revokedJTI, time.Now().Add(time.Hour), "revoked before the window"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// The window: no store, so the gateway cannot check (#3335 Q8: degraded,
	// not refused) — the same answer it gave with no checker at all.
	if got := call(revoked); got != http.StatusOK {
		t.Fatalf("before install: revoked token got %d, want 200 (no store to check yet)", got)
	}

	f.runToCompletion(t, nil)

	if got := call(revoked); got != http.StatusUnauthorized {
		t.Fatalf("after late install: revoked gateway token got %d, want 401 with no restart", got)
	}
	if got := call(live); got != http.StatusOK {
		t.Fatalf("after late install: unrevoked gateway token got %d, want 200", got)
	}
	// Revoked after install (e.g. `containarium token revoke --jti`): the
	// adapter reads the store per call, so this is rejected at once too.
	other, otherJTI := mintRecoveryToken(t, "")
	_ = f.store.Revoke(context.Background(), otherJTI, time.Now().Add(time.Hour), "revoked after install")
	if got := call(other); got != http.StatusUnauthorized {
		t.Fatalf("token revoked after install got %d, want 401", got)
	}
}

// (b) Cutoffs recorded in memory during the window are in the durable store
// after install, and the latest cutoff per owner wins — whichever side holds
// it.
func TestGatewayRevocationRecovery_OwnerCutoffsCarriedIntoDurableStore(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		window  map[string]time.Time // recorded in memory during the window
		durable map[string]time.Time // already in Postgres before the outage
		want    map[string]time.Time
	}{
		{
			name:   "a window cutoff with no durable row is carried over",
			window: map[string]time.Time{"user:alice": t0},
			want:   map[string]time.Time{"user:alice": t0},
		},
		{
			name:    "a later window cutoff replaces an earlier durable one",
			window:  map[string]time.Time{"user:alice": t0.Add(time.Hour)},
			durable: map[string]time.Time{"user:alice": t0},
			want:    map[string]time.Time{"user:alice": t0.Add(time.Hour)},
		},
		{
			name:    "an earlier window cutoff never narrows a later durable one",
			window:  map[string]time.Time{"user:alice": t0},
			durable: map[string]time.Time{"user:alice": t0.Add(time.Hour)},
			want:    map[string]time.Time{"user:alice": t0.Add(time.Hour)},
		},
		{
			name:    "several owners, each keeps its own latest",
			window:  map[string]time.Time{"user:alice": t0.Add(2 * time.Hour), "user:bob": t0, "org:acme": t0.Add(time.Minute)},
			durable: map[string]time.Time{"user:bob": t0.Add(time.Hour), "user:carol": t0},
			want: map[string]time.Time{
				"user:alice": t0.Add(2 * time.Hour), "user:bob": t0.Add(time.Hour),
				"org:acme": t0.Add(time.Minute), "user:carol": t0,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f := newRevocationRecoveryFixture(t, &fakePostgres{downFor: 1})
			durable := newFakeOwnerRevocationStore()
			for o, at := range tc.durable {
				durable.cutoff[o] = at
			}
			gr := newGatewayRevocations(func(context.Context, *pgxpool.Pool) (ownerRevocationStore, error) { return durable, nil })
			c := f.consumers()
			c.gateway = gr
			registerRevocationLateInstall(f.r, c, f.open)
			for o, at := range tc.window {
				if err := gr.owners.RevokeOwner(ctx, o, at, "key removed during the window"); err != nil {
					t.Fatalf("RevokeOwner(%s) during the window: %v", o, err)
				}
			}

			f.runToCompletion(t, nil)

			for o, want := range tc.want {
				if got := durable.get(o); !got.Equal(want) {
					t.Errorf("durable cutoff for %s = %v, want %v", o, got, want)
				}
				// The gateway now reads the durable store.
				got, err := gr.owners.RevokedBefore(ctx, o)
				if err != nil || !got.Equal(want) {
					t.Errorf("gateway cutoff for %s after install = %v, %v; want %v", o, got, err, want)
				}
			}
		})
	}
}

// (b) end to end: an owner revoked during the window stays revoked across the
// install, and a revocation after the install lands in Postgres.
func TestGatewayRevocationRecovery_OwnerRevokedDuringWindowStaysRevoked(t *testing.T) {
	ctx := context.Background()
	f := newRevocationRecoveryFixture(t, &fakePostgres{downFor: 1})
	durable := newFakeOwnerRevocationStore()
	gr := newGatewayRevocations(func(context.Context, *pgxpool.Pool) (ownerRevocationStore, error) { return durable, nil })
	c := f.consumers()
	c.gateway = gr
	registerRevocationLateInstall(f.r, c, f.open)
	call := newRecoveryGateway(t, gr)
	gw := modelgateway.New(modelgateway.Config{Secret: gatewayRecoverySecret, OwnerRevocations: gr.owners})

	tok, _ := mintRecoveryToken(t, "user:alice")
	if err := gw.RevokeByKeyOwner(ctx, "user:alice", "key removed during the window"); err != nil {
		t.Fatalf("RevokeByKeyOwner during the window: %v", err)
	}
	if got := call(tok); got != http.StatusUnauthorized {
		t.Fatalf("during the window: owner-revoked token got %d, want 401", got)
	}

	f.runToCompletion(t, nil)

	if durable.get("user:alice").IsZero() {
		t.Fatal("cutoff recorded during the window is not in the durable store after install")
	}
	if got := call(tok); got != http.StatusUnauthorized {
		t.Fatalf("after install: owner-revoked token got %d, want 401", got)
	}
	if err := gw.RevokeByKeyOwner(ctx, "user:bob", "key removed after install"); err != nil {
		t.Fatalf("RevokeByKeyOwner after install: %v", err)
	}
	if durable.get("user:bob").IsZero() {
		t.Fatal("revocation after install did not reach the durable store")
	}
}

// A failing carry-over leaves the in-memory store serving, keeps its
// cutoffs, and is retried; the jti checker is not swapped half-way.
func TestGatewayRevocationRecovery_FailedCarryOverIsRetried(t *testing.T) {
	ctx := context.Background()
	f := newRevocationRecoveryFixture(t, &fakePostgres{})
	durable := newFakeOwnerRevocationStore()
	durable.failNext = errors.New("insert gateway_owner_revocations: connection reset")
	gr := newGatewayRevocations(func(context.Context, *pgxpool.Pool) (ownerRevocationStore, error) { return durable, nil })
	c := f.consumers()
	c.gateway = gr
	registerRevocationLateInstall(f.r, c, f.open)
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	if err := gr.owners.RevokeOwner(ctx, "user:alice", at, "window"); err != nil {
		t.Fatalf("RevokeOwner: %v", err)
	}

	f.runToCompletion(t, nil)

	if f.opens != 2 {
		t.Errorf("install ran %d times, want 2 (carry-over failed once, then succeeded)", f.opens)
	}
	if got := durable.get("user:alice"); !got.Equal(at) {
		t.Errorf("durable cutoff after retry = %v, want %v", got, at)
	}
}

// The owner store failing to open fails the whole install, so it is retried
// rather than leaving the gateway half-installed.
func TestGatewayRevocationRecovery_OwnerStoreOpenFailureIsRetried(t *testing.T) {
	f := newRevocationRecoveryFixture(t, &fakePostgres{})
	durable := newFakeOwnerRevocationStore()
	var ownerOpens int
	gr := newGatewayRevocations(func(context.Context, *pgxpool.Pool) (ownerRevocationStore, error) {
		ownerOpens++
		if ownerOpens == 1 {
			return nil, errors.New("create table gateway_owner_revocations: permission denied")
		}
		return durable, nil
	})
	c := f.consumers()
	c.gateway = gr
	registerRevocationLateInstall(f.r, c, f.open)

	f.runToCompletion(t, nil)

	if ownerOpens != 2 {
		t.Errorf("owner store opened %d times, want 2", ownerOpens)
	}
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	if err := gr.owners.RevokeOwner(context.Background(), "user:alice", at, "after install"); err != nil {
		t.Fatalf("RevokeOwner after install: %v", err)
	}
	if got := durable.get("user:alice"); !got.Equal(at) {
		t.Errorf("revocation after the retried install reached the durable store as %v, want %v", got, at)
	}
}

// The adapters are read on every proxied call while the install swaps them:
// run with -race.
func TestGatewayRevocationRecovery_SwapIsRaceSafe(t *testing.T) {
	ctx := context.Background()
	gr := newGatewayRevocations(nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_, _ = gr.jti.IsRevoked(ctx, "jti")
			_, _ = gr.owners.RevokedBefore(ctx, "user:alice")
			_ = gr.owners.RevokeOwner(ctx, "user:alice", time.Now(), "race")
		}
	}()
	for i := 0; i < 50; i++ {
		gr.jti.install(newFakeRevocationStore())
		if _, err := gr.owners.install(ctx, newFakeOwnerRevocationStore()); err != nil {
			t.Fatalf("install: %v", err)
		}
	}
	<-done
}

// cleanableRevocationStore is a revocation store that can also prune, like
// *auth.PgRevocationStore.
type cleanableRevocationStore struct {
	*fakeRevocationStore
}

func (cleanableRevocationStore) CleanupExpired(context.Context, time.Time) (int64, error) {
	return 0, nil
}

// cleanupRecorder counts how many cleanup loops were started and with which
// store.
type cleanupRecorder struct {
	runs    atomic.Int32
	started chan revocationCleaner
}

func newCleanupRecorder() *cleanupRecorder {
	return &cleanupRecorder{started: make(chan revocationCleaner, 16)}
}

func (r *cleanupRecorder) run(_ context.Context, st revocationCleaner) {
	r.runs.Add(1)
	r.started <- st
}

func (r *cleanupRecorder) waitOne(t *testing.T) revocationCleaner {
	t.Helper()
	select {
	case st := <-r.started:
		return st
	case <-time.After(5 * time.Second):
		t.Fatal("the cleanup loop was not started")
		return nil
	}
}

// assertRuns waits a short grace period, then checks how many loops started.
func (r *cleanupRecorder) assertRuns(t *testing.T, want int32) {
	t.Helper()
	time.Sleep(50 * time.Millisecond)
	if got := r.runs.Load(); got != want {
		t.Fatalf("cleanup loops started = %d, want %d", got, want)
	}
}

// (c) After a degraded start the cleanup loop starts exactly once, from the
// install, whichever of Start() and the install comes first.
func TestRevocationCleanup_StartsOnceFromLateInstall(t *testing.T) {
	for _, startFirst := range []bool{true, false} {
		name := "install before Start"
		if startFirst {
			name = "Start before install"
		}
		t.Run(name, func(t *testing.T) {
			f := newRevocationRecoveryFixture(t, &fakePostgres{downFor: 1})
			store := cleanableRevocationStore{f.store}
			rec := newCleanupRecorder()
			cl := newRevocationCleanup(rec.run)
			c := f.consumers()
			c.cleanup = cl
			registerRevocationLateInstall(f.r, c, func(context.Context, *pgxpool.Pool) (auth.RevocationStore, error) {
				return store, nil
			})

			if startFirst {
				cl.start(f.ctx) // DualServer.Start: no store yet
				rec.assertRuns(t, 0)
			}
			f.runToCompletion(t, nil)
			if !startFirst {
				rec.assertRuns(t, 0) // no serving context yet
				cl.start(f.ctx)
			}

			if got := rec.waitOne(t); got != revocationCleaner(store) {
				t.Errorf("cleanup loop started with %T, want the late-installed store", got)
			}
			// Neither a second Start nor a second store starts another loop.
			cl.start(f.ctx)
			cl.setStore(store)
			rec.assertRuns(t, 1)
		})
	}
}

// (c) A store installed at startup starts the loop once, from Start(); a
// repeated Start or store hand-off never starts it twice.
func TestRevocationCleanup_StartupInstallStartsOnce(t *testing.T) {
	rec := newCleanupRecorder()
	cl := newRevocationCleanup(rec.run)
	store := cleanableRevocationStore{newFakeRevocationStore()}
	cl.setStore(store) // NewDualServer, startup install
	rec.assertRuns(t, 0)
	cl.start(context.Background())
	if got := rec.waitOne(t); got != revocationCleaner(store) {
		t.Errorf("cleanup loop started with %T, want the startup store", got)
	}
	cl.setStore(store)
	cl.start(context.Background())
	rec.assertRuns(t, 1)
}

// Start and the install race on different goroutines: exactly one loop, and
// no data race on the shared fields (-race).
func TestRevocationCleanup_ConcurrentStartAndInstallStartOnce(t *testing.T) {
	for i := 0; i < 50; i++ {
		rec := newCleanupRecorder()
		cl := newRevocationCleanup(rec.run)
		store := cleanableRevocationStore{newFakeRevocationStore()}
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(2)
			go func() { defer wg.Done(); cl.setStore(store) }()
			go func() { defer wg.Done(); cl.start(context.Background()) }()
		}
		wg.Wait()
		rec.waitOne(t)
		rec.assertRuns(t, 1)
	}
}

// No daemon without the store: a nil cleanup (not wired) is a no-op.
func TestRevocationCleanup_NilIsNoOp(t *testing.T) {
	var cl *revocationCleanup
	cl.setStore(cleanableRevocationStore{newFakeRevocationStore()})
	cl.start(context.Background())
}
