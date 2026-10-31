//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/secrets"
	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3329: the tracker store family on the late-install helper (#3326),
// after the secrets store (#3327). With Postgres down at startup every
// tracker RPC answers UNAVAILABLE and the `containarium.tracker` readiness
// entry is NOT_SERVING; once Postgres answers and the secrets store is in,
// the tracker store installs in the running daemon, the run starter and
// the agent server's connection checker and lineage reservations are
// wired with it, and a connection can be created and a run started, with
// no restart. While the secrets store is absent the tracker store does not
// install: its credentials live there, so it fails closed.

const trackerRecoveryTestUser = "tracker-recovery-test-user"

// assertTrackerRPCsUnavailable calls every tracker RPC whose store check
// runs before any argument the call needs a store for, as a caller allowed
// to make it, and wants UNAVAILABLE from each.
func assertTrackerRPCsUnavailable(t *testing.T, cs *ContainerServer) {
	t.Helper()
	u := trackerRecoveryTestUser
	admin := kmsKeyTestCtx(u, "member", "tracker:admin,agents:run")
	calls := map[string]func() error{
		"SetTrackerConnection": func() error {
			_, err := cs.SetTrackerConnection(admin, &pb.SetTrackerConnectionRequest{Username: u, Name: "default", CredentialSecret: "GH_TOKEN"})
			return err
		},
		"GetTrackerConnection": func() error {
			_, err := cs.GetTrackerConnection(admin, &pb.GetTrackerConnectionRequest{Username: u, Name: "default"})
			return err
		},
		"ListTrackerConnections": func() error {
			_, err := cs.ListTrackerConnections(admin, &pb.ListTrackerConnectionsRequest{Username: u})
			return err
		},
		"DeleteTrackerConnection": func() error {
			_, err := cs.DeleteTrackerConnection(admin, &pb.DeleteTrackerConnectionRequest{Username: u, Name: "default"})
			return err
		},
		"GetTrackerStatus": func() error {
			_, err := cs.GetTrackerStatus(admin, &pb.GetTrackerStatusRequest{Username: u, Name: "default"})
			return err
		},
		"SetTrackerRoute": func() error {
			_, err := cs.SetTrackerRoute(admin, &pb.SetTrackerRouteRequest{Username: u, Connection: "default", Scope: "product", SkillId: "product-define"})
			return err
		},
		"ListTrackerRoutes": func() error {
			_, err := cs.ListTrackerRoutes(admin, &pb.ListTrackerRoutesRequest{Username: u, Connection: "default"})
			return err
		},
		"DeleteTrackerRoute": func() error {
			_, err := cs.DeleteTrackerRoute(admin, &pb.DeleteTrackerRouteRequest{Username: u, Connection: "default", Scope: "product"})
			return err
		},
		"DispatchTrackerIssues": func() error {
			_, err := cs.DispatchTrackerIssues(admin, &pb.DispatchTrackerIssuesRequest{Username: u, Connection: "default"})
			return err
		},
		"ListTrackerDispatches": func() error {
			_, err := cs.ListTrackerDispatches(admin, &pb.ListTrackerDispatchesRequest{Username: u, Connection: "default"})
			return err
		},
	}
	for name, call := range calls {
		if code := status.Code(call()); code != codes.Unavailable {
			t.Errorf("%s with no tracker store = %v, want Unavailable", name, code)
		}
	}
}

// assertAgentTrackerUnwired: with no tracker store a run naming a tracker
// connection fails closed, and there are no lineage reservations to sweep.
func assertAgentTrackerUnwired(t *testing.T, agents *AgentSkillServer) {
	t.Helper()
	ctx := kmsKeyTestCtx(trackerRecoveryTestUser, "member", "agents:run")
	if code := status.Code(agents.validateTrackerConnection(ctx, "default")); code != codes.FailedPrecondition {
		t.Errorf("validateTrackerConnection with no tracker store = %v, want FailedPrecondition", code)
	}
	if agents.loadLineageReservations() != nil {
		t.Error("lineage reservations wired with no tracker store")
	}
}

// fakeTrackerOpen records each open and returns store.
type fakeTrackerOpen struct {
	mu    sync.Mutex
	store *tracker.Store
	pools []*pgxpool.Pool
}

func (f *fakeTrackerOpen) open(_ context.Context, pool *pgxpool.Pool) (*tracker.Store, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pools = append(f.pools, pool)
	return f.store, nil
}

func (f *fakeTrackerOpen) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pools)
}

// AC1 + the install half of AC2, without a database: Postgres is down for
// two attempts, the secrets family is registered first (as NewDualServer
// does) and the tracker family after it. Before recovery the tracker entry
// is NOT_SERVING, every tracker RPC answers UNAVAILABLE and the agent
// server has nothing wired. After it, the entry is SERVING and the store,
// the run starter, the connection checker and the lineage reservations are
// all the late-installed ones. Readers run during the swap, so -race
// catches a field that is still read raw.
func TestTrackerRecovery_DegradedStartThenInstalledInProcess(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 2})
	cs := &ContainerServer{}
	agents := &AgentSkillServer{}
	f.r.Register(secretsStoreFamily(cs, func(context.Context, *pgxpool.Pool) (*secrets.Store, error) {
		return &secrets.Store{}, nil
	}))
	durable := &fakeTrackerOpen{store: &tracker.Store{}}
	starter := &recordingRunStarter{}
	f.r.Register(trackerStoreFamily(cs, agents, durable.open, func() tracker.RunStarter { return starter }))

	if got := f.status(t, trackerStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("tracker readiness before recovery = %v, want NOT_SERVING", got)
	}
	if f.readiness.entries[trackerStoreService] == "" {
		t.Errorf("tracker family published no readiness display name: %v", f.readiness.entries)
	}
	assertTrackerRPCsUnavailable(t, cs)
	assertAgentTrackerUnwired(t, agents)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := kmsKeyTestCtx(trackerRecoveryTestUser, "member", "tracker:admin")
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = cs.loadTrackerStore()
				_ = cs.loadTrackerRunStarter()
				_ = agents.loadTrackerConnections()
				_ = agents.loadLineageReservations()
				// The preamble every route and dispatch RPC runs.
				_ = cs.requireTrackerRouteAccess(ctx, "", "default")
			}
		}()
	}
	f.runToCompletion(t, nil)
	close(stop)
	wg.Wait()

	if got := f.status(t, trackerStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("tracker readiness after recovery = %v, want SERVING", got)
	}
	if got := cs.loadTrackerStore(); got != durable.store {
		t.Errorf("tracker store after recovery = %p, want the installed store %p", got, durable.store)
	}
	if got := cs.loadTrackerRunStarter(); got != tracker.RunStarter(starter) {
		t.Errorf("run starter after recovery = %v, want the late-wired starter", got)
	}
	if got := agents.loadTrackerConnections(); got != trackerConnectionChecker(durable.store) {
		t.Errorf("agent connection checker after recovery = %v, want the installed store", got)
	}
	if got := agents.loadLineageReservations(); got != lineageReservationReleaser(durable.store) {
		t.Errorf("agent lineage reservations after recovery = %v, want the installed store", got)
	}
	if n := durable.count(); n != 1 {
		t.Errorf("tracker store opened %d times, want once", n)
	}
	if f.r.pending() {
		t.Error("tracker family still pending after it installed")
	}
}

// Fail closed on credentials: Postgres answers, but the secrets store is
// not installed, so the tracker store does not install either — it is
// never even opened, readiness stays NOT_SERVING and the RPCs keep
// answering UNAVAILABLE. Once the secrets store is in, the next attempt
// installs it.
func TestTrackerRecovery_WaitsForSecretsStore(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	f.clock.stopAfter = 4 // three attempts, then the test ends the loop
	cs := &ContainerServer{}
	agents := &AgentSkillServer{}
	durable := &fakeTrackerOpen{store: &tracker.Store{}}
	fam := trackerStoreFamily(cs, agents, durable.open, func() tracker.RunStarter { return &recordingRunStarter{} })
	f.r.Register(fam)

	f.r.Run(f.ctx, nil)

	if n := durable.count(); n != 0 {
		t.Errorf("tracker store opened %d times with no secrets store, want never", n)
	}
	if cs.loadTrackerStore() != nil || cs.loadTrackerRunStarter() != nil {
		t.Fatal("tracker store or run starter wired with no secrets store")
	}
	assertTrackerRPCsUnavailable(t, cs)
	assertAgentTrackerUnwired(t, agents)
	if got := f.status(t, trackerStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("tracker readiness with no secrets store = %v, want NOT_SERVING", got)
	}
	if !f.r.pending() {
		t.Error("tracker family is not pending with no secrets store")
	}

	cs.SetSecretsStore(&secrets.Store{})
	if err := fam.Install(context.Background(), new(pgxpool.Pool)); err != nil {
		t.Fatalf("Install once the secrets store is in: %v", err)
	}
	if cs.loadTrackerStore() != durable.store {
		t.Error("tracker store not installed once the secrets store is in")
	}
}

// A failed open leaves everything unwired, so the RPCs keep answering
// UNAVAILABLE and the loop tries again.
func TestTrackerRecovery_FailedOpenKeepsStoreNil(t *testing.T) {
	cs := withSecretsStore(&ContainerServer{}, &secrets.Store{})
	agents := &AgentSkillServer{}
	fam := trackerStoreFamily(cs, agents, func(context.Context, *pgxpool.Pool) (*tracker.Store, error) {
		return nil, errors.New("create table: boom")
	}, func() tracker.RunStarter { return &recordingRunStarter{} })
	if fam.Service != trackerStoreService || fam.Display == "" {
		t.Fatalf("family = %q / %q, want service %q with a display name", fam.Service, fam.Display, trackerStoreService)
	}
	if err := fam.Install(context.Background(), new(pgxpool.Pool)); err == nil {
		t.Fatal("Install returned nil although opening the store failed")
	}
	if cs.loadTrackerStore() != nil || cs.loadTrackerRunStarter() != nil {
		t.Fatal("a failed install wired the tracker store or run starter")
	}
	assertTrackerRPCsUnavailable(t, cs)
	assertAgentTrackerUnwired(t, agents)
}

// AC2 against a real Postgres: down for two attempts, then up. The real
// secrets open path and tracker.NewStore run over the helper's shared pool,
// secrets first, then tracker; afterwards a broker-only secret, a tracker
// connection and a route are created and a dispatch tick starts a run
// through the late-wired run starter, with no restart.
func TestTrackerRecovery_LateInstallConnectionAndRun(t *testing.T) {
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres")
	}
	t.Setenv("CONTAINARIUM_REQUIRE_ENVELOPE", "")
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "inproc")
	keyPath := filepath.Join(t.TempDir(), "secrets.key")
	const user = "tracker-recovery-late-install"

	f := newStoreRecoveryFixture(t, &fakePostgres{})
	var mu sync.Mutex
	dials := 0
	f.r.connect = func(ctx context.Context) (*pgxpool.Pool, error) {
		mu.Lock()
		defer mu.Unlock()
		dials++
		if dials <= 2 {
			return nil, errors.New("dial tcp: connection refused")
		}
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			t.Cleanup(pool.Close)
		}
		return pool, err
	}
	issue := tracker.Issue{Number: 7, Title: "idea", State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, Labels: []string{"scope:product"}}
	provider := &fakeWriterProvider{fakeReaderProvider: fakeReaderProvider{issues: []tracker.Issue{issue}, issue: issue}}
	cs := &ContainerServer{trackerDescribers: fakeDescriberSet(provider), claimLocks: tracker.NewClaimLocks()}
	agents := &AgentSkillServer{}
	starter := &recordingRunStarter{}
	f.r.Register(secretsStoreFamily(cs, func(ctx context.Context, pool *pgxpool.Pool) (*secrets.Store, error) {
		return openSecretsStore(ctx, pool, cs, keyPath)
	}))
	f.r.Register(trackerStoreFamily(cs, agents, tracker.NewStore, func() tracker.RunStarter { return starter }))
	assertTrackerRPCsUnavailable(t, cs)

	f.runToCompletion(t, nil)

	if got := f.status(t, trackerStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("tracker readiness after Postgres answered = %v, want SERVING", got)
	}
	ctx := context.Background()
	_ = cs.loadTrackerStore().Delete(ctx, user, "default") // dispatch rows cascade from it
	secretCtx := kmsKeyTestCtx(user, "member", "secrets:write")
	t.Cleanup(func() {
		_, _ = cs.DeleteSecret(secretCtx, &pb.DeleteSecretRequest{Username: user, Name: "GH_TOKEN"})
		_ = cs.loadTrackerStore().Delete(ctx, user, "default")
	})
	if _, err := cs.SetSecret(secretCtx, &pb.SetSecretRequest{
		Username: user, Name: "GH_TOKEN", Value: "ghp_x",
		DeliveryMode: pb.SecretDelivery_SECRET_DELIVERY_BROKER_ONLY,
	}); err != nil {
		t.Fatalf("SetSecret (broker-only) after the late install: %v", err)
	}
	admin := kmsKeyTestCtx(user, "member", "tracker:admin,agents:run")
	if _, err := cs.SetTrackerConnection(admin, &pb.SetTrackerConnectionRequest{
		Username: user, Name: "default",
		Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:  "acme/widgets", CredentialSecret: "GH_TOKEN",
	}); err != nil {
		t.Fatalf("SetTrackerConnection after the late install: %v", err)
	}
	if _, err := cs.SetTrackerRoute(admin, &pb.SetTrackerRouteRequest{Username: user, Connection: "default", Scope: "product", SkillId: "product-define"}); err != nil {
		t.Fatalf("SetTrackerRoute after the late install: %v", err)
	}
	resp, err := cs.DispatchTrackerIssues(admin, &pb.DispatchTrackerIssuesRequest{Username: user, Connection: "default"})
	if err != nil {
		t.Fatalf("DispatchTrackerIssues after the late install: %v", err)
	}
	if len(resp.GetStarted()) != 1 {
		t.Fatalf("started = %+v, want one run", resp.GetStarted())
	}
	starter.mu.Lock()
	calls := append([]tracker.StartRunRequest(nil), starter.calls...)
	starter.mu.Unlock()
	if len(calls) != 1 || calls[0].RunID != resp.GetStarted()[0].GetRunId() {
		t.Fatalf("StartRun calls = %+v, want one with the dispatched run id", calls)
	}
	// The agent server validates the run's tracker connection against the
	// late-installed store.
	if err := agents.validateTrackerConnection(kmsKeyTestCtx(user, "member", "agents:run"), "default"); err != nil {
		t.Errorf("validateTrackerConnection after the late install: %v", err)
	}
	if err := agents.validateTrackerConnection(kmsKeyTestCtx(user, "member", "agents:run"), "missing"); status.Code(err) != codes.InvalidArgument {
		t.Errorf("validateTrackerConnection(missing) = %v, want InvalidArgument", err)
	}
}
