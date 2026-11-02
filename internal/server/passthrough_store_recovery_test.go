//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/network"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3333: the passthrough route store and its sync job on the late-install
// helper (#3326). With Postgres down at startup every passthrough RPC
// answers UNAVAILABLE, nothing is written to the host's forwarding rules,
// and the `containarium.passthrough` readiness entry is NOT_SERVING. Once
// Postgres answers, the store installs in the running daemon, the container
// delete cascade gets it, and the sync job is created and started exactly
// once on the daemon's serving context, with no restart.

// recordingPassthroughRules stands in for the host's iptables rules. A write
// refused while the store is absent must not reach it (#3335 Q13).
type recordingPassthroughRules struct {
	mu    sync.Mutex
	calls []string
}

func (r *recordingPassthroughRules) record(call string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
}

func (r *recordingPassthroughRules) AddRoute(int, string, int, string) error {
	r.record("AddRoute")
	return nil
}

func (r *recordingPassthroughRules) RemoveRoute(int, string) error {
	r.record("RemoveRoute")
	return nil
}

func (r *recordingPassthroughRules) ListRoutes() ([]network.PassthroughRoute, error) {
	r.record("ListRoutes")
	return nil, nil
}

func (r *recordingPassthroughRules) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// fakePassthroughSyncJob records the lifecycle calls the daemon makes.
type fakePassthroughSyncJob struct {
	mu     sync.Mutex
	store  network.PassthroughStore
	starts int
	stops  int
	ctx    context.Context
}

func (j *fakePassthroughSyncJob) Start(ctx context.Context) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.starts++
	j.ctx = ctx
}

func (j *fakePassthroughSyncJob) Stop() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.stops++
}

func (j *fakePassthroughSyncJob) counts() (starts, stops int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.starts, j.stops
}

// fakePassthroughSyncJobs builds fake sync jobs and keeps every one built.
type fakePassthroughSyncJobs struct {
	mu   sync.Mutex
	jobs []*fakePassthroughSyncJob
}

func (f *fakePassthroughSyncJobs) build(st network.PassthroughStore) passthroughSyncRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	j := &fakePassthroughSyncJob{store: st}
	f.jobs = append(f.jobs, j)
	return j
}

func (f *fakePassthroughSyncJobs) built() []*fakePassthroughSyncJob {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*fakePassthroughSyncJob(nil), f.jobs...)
}

// fakePassthroughOpen records each open and returns store.
type fakePassthroughOpen struct {
	mu    sync.Mutex
	store network.PassthroughStore
	err   error
	opens int
}

func (f *fakePassthroughOpen) open(context.Context, *pgxpool.Pool) (network.PassthroughStore, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens++
	if f.err != nil {
		return nil, f.err
	}
	return f.store, nil
}

func (f *fakePassthroughOpen) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens
}

type passthroughRecoveryRig struct {
	network    *NetworkServer
	containers *ContainerServer
	rules      *recordingPassthroughRules
	jobs       *fakePassthroughSyncJobs
	sync       *passthroughSync
}

func newPassthroughRecoveryRig() *passthroughRecoveryRig {
	rules := &recordingPassthroughRules{}
	jobs := &fakePassthroughSyncJobs{}
	return &passthroughRecoveryRig{
		network:    &NetworkServer{passthroughRules: rules},
		containers: &ContainerServer{},
		rules:      rules,
		jobs:       jobs,
		sync:       newPassthroughSync(jobs.build),
	}
}

func (g *passthroughRecoveryRig) consumers() passthroughConsumers {
	return passthroughConsumers{network: g.network, containers: g.containers, sync: g.sync}
}

// passthroughWriteCalls is every passthrough RPC, as an admin, with a valid
// request, so a refusal can only come from the store check.
func passthroughWriteCalls(ns *NetworkServer) map[string]func() error {
	ctx := adminCtx()
	enable := true
	disable := false
	return map[string]func() error{
		"AddPassthroughRoute": func() error {
			_, err := ns.AddPassthroughRoute(ctx, &pb.AddPassthroughRouteRequest{
				ExternalPort: 4566, TargetIp: "10.0.3.5", TargetPort: 4566,
				Protocol: pb.RouteProtocol_ROUTE_PROTOCOL_TCP,
			})
			return err
		},
		"UpdatePassthroughRoute(enable)": func() error {
			_, err := ns.UpdatePassthroughRoute(ctx, &pb.UpdatePassthroughRouteRequest{ExternalPort: 4566, Active: &enable})
			return err
		},
		"UpdatePassthroughRoute(disable)": func() error {
			_, err := ns.UpdatePassthroughRoute(ctx, &pb.UpdatePassthroughRouteRequest{ExternalPort: 4566, Active: &disable})
			return err
		},
		"UpdatePassthroughRoute(target)": func() error {
			_, err := ns.UpdatePassthroughRoute(ctx, &pb.UpdatePassthroughRouteRequest{ExternalPort: 4566, TargetIp: "10.0.3.6", TargetPort: 4567})
			return err
		},
		"DeletePassthroughRoute": func() error {
			_, err := ns.DeletePassthroughRoute(ctx, &pb.DeletePassthroughRouteRequest{ExternalPort: 4566})
			return err
		},
		"ListPassthroughRoutes": func() error {
			_, err := ns.ListPassthroughRoutes(ctx, &pb.ListPassthroughRoutesRequest{})
			return err
		},
	}
}

// assertPassthroughRefused: every passthrough RPC answers UNAVAILABLE and
// none of them touched the host's rules (Q13: no in-memory rule).
func assertPassthroughRefused(t *testing.T, g *passthroughRecoveryRig) {
	t.Helper()
	for name, call := range passthroughWriteCalls(g.network) {
		if code := status.Code(call()); code != codes.Unavailable {
			t.Errorf("%s with the passthrough store absent = %v, want Unavailable", name, code)
		}
	}
	if calls := g.rules.recorded(); len(calls) != 0 {
		t.Errorf("host rules touched while the store is absent: %v; a refused write must leave no rule", calls)
	}
}

// AC1 + AC2 with a fake store install: Postgres is down for two attempts.
// Before recovery the entry is NOT_SERVING and every passthrough RPC answers
// UNAVAILABLE with no rule written. After it, the entry is SERVING, writes
// land in the installed store (not in the host's rules), the delete cascade
// has the store, and the sync job was built once over it. Readers run during
// the swap, so -race catches a field that is still read raw.
func TestPassthroughRecovery_DegradedStartThenInstalledInProcess(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 2})
	g := newPassthroughRecoveryRig()
	durable := &fakePassthroughOpen{store: newFakePassthroughStore()}
	registerPassthroughLateInstall(f.r, g.consumers(), durable.open)

	if got := f.status(t, passthroughStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("passthrough readiness before recovery = %v, want NOT_SERVING", got)
	}
	if f.readiness.entries[passthroughStoreService] == "" {
		t.Errorf("passthrough family published no readiness display name: %v", f.readiness.entries)
	}
	assertPassthroughRefused(t, g)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = g.network.currentPassthroughStore()
				_ = g.containers.loadPassthroughStore()
			}
		}()
	}
	f.runToCompletion(t, nil)
	close(stop)
	wg.Wait()

	if got := f.status(t, passthroughStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("passthrough readiness after recovery = %v, want SERVING", got)
	}
	if n := durable.count(); n != 1 {
		t.Errorf("passthrough store opened %d times, want once", n)
	}
	if got := g.containers.loadPassthroughStore(); got != durable.store {
		t.Errorf("delete-cascade store after recovery = %v, want the installed store", got)
	}
	jobs := g.jobs.built()
	if len(jobs) != 1 || jobs[0].store != durable.store {
		t.Fatalf("sync jobs built = %d, want exactly one over the installed store", len(jobs))
	}

	if _, err := g.network.AddPassthroughRoute(adminCtx(), &pb.AddPassthroughRouteRequest{
		ExternalPort: 4566, TargetIp: "10.0.3.5", TargetPort: 4566,
		Protocol: pb.RouteProtocol_ROUTE_PROTOCOL_TCP,
	}); err != nil {
		t.Fatalf("AddPassthroughRoute after recovery: %v", err)
	}
	st := durable.store.(*fakePassthroughStore)
	if _, err := st.GetByPortProtocol(context.Background(), 4566, "tcp"); err != nil {
		t.Errorf("route added after recovery is not in the installed store: %v", err)
	}
	if calls := g.rules.recorded(); len(calls) != 0 {
		t.Errorf("host rules written directly after recovery: %v; the sync job owns them", calls)
	}
	if f.r.pending() {
		t.Error("passthrough family still pending after it installed")
	}
}

// The sync job starts exactly once, on the daemon's serving context, in
// whichever order the install and Start arrive; Stop at shutdown stops it;
// an install after shutdown builds nothing.
func TestPassthroughRecovery_SyncJobStartsExactlyOnce(t *testing.T) {
	type daemonCtxKey struct{}
	serving := context.WithValue(context.Background(), daemonCtxKey{}, "serving")
	store := newFakePassthroughStore()

	cases := []struct {
		name       string
		steps      func(p *passthroughSync)
		wantBuilt  int
		wantStarts int
		wantStops  int
	}{
		{"install then start", func(p *passthroughSync) { p.install(store); p.start(serving) }, 1, 1, 0},
		{"start then install", func(p *passthroughSync) { p.start(serving); p.install(store) }, 1, 1, 0},
		{"repeated start and install", func(p *passthroughSync) {
			p.start(serving)
			p.install(store)
			p.start(serving)
			p.install(store)
		}, 1, 1, 0},
		{"started then stopped", func(p *passthroughSync) { p.start(serving); p.install(store); p.stop(); p.stop() }, 1, 1, 1},
		{"installed, never started, stopped", func(p *passthroughSync) { p.install(store); p.stop() }, 1, 0, 0},
		{"stopped before install", func(p *passthroughSync) { p.start(serving); p.stop(); p.install(store) }, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jobs := &fakePassthroughSyncJobs{}
			p := newPassthroughSync(jobs.build)
			tc.steps(p)
			built := jobs.built()
			if len(built) != tc.wantBuilt {
				t.Fatalf("sync jobs built = %d, want %d", len(built), tc.wantBuilt)
			}
			if len(built) == 0 {
				return
			}
			starts, stops := built[0].counts()
			if starts != tc.wantStarts || stops != tc.wantStops {
				t.Errorf("starts/stops = %d/%d, want %d/%d", starts, stops, tc.wantStarts, tc.wantStops)
			}
			if starts > 0 && built[0].ctx != serving {
				t.Error("sync job started on a context other than the daemon's serving context")
			}
		})
	}
}

// Start and a late install race on different goroutines; the job still
// starts exactly once.
func TestPassthroughRecovery_SyncJobStartRaceStartsOnce(t *testing.T) {
	for range 50 {
		jobs := &fakePassthroughSyncJobs{}
		p := newPassthroughSync(jobs.build)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); p.start(context.Background()) }()
		go func() { defer wg.Done(); p.install(newFakePassthroughStore()) }()
		wg.Wait()
		built := jobs.built()
		if len(built) != 1 {
			t.Fatalf("sync jobs built = %d, want 1", len(built))
		}
		if starts, _ := built[0].counts(); starts != 1 {
			t.Fatalf("sync job started %d times, want 1", starts)
		}
	}
}

// A healthy startup installs the store at once: the entry is SERVING, the
// family is not pending, and the RPCs write to the store.
func TestPassthroughRecovery_StartupInstall(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	g := newPassthroughRecoveryRig()
	durable := &fakePassthroughOpen{store: newFakePassthroughStore()}
	setupPassthroughStore(f.r, g.consumers(), func() (*pgxpool.Pool, error) { return new(pgxpool.Pool), nil }, durable.open)

	if got := f.status(t, passthroughStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("passthrough readiness after a startup install = %v, want SERVING", got)
	}
	if f.r.pending() {
		t.Error("passthrough family pending after a startup install")
	}
	if st, err := g.network.currentPassthroughStore(); err != nil || st != durable.store {
		t.Errorf("network passthrough store = %v, %v; want the installed store", st, err)
	}
	if got := g.containers.loadPassthroughStore(); got != durable.store {
		t.Errorf("delete-cascade store = %v, want the installed store", got)
	}
	if n := len(g.jobs.built()); n != 1 {
		t.Errorf("sync jobs built = %d, want 1", n)
	}
}

// Postgres down at startup: the family registers pending, readiness is
// NOT_SERVING, and the RPCs refuse; nothing was opened.
func TestPassthroughRecovery_StartupConnectFailureRegistersPending(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	g := newPassthroughRecoveryRig()
	durable := &fakePassthroughOpen{store: newFakePassthroughStore()}
	setupPassthroughStore(f.r, g.consumers(), func() (*pgxpool.Pool, error) {
		return nil, errors.New("dial tcp: connection refused")
	}, durable.open)

	if got := f.status(t, passthroughStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("passthrough readiness after a failed startup connect = %v, want NOT_SERVING", got)
	}
	if !f.r.pending() {
		t.Error("passthrough family not pending after a failed startup connect")
	}
	if n := durable.count(); n != 0 {
		t.Errorf("store opened %d times with no pool, want 0", n)
	}
	assertPassthroughRefused(t, g)
	if n := len(g.jobs.built()); n != 0 {
		t.Errorf("sync jobs built with no store = %d, want 0", n)
	}
}

// A daemon with no Postgres configured never requires the store: the legacy
// path that writes the host's rules directly is unchanged.
func TestPassthroughRecovery_NoPostgresConfiguredKeepsLegacyPath(t *testing.T) {
	rules := &recordingPassthroughRules{}
	ns := &NetworkServer{passthroughRules: rules}
	if _, err := ns.AddPassthroughRoute(adminCtx(), &pb.AddPassthroughRouteRequest{
		ExternalPort: 4566, TargetIp: "10.0.3.5", TargetPort: 4566,
	}); err != nil {
		t.Fatalf("AddPassthroughRoute with no Postgres configured: %v", err)
	}
	if got := rules.recorded(); len(got) != 1 || got[0] != "AddRoute" {
		t.Errorf("host rule calls = %v, want one AddRoute", got)
	}
}
