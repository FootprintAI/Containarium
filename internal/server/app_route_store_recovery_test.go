//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/events"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3331: the app-hosting store and the route store (with the Caddy route
// sync) as late-install families on the #3326 helper (decision Q12 on
// #3335). With Postgres down at startup the AppService and the route RPCs
// answer UNAVAILABLE, `containarium.app_hosting` and `containarium.routes`
// are NOT_SERVING, and a route write touches nothing (Q13: no route is
// applied in Caddy while the store is absent). Once Postgres answers the
// stores install in the running daemon, the Caddy set-up that boot would
// have run runs once, the sync job is created once and started with the
// daemon's serving context (stopped at shutdown, not by the helper), and
// every consumer that used to capture the store by value reads it through
// the live accessor.

// fakeCaddyAdmin counts every request the proxy manager makes.
type fakeCaddyAdmin struct {
	srv  *httptest.Server
	hits atomic.Int64
}

func newFakeCaddyAdmin(t *testing.T) *fakeCaddyAdmin {
	t.Helper()
	f := &fakeCaddyAdmin{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// fakeRouteSyncJob records the serving context it was started with.
type fakeRouteSyncJob struct {
	mu      sync.Mutex
	starts  []context.Context
	stops   int
	tracker app.WakeTracker
}

func (j *fakeRouteSyncJob) Start(ctx context.Context) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.starts = append(j.starts, ctx)
}

func (j *fakeRouteSyncJob) Stop() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.stops++
}

func (j *fakeRouteSyncJob) SetWakeTracker(t app.WakeTracker) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.tracker = t
}

func (j *fakeRouteSyncJob) startCount() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.starts)
}

func (j *fakeRouteSyncJob) stopCount() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.stops
}

func (j *fakeRouteSyncJob) wakeTracker() app.WakeTracker {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.tracker
}

// fakeRouteEdge stands in for the Caddy side: the one-time set-up, the sync
// job and the management routes.
type fakeRouteEdge struct {
	mu     sync.Mutex
	setUps int
	jobs   []*fakeRouteSyncJob
	mgmt   []*app.RouteStore
}

func (e *fakeRouteEdge) setUp() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.setUps++
}

func (e *fakeRouteEdge) newSyncJob(*app.RouteStore) routeSyncJob {
	e.mu.Lock()
	defer e.mu.Unlock()
	j := &fakeRouteSyncJob{}
	e.jobs = append(e.jobs, j)
	return j
}

func (e *fakeRouteEdge) ensureManagementRoutes(_ context.Context, st *app.RouteStore) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mgmt = append(e.mgmt, st)
}

func (e *fakeRouteEdge) setUpCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.setUps
}

func (e *fakeRouteEdge) jobList() []*fakeRouteSyncJob {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*fakeRouteSyncJob(nil), e.jobs...)
}

func (e *fakeRouteEdge) managementStores() []*app.RouteStore {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*app.RouteStore(nil), e.mgmt...)
}

// fakeRouteOpen fails `failures` times, then returns store.
type fakeRouteOpen struct {
	mu       sync.Mutex
	store    *app.RouteStore
	failures int
	opens    int
}

func (f *fakeRouteOpen) open(context.Context, *pgxpool.Pool) (*app.RouteStore, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens++
	if f.opens <= f.failures {
		return nil, errors.New("create table routes: connection reset")
	}
	return f.store, nil
}

func (f *fakeRouteOpen) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens
}

type fakeWakeTracker struct{}

func (fakeWakeTracker) IsInWakeMode(string) (string, int, bool) { return "", 0, false }

func routeAdminCtx() context.Context {
	return kmsKeyTestCtx("operator", "admin", "routes:read,routes:write")
}

// AC1 + Q13: while the route store is pending every route RPC answers
// UNAVAILABLE and Caddy is not touched — the legacy direct-to-Caddy
// fallback must not run for a store that is merely absent.
func TestAppRouteRecovery_RouteRPCsRefuseUnavailableWhilePendingAndTouchNoCaddy(t *testing.T) {
	caddy := newFakeCaddyAdmin(t)
	pm := app.NewProxyManager(caddy.srv.URL, "example.test")
	h := newRouteHostingWithEdge(pm, &fakeRouteEdge{})
	ns := &NetworkServer{routes: h.store(), proxyManager: pm, baseDomain: "example.test"}
	ctx := routeAdminCtx()
	active := false
	calls := map[string]func() error{
		"GetRoutes": func() error {
			_, err := ns.GetRoutes(ctx, &pb.GetRoutesRequest{})
			return err
		},
		"AddRoute": func() error {
			_, err := ns.AddRoute(ctx, &pb.AddRouteRequest{Domain: "demo", TargetIp: "10.0.0.9", TargetPort: 8080})
			return err
		},
		"UpdateRoute toggle": func() error {
			_, err := ns.UpdateRoute(ctx, &pb.UpdateRouteRequest{Domain: "demo", Active: &active})
			return err
		},
		"UpdateRoute target": func() error {
			_, err := ns.UpdateRoute(ctx, &pb.UpdateRouteRequest{Domain: "demo", TargetIp: "10.0.0.9", TargetPort: 9090})
			return err
		},
		"DeleteRoute": func() error {
			_, err := ns.DeleteRoute(ctx, &pb.DeleteRouteRequest{Domain: "demo"})
			return err
		},
	}
	for name, call := range calls {
		err := call()
		if code := status.Code(err); code != codes.Unavailable {
			t.Errorf("%s with the route store pending = %v (%v), want Unavailable", name, code, err)
		}
		if !errors.Is(err, errRouteStoreNotInstalled) {
			t.Errorf("%s error = %v, want errRouteStoreNotInstalled", name, err)
		}
	}
	if n := caddy.hits.Load(); n != 0 {
		t.Errorf("Caddy admin API received %d request(s) while the route store was pending, want 0 (no route applied in memory)", n)
	}
}

// A daemon with no route persistence configured at all (no Postgres, or no
// Caddy) keeps the legacy direct-to-Caddy fallback: the refusal is for a
// store that is pending, not for one that was never configured.
func TestAppRouteRecovery_LegacyCaddyFallbackKeptWhenRoutePersistenceNotConfigured(t *testing.T) {
	caddy := newFakeCaddyAdmin(t)
	pm := app.NewProxyManager(caddy.srv.URL, "example.test")
	ns := &NetworkServer{proxyManager: pm, baseDomain: "example.test", emitter: events.NewEmitter(events.GetBus())}
	_, err := ns.DeleteRoute(routeAdminCtx(), &pb.DeleteRouteRequest{Domain: "demo"})
	if code := status.Code(err); code == codes.Unavailable {
		t.Fatalf("DeleteRoute with no route persistence configured = Unavailable, want the legacy Caddy fallback")
	}
	if n := caddy.hits.Load(); n == 0 {
		t.Fatal("Caddy admin API received no request: the legacy fallback did not run")
	}
}

// AC2: Postgres down then up. The family turns NOT_SERVING -> SERVING with
// no restart; the Caddy set-up runs once; the sync job is created once and,
// because the serving context arrived first, started with it from the
// install; the management routes are ensured once; stop() stops the job.
func TestAppRouteRecovery_FamilyInstallsOnceAndSyncJobStartsWithServingContext(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 1})
	edge := &fakeRouteEdge{}
	h := newRouteHostingWithEdge(nil, edge)
	open := &fakeRouteOpen{store: &app.RouteStore{}, failures: 1}
	f.r.Register(h.family(open.open))

	if got := f.status(t, routeStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness before recovery = %v, want NOT_SERVING", got)
	}
	if _, err := h.store().current(); !errors.Is(err, errRouteStoreNotInstalled) {
		t.Fatalf("current() before recovery = %v, want errRouteStoreNotInstalled", err)
	}
	if !f.r.holdsRestart() {
		t.Fatal("holdsRestart() = false with the route family pending")
	}

	type servingKey struct{}
	serving := context.WithValue(context.Background(), servingKey{}, "serving")
	h.start(serving)
	if n := len(edge.jobList()); n != 0 {
		t.Fatalf("sync jobs created before the store installed = %d, want 0", n)
	}

	f.runToCompletion(t, nil)

	if got := f.status(t, routeStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("readiness after recovery = %v, want SERVING", got)
	}
	if st, err := h.store().current(); err != nil || st != open.store {
		t.Errorf("current() after recovery = (%p, %v), want the installed store %p", st, err, open.store)
	}
	if n := open.count(); n != 2 {
		t.Errorf("open ran %d times, want 2 (one failure, one success, then never again)", n)
	}
	if n := edge.setUpCount(); n != 1 {
		t.Errorf("Caddy set-up ran %d times, want exactly 1 on the late install", n)
	}
	jobs := edge.jobList()
	if len(jobs) != 1 {
		t.Fatalf("sync jobs created = %d, want exactly 1", len(jobs))
	}
	if n := jobs[0].startCount(); n != 1 {
		t.Fatalf("sync job started %d times, want 1", n)
	}
	if got := jobs[0].starts[0].Value(servingKey{}); got != "serving" {
		t.Errorf("sync job started with context value %v, want the daemon's serving context, not the helper's", got)
	}
	if mg := edge.managementStores(); len(mg) != 1 || mg[0] != open.store {
		t.Errorf("management routes ensured with %v, want once with the installed store", mg)
	}
	h.start(serving) // a second start is a no-op
	if n := jobs[0].startCount(); n != 1 {
		t.Errorf("sync job started %d times after a second start, want still 1", n)
	}
	h.stop()
	if n := jobs[0].stopCount(); n != 1 {
		t.Errorf("sync job stopped %d times at shutdown, want 1", n)
	}
	if f.r.pending() || f.r.holdsRestart() {
		t.Error("family still pending or holding the restart after install")
	}
}

// The other order: the store installs (at boot, or late before Start) and
// the serving context arrives after. The job starts once, from start().
// A shutdown before anything served is a no-op that also keeps a later
// install or start from starting the job.
func TestAppRouteRecovery_InstallBeforeStartServesFromStart(t *testing.T) {
	t.Run("shutdown before serving starts nothing", func(t *testing.T) {
		edge := &fakeRouteEdge{}
		h := newRouteHostingWithEdge(nil, edge)
		h.stop()
		open := &fakeRouteOpen{store: &app.RouteStore{}}
		if err := h.family(open.open).Install(context.Background(), new(pgxpool.Pool)); err != nil {
			t.Fatalf("install: %v", err)
		}
		h.start(context.Background())
		if jobs := edge.jobList(); len(jobs) != 1 || jobs[0].startCount() != 0 {
			t.Errorf("sync job started after shutdown (jobs=%d)", len(jobs))
		}
	})
	edge := &fakeRouteEdge{}
	h := newRouteHostingWithEdge(nil, edge)
	open := &fakeRouteOpen{store: &app.RouteStore{}}
	if err := h.family(open.open).Install(context.Background(), new(pgxpool.Pool)); err != nil {
		t.Fatalf("install: %v", err)
	}
	jobs := edge.jobList()
	if len(jobs) != 1 {
		t.Fatalf("sync jobs created = %d, want 1", len(jobs))
	}
	if n := jobs[0].startCount(); n != 0 {
		t.Fatalf("sync job started %d times before the serving context arrived, want 0", n)
	}
	if n := len(edge.managementStores()); n != 0 {
		t.Fatalf("management routes ensured %d times before the serving context arrived, want 0", n)
	}
	h.start(context.Background())
	if n := jobs[0].startCount(); n != 1 {
		t.Errorf("sync job started %d times, want 1", n)
	}
	if n := len(edge.managementStores()); n != 1 {
		t.Errorf("management routes ensured %d times, want 1", n)
	}
	h.stop()
	if n := jobs[0].stopCount(); n != 1 {
		t.Errorf("sync job stopped %d times, want 1", n)
	}
}

// The helper never runs an install twice, but the once-guards are the
// family's own: a second install (a boot install that is retried by hand,
// say) swaps the newer store in without a second Caddy set-up or a second
// sync job.
func TestAppRouteRecovery_SecondInstallKeepsOneSetUpAndOneSyncJob(t *testing.T) {
	edge := &fakeRouteEdge{}
	h := newRouteHostingWithEdge(nil, edge)
	first, second := &app.RouteStore{}, &app.RouteStore{}
	for i, st := range []*app.RouteStore{first, second} {
		if err := h.family((&fakeRouteOpen{store: st}).open).Install(context.Background(), new(pgxpool.Pool)); err != nil {
			t.Fatalf("install %d: %v", i+1, err)
		}
	}
	if n := edge.setUpCount(); n != 1 {
		t.Errorf("Caddy set-up ran %d times over two installs, want 1", n)
	}
	if n := len(edge.jobList()); n != 1 {
		t.Errorf("sync jobs created over two installs = %d, want 1", n)
	}
	if st, _ := h.store().current(); st != second {
		t.Errorf("current() = %p after the second install, want the second store %p", st, second)
	}
}

// The wake tracker is wired in NewDualServer, before or after the store
// installs; the sync job sees it either way.
func TestAppRouteRecovery_WakeTrackerReachesSyncJobInEitherOrder(t *testing.T) {
	open := &fakeRouteOpen{store: &app.RouteStore{}}
	t.Run("tracker before install", func(t *testing.T) {
		edge := &fakeRouteEdge{}
		h := newRouteHostingWithEdge(nil, edge)
		h.setWakeTracker(fakeWakeTracker{})
		if err := h.family(open.open).Install(context.Background(), new(pgxpool.Pool)); err != nil {
			t.Fatalf("install: %v", err)
		}
		if edge.jobList()[0].wakeTracker() == nil {
			t.Error("sync job created after setWakeTracker has no wake tracker")
		}
	})
	t.Run("tracker after install", func(t *testing.T) {
		edge := &fakeRouteEdge{}
		h := newRouteHostingWithEdge(nil, edge)
		if err := h.family(open.open).Install(context.Background(), new(pgxpool.Pool)); err != nil {
			t.Fatalf("install: %v", err)
		}
		h.setWakeTracker(fakeWakeTracker{})
		if edge.jobList()[0].wakeTracker() == nil {
			t.Error("setWakeTracker after install did not reach the sync job")
		}
	})
}

// An open that fails on a connection or schema error is an ordinary
// failure, not a configuration refusal: the family holds the self-restart
// and is retried.
func TestAppRouteRecovery_OpenErrorIsNotAConfigRefusal(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	f.clock.stopAfter = 2 // one attempt, then the context ends
	h := newRouteHostingWithEdge(nil, &fakeRouteEdge{})
	open := &fakeRouteOpen{store: &app.RouteStore{}, failures: 100}
	f.r.Register(h.family(open.open))
	f.r.Run(f.ctx, nil)
	if n := open.count(); n != 1 {
		t.Fatalf("open ran %d times, want 1", n)
	}
	if !f.r.pending() || !f.r.holdsRestart() {
		t.Errorf("pending=%v holdsRestart=%v after an open error, want both true", f.r.pending(), f.r.holdsRestart())
	}
	if got := f.status(t, routeStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("readiness = %v, want NOT_SERVING", got)
	}
	_, err := open.open(context.Background(), nil)
	if isStoreConfigRefusal(err) {
		t.Error("an open error is reported as a config refusal")
	}
}

// Consumers that read the route store through the live accessor fail
// closed while it is pending: no nil dereference, an UNAVAILABLE error,
// and ContainerServer's opportunistic readiness probe says "ready now".
func TestAppRouteRecovery_LiveRouteStoreConsumersFailClosedWhilePending(t *testing.T) {
	h := newRouteHostingWithEdge(nil, &fakeRouteEdge{})
	live := h.store()
	ctx := context.Background()
	if _, err := live.ListByContainer(ctx, "box"); !errors.Is(err, errRouteStoreNotInstalled) {
		t.Errorf("ListByContainer = %v, want errRouteStoreNotInstalled", err)
	}
	if err := live.Save(ctx, &app.RouteRecord{FullDomain: "a.example.test"}); !errors.Is(err, errRouteStoreNotInstalled) {
		t.Errorf("Save = %v, want errRouteStoreNotInstalled", err)
	}
	if err := live.Delete(ctx, "a.example.test"); !errors.Is(err, errRouteStoreNotInstalled) {
		t.Errorf("Delete = %v, want errRouteStoreNotInstalled", err)
	}
	if _, err := live.GetByDomain(ctx, "a.example.test"); !errors.Is(err, errRouteStoreNotInstalled) {
		t.Errorf("GetByDomain = %v, want errRouteStoreNotInstalled", err)
	}
	cs := &ContainerServer{routeStore: live}
	if cs.waitForContainerReady(ctx, "alice", "10.0.0.5", 0) {
		t.Error("waitForContainerReady with the route store pending reported a timeout, want ready now")
	}
	lookup := &routeLookupAdapter{store: live}
	if _, ok, err := lookup.ResolveByHost(ctx, "a.example.test:443"); ok || !errors.Is(err, errRouteStoreNotInstalled) {
		t.Errorf("ResolveByHost = (ok=%v, %v), want (false, errRouteStoreNotInstalled)", ok, err)
	}
	actuator := &cloudContainerActuator{routes: live}
	actuator.pruneRoutes(ctx, "box", nil) // must not panic with the store pending
}

// AC1 for the app-hosting family: the AppService is registered before the
// store exists and every RPC answers UNAVAILABLE until install swaps the
// real server in; the network server's app lister fails closed the same way.
func TestAppRouteRecovery_AppServiceAnswersUnavailableUntilInstalled(t *testing.T) {
	a := newAppHosting(func(st *app.Store) *AppServer { return NewAppServer(nil, st) })
	ctx := kmsKeyTestCtx("alice", "member", "containers:read,containers:write")
	svc := a.service
	calls := map[string]func() error{
		"DeployApp": func() error {
			_, err := svc.DeployApp(ctx, &pb.DeployAppRequest{Username: "alice", AppName: "web", SourceTarball: []byte("x")})
			return err
		},
		"ListApps": func() error {
			_, err := svc.ListApps(ctx, &pb.ListAppsRequest{Username: "alice"})
			return err
		},
		"GetApp": func() error {
			_, err := svc.GetApp(ctx, &pb.GetAppRequest{Username: "alice", AppName: "web"})
			return err
		},
		"StopApp": func() error {
			_, err := svc.StopApp(ctx, &pb.StopAppRequest{Username: "alice", AppName: "web"})
			return err
		},
		"StartApp": func() error {
			_, err := svc.StartApp(ctx, &pb.StartAppRequest{Username: "alice", AppName: "web"})
			return err
		},
		"RestartApp": func() error {
			_, err := svc.RestartApp(ctx, &pb.RestartAppRequest{Username: "alice", AppName: "web"})
			return err
		},
		"DeleteApp": func() error {
			_, err := svc.DeleteApp(ctx, &pb.DeleteAppRequest{Username: "alice", AppName: "web"})
			return err
		},
		"GetAppLogs": func() error {
			return svc.GetAppLogs(&pb.GetAppLogsRequest{Username: "alice", AppName: "web"}, nil)
		},
	}
	for name, call := range calls {
		err := call()
		if code := status.Code(err); code != codes.Unavailable {
			t.Errorf("%s before install = %v (%v), want Unavailable", name, code, err)
		}
		if !errors.Is(err, errAppHostingNotInstalled) {
			t.Errorf("%s error = %v, want errAppHostingNotInstalled", name, err)
		}
	}
	if _, err := a.lister().List(ctx, "alice", pb.AppState_APP_STATE_UNSPECIFIED); !errors.Is(err, errAppHostingNotInstalled) {
		t.Errorf("app lister before install = %v, want errAppHostingNotInstalled", err)
	}

	// Install hands the real server in. With a nil manager it answers as a
	// disabled AppServer does (ListApps: an empty list), which is not the
	// stand-in's refusal: the call reached the installed server.
	installed := &app.Store{}
	a.install(installed)
	resp, err := svc.ListApps(ctx, &pb.ListAppsRequest{Username: "alice"})
	if err != nil || resp == nil {
		t.Fatalf("ListApps after install = (%v, %v), want the installed server's answer", resp, err)
	}
	if st := a.current(); st != installed {
		t.Errorf("current app store = %p, want the installed %p", st, installed)
	}
}

// The app-hosting family on the helper: NOT_SERVING -> SERVING, installed
// once, the AppService live after.
func TestAppRouteRecovery_AppHostingFamilyRecovers(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 1})
	a := newAppHosting(func(st *app.Store) *AppServer { return NewAppServer(nil, st) })
	var opens atomic.Int32
	store := &app.Store{}
	f.r.Register(a.family(func(context.Context, *pgxpool.Pool) (*app.Store, error) {
		opens.Add(1)
		return store, nil
	}))
	if got := f.status(t, appHostingStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness before recovery = %v, want NOT_SERVING", got)
	}
	f.runToCompletion(t, nil)
	if got := f.status(t, appHostingStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("readiness after recovery = %v, want SERVING", got)
	}
	if n := opens.Load(); n != 1 {
		t.Errorf("open ran %d times, want 1", n)
	}
	if a.current() != store {
		t.Error("the installed app store is not the one the live accessor returns")
	}
	ctx := kmsKeyTestCtx("alice", "member", "containers:read")
	if _, err := a.service.ListApps(ctx, &pb.ListAppsRequest{Username: "alice"}); err != nil {
		t.Errorf("ListApps after install = %v, want the installed server's answer", err)
	}
}
