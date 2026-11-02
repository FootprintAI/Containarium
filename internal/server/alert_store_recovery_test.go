//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/alert"
	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3334: the alert store, rules manager and delivery store, and the
// credential-expiry watch, as late-install families on the #3326 helper.
// With Postgres down at startup the alert RPCs that need the store answer
// UNAVAILABLE and the readiness entries are NOT_SERVING; once Postgres
// answers both install with no restart, the rules are synced once, the
// watcher starts exactly once with the daemon's context and does not re-fire
// a state Postgres already holds. A delivery raised before the store arrives
// is logged and counted, never buffered (#3335 Q15). Without VictoriaMetrics
// (or Postgres, or the daemon config store) a family does not exist and is
// not pending.

// fakeAlertRules is an in-memory alertRuleStore.
type fakeAlertRules struct {
	mu    sync.Mutex
	rules map[string]*alert.AlertRule
	next  int
}

func newFakeAlertRules(seed ...*alert.AlertRule) *fakeAlertRules {
	f := &fakeAlertRules{rules: map[string]*alert.AlertRule{}}
	for _, r := range seed {
		f.rules[r.ID] = r
	}
	return f
}

func (f *fakeAlertRules) Create(_ context.Context, r *alert.AlertRule) (*alert.AlertRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	c := *r
	c.ID = fmt.Sprintf("rule-%d", f.next)
	f.rules[c.ID] = &c
	return &c, nil
}

func (f *fakeAlertRules) Get(_ context.Context, id string) (*alert.AlertRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rules[id]
	if !ok {
		return nil, fmt.Errorf("alert rule not found: %s", id)
	}
	c := *r
	return &c, nil
}

func (f *fakeAlertRules) List(context.Context) ([]*alert.AlertRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*alert.AlertRule, 0, len(f.rules))
	for _, r := range f.rules {
		c := *r
		out = append(out, &c)
	}
	return out, nil
}

func (f *fakeAlertRules) Update(_ context.Context, r *alert.AlertRule) (*alert.AlertRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := *r
	f.rules[r.ID] = &c
	return &c, nil
}

func (f *fakeAlertRules) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rules, id)
	return nil
}

// fakeAlertSyncer counts rule syncs.
type fakeAlertSyncer struct {
	mu    sync.Mutex
	syncs int
}

func (f *fakeAlertSyncer) SyncRules(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncs++
	return nil
}

func (f *fakeAlertSyncer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.syncs
}

// fakeDeliveryLog is an in-memory alertDeliveryLog.
type fakeDeliveryLog struct {
	mu   sync.Mutex
	recs []alert.WebhookDelivery
}

func (f *fakeDeliveryLog) Record(_ context.Context, d *alert.WebhookDelivery) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recs = append(f.recs, *d)
	return nil
}

func (f *fakeDeliveryLog) List(context.Context, int, int) ([]alert.WebhookDelivery, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]alert.WebhookDelivery(nil), f.recs...), len(f.recs), nil
}

func (f *fakeDeliveryLog) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.recs)
}

// fakeAlertOpen opens the fake backends and records each pool it was
// handed, so the test can tell the shared pool from a fresh dial.
type fakeAlertOpen struct {
	mu      sync.Mutex
	rules   *fakeAlertRules
	syncer  *fakeAlertSyncer
	deliv   *fakeDeliveryLog
	pools   []*pgxpool.Pool
	failErr error // returned (once) instead of the backends
}

func newFakeAlertOpen() *fakeAlertOpen {
	return &fakeAlertOpen{
		rules:  newFakeAlertRules(&alert.AlertRule{ID: "rule-0", Name: "HighCPU", Expr: "cpu > 90", Duration: "5m", Severity: alert.SeverityWarning}),
		syncer: &fakeAlertSyncer{},
		deliv:  &fakeDeliveryLog{},
	}
}

func (f *fakeAlertOpen) open(_ context.Context, pool *pgxpool.Pool) (*alertBackends, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pools = append(f.pools, pool)
	if err := f.failErr; err != nil {
		f.failErr = nil
		return nil, err
	}
	return &alertBackends{rules: f.rules, syncer: f.syncer, deliveries: f.deliv}, nil
}

func (f *fakeAlertOpen) opens() []*pgxpool.Pool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pgxpool.Pool(nil), f.pools...)
}

func adminAlertsCtx() context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{auth.RoleAdmin}, []string{auth.ScopeAlertsRead, auth.ScopeAlertsWrite})
}

// alertStoreRPCs are the alert RPCs that need the store, as an admin.
func alertStoreRPCs(cs *ContainerServer) map[string]func() error {
	ctx := adminAlertsCtx()
	return map[string]func() error{
		"CreateAlertRule": func() error {
			_, err := cs.CreateAlertRule(ctx, &pb.CreateAlertRuleRequest{Name: "Disk", Expr: "disk > 90", Enabled: true})
			return err
		},
		"ListAlertRules": func() error {
			_, err := cs.ListAlertRules(ctx, &pb.ListAlertRulesRequest{})
			return err
		},
		"GetAlertRule": func() error {
			_, err := cs.GetAlertRule(ctx, &pb.GetAlertRuleRequest{Id: "rule-0"})
			return err
		},
		"UpdateAlertRule": func() error {
			_, err := cs.UpdateAlertRule(ctx, &pb.UpdateAlertRuleRequest{Id: "rule-0", Name: "HighCPU", Expr: "cpu > 95", Duration: "5m", Severity: alert.SeverityWarning})
			return err
		},
		"DeleteAlertRule": func() error {
			_, err := cs.DeleteAlertRule(ctx, &pb.DeleteAlertRuleRequest{Id: "rule-x"})
			return err
		},
		"UpdateAlertingConfig": func() error {
			_, err := cs.UpdateAlertingConfig(ctx, &pb.UpdateAlertingConfigRequest{WebhookUrl: "https://hooks.example.com/x"})
			return err
		},
		"ListWebhookDeliveries": func() error {
			_, err := cs.ListWebhookDeliveries(ctx, &pb.ListWebhookDeliveriesRequest{Limit: 10})
			return err
		},
	}
}

func failingConnect() (*pgxpool.Pool, error) {
	return nil, errors.New("dial tcp: connection refused")
}

func alertSetup(open openAlertBackendsFunc, connect func() (*pgxpool.Pool, error)) alertFamilySetup {
	return alertFamilySetup{
		PostgresDSN:        "postgres://unused",
		VictoriaMetricsURL: "http://vm.example.com:8428",
		WebhookURL:         "https://hooks.example.com/alerts",
		Connect:            connect,
		Open:               open,
	}
}

// AC1 + AC2 + AC3: Postgres down at start => containarium.alerts is
// NOT_SERVING and every store-backed alert RPC answers UNAVAILABLE (saying
// it is pending, not unconfigured). Postgres answers => the family installs
// over the shared pool with no restart, readiness turns SERVING, the rules
// are synced once (as at boot), and the RPCs serve.
func TestAlertRecovery_DegradedStartThenInstalledInProcess(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 1})
	cs := &ContainerServer{}
	op := newFakeAlertOpen()

	if pool := setupAlertFamily(f.r, cs, alertSetup(op.open, failingConnect)); pool != nil {
		t.Fatal("setupAlertFamily returned a startup pool after a failed connect")
	}

	if got := f.status(t, alertStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness %s before recovery = %v, want NOT_SERVING", alertStoreService, got)
	}
	if _, ok := f.readiness.entries[alertStoreService]; !ok {
		t.Fatalf("%s not published to the readiness registry", alertStoreService)
	}
	if !f.r.pending() || !f.r.holdsRestart() {
		t.Fatal("alert family is not pending / does not hold the self-restart while Postgres is down")
	}
	for name, call := range alertStoreRPCs(cs) {
		err := call()
		if status.Code(err) != codes.Unavailable {
			t.Errorf("%s before recovery: %v, want UNAVAILABLE", name, err)
			continue
		}
		if status.Convert(err).Message() != status.Convert(errAlertsNotInstalled).Message() {
			t.Errorf("%s before recovery: %q, want the pending message naming readiness %s", name, status.Convert(err).Message(), alertStoreService)
		}
	}
	info, err := cs.GetAlertingInfo(adminAlertsCtx(), &pb.GetAlertingInfoRequest{})
	if err != nil || info.Enabled {
		t.Fatalf("GetAlertingInfo before recovery = %+v, %v; want Enabled=false, no error", info, err)
	}
	if op.syncer.count() != 0 {
		t.Fatalf("rules synced %d times before the store installed", op.syncer.count())
	}

	f.runToCompletion(t, nil)

	if got := f.status(t, alertStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness %s after recovery = %v, want SERVING", alertStoreService, got)
	}
	if n := op.syncer.count(); n != 1 {
		t.Fatalf("initial rule syncs on late install = %d, want 1", n)
	}
	pools := op.opens()
	if len(pools) != 1 || pools[0] == nil {
		t.Fatalf("opened over pools %v, want once over the helper's shared pool", pools)
	}
	if f.pg.dialCount() != 2 {
		t.Fatalf("helper dials = %d, want 2 (one refused, one shared pool)", f.pg.dialCount())
	}

	ctx := adminAlertsCtx()
	list, err := cs.ListAlertRules(ctx, &pb.ListAlertRulesRequest{})
	if err != nil || len(list.Rules) != 1 || list.Rules[0].Name != "HighCPU" {
		t.Fatalf("ListAlertRules after recovery = %+v, %v; want the stored rule", list, err)
	}
	if _, err := cs.CreateAlertRule(ctx, &pb.CreateAlertRuleRequest{Name: "Disk", Expr: "disk > 90", Enabled: true}); err != nil {
		t.Fatalf("CreateAlertRule after recovery: %v", err)
	}
	if n := op.syncer.count(); n != 2 {
		t.Fatalf("rule syncs after a create = %d, want 2 (install + create)", n)
	}
	if _, err := cs.ListWebhookDeliveries(ctx, &pb.ListWebhookDeliveriesRequest{}); err != nil {
		t.Fatalf("ListWebhookDeliveries after recovery: %v", err)
	}
	info, err = cs.GetAlertingInfo(ctx, &pb.GetAlertingInfoRequest{})
	if err != nil || !info.Enabled {
		t.Fatalf("GetAlertingInfo after recovery = %+v, %v; want Enabled", info, err)
	}
	if !logsContain(f.logs, "Store family containarium.alerts: Postgres store installed in-process") {
		t.Errorf("no in-process install line; logs: %q", f.logs.all())
	}
}

// A failed open (Postgres up, schema not) leaves nothing installed; the
// next attempt installs.
func TestAlertRecovery_FailedOpenIsRetried(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	cs := &ContainerServer{}
	op := newFakeAlertOpen()
	op.failErr = errors.New("create table alert_rules: permission denied")

	setupAlertFamily(f.r, cs, alertSetup(op.open, failingConnect))
	f.runToCompletion(t, nil)

	if n := len(op.opens()); n != 2 {
		t.Fatalf("opens = %d, want 2 (one failed, one installed)", n)
	}
	if cs.loadAlerts() == nil {
		t.Fatal("alert family not installed after the retry")
	}
	if n := op.syncer.count(); n != 1 {
		t.Fatalf("rule syncs = %d, want 1 (the failed attempt installs nothing)", n)
	}
}

// Postgres up at startup: installed and SERVING at once, synced once, not
// pending, and the startup pool is returned for shutdown.
func TestAlertRecovery_StartupInstall(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	cs := &ContainerServer{}
	op := newFakeAlertOpen()
	boot := new(pgxpool.Pool)

	got := setupAlertFamily(f.r, cs, alertSetup(op.open, func() (*pgxpool.Pool, error) { return boot, nil }))
	if got != boot {
		t.Fatal("setupAlertFamily did not return the startup pool for shutdown")
	}
	if f.status(t, alertStoreService) != healthpb.HealthCheckResponse_SERVING {
		t.Fatal("startup install is not SERVING")
	}
	if f.r.pending() {
		t.Fatal("startup install left the family pending")
	}
	if cs.loadAlerts() == nil || op.syncer.count() != 1 {
		t.Fatalf("startup install: installed=%v syncs=%d; want installed, 1 sync", cs.loadAlerts() != nil, op.syncer.count())
	}
}

// Beyond the ACs (addendum): no VictoriaMetrics URL, or no Postgres, means
// the family does not exist. It is not pending, does not hold the restart,
// has no readiness entry, never dials, and the RPCs keep their old
// not-configured answers.
func TestAlertRecovery_NotConfiguredIsNotPending(t *testing.T) {
	for _, tc := range []struct{ name, dsn, vm string }{
		{"no VictoriaMetrics", "postgres://unused", ""},
		{"no Postgres", "", "http://vm.example.com:8428"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStoreRecoveryFixture(t, &fakePostgres{})
			cs := &ContainerServer{}
			op := newFakeAlertOpen()
			dialed := false
			c := alertSetup(op.open, func() (*pgxpool.Pool, error) { dialed = true; return nil, errors.New("unexpected dial") })
			c.PostgresDSN, c.VictoriaMetricsURL = tc.dsn, tc.vm

			if pool := setupAlertFamily(f.r, cs, c); pool != nil || dialed {
				t.Fatalf("unconfigured family dialed=%v pool=%v", dialed, pool)
			}
			if f.r.pending() {
				t.Fatal("an unconfigured alert family is pending")
			}
			if _, ok := f.readiness.entries[alertStoreService]; ok {
				t.Fatal("an unconfigured alert family published a readiness entry")
			}
			if _, err := f.health.Check(context.Background(), &healthpb.HealthCheckRequest{Service: alertStoreService}); status.Code(err) != codes.NotFound {
				t.Fatalf("health %s = %v, want NotFound (no entry)", alertStoreService, err)
			}
			ctx := adminAlertsCtx()
			if resp, err := cs.ListAlertRules(ctx, &pb.ListAlertRulesRequest{}); err != nil || len(resp.Rules) != 0 {
				t.Fatalf("ListAlertRules unconfigured = %v, %v; want empty, no error", resp, err)
			}
			if _, err := cs.CreateAlertRule(ctx, &pb.CreateAlertRuleRequest{Name: "x", Expr: "y"}); status.Convert(err).Message() != "alerting is not configured" {
				t.Fatalf("CreateAlertRule unconfigured = %v, want 'alerting is not configured'", err)
			}
		})
	}
}

// The manager needs an Incus client; without one the install is a
// configuration refusal (#3378), checked before Postgres is touched: the
// family stays pending and NOT_SERVING but does not hold the self-restart.
func TestAlertRecovery_IncusFailureIsConfigRefusal(t *testing.T) {
	open := openAlertBackends(func() (*incus.Client, error) { return nil, errors.New("incus socket not found") })
	// A zero pool panics if used, so a refusal that touched Postgres first
	// fails this test loudly.
	_, err := open(context.Background(), new(pgxpool.Pool))
	if !isStoreConfigRefusal(err) {
		t.Fatalf("open without Incus = %v, want a storeConfigRefusal", err)
	}

	f := newStoreRecoveryFixture(t, &fakePostgres{})
	f.clock.stopAfter = 3
	cs := &ContainerServer{}
	setupAlertFamily(f.r, cs, alertSetup(open, failingConnect))
	f.r.Run(f.ctx, nil)

	if cs.loadAlerts() != nil {
		t.Fatal("alert family installed without an Incus client")
	}
	if f.status(t, alertStoreService) != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatal("refused alert family is not NOT_SERVING")
	}
	if !f.r.pending() || f.r.holdsRestart() {
		t.Fatalf("refused family: pending=%v holdsRestart=%v; want pending, not holding", f.r.pending(), f.r.holdsRestart())
	}
}

// Q15 (#3335): a delivery raised while the store is pending is logged as one
// structured line and counted, and NOT buffered: after the install the store
// holds only deliveries raised after it. With alerting not configured a
// delivery is neither logged nor counted, as before.
func TestAlertRecovery_DeliveriesBeforeInstallAreLoggedAndCountedNotBuffered(t *testing.T) {
	std := captureStdLog(t)
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	cs := &ContainerServer{}
	op := newFakeAlertOpen()
	setupAlertFamily(f.r, cs, alertSetup(op.open, failingConnect))

	ctx := context.Background()
	cs.recordRelayDelivery(ctx, "HostDown", "relay", "https://hooks.example.com/***", true, 200, "", 512, 40)
	cs.recordRelayDelivery(ctx, "DiskFull", "relay", "https://hooks.example.com/***", false, 502, "bad gateway", 300, 900)

	if n := cs.unrecordedAlertDeliveries(); n != 2 {
		t.Fatalf("unrecorded deliveries = %d, want 2", n)
	}
	if n := std.count("alert_delivery_unrecorded store=containarium.alerts state=pending"); n != 2 {
		t.Fatalf("structured pending lines = %d, want 2", n)
	}
	if std.count(`alert="DiskFull" source="relay" success=false http_status=502 unrecorded_total=2`) != 1 {
		t.Errorf("pending line does not carry the delivery's fields and running count")
	}

	f.runToCompletion(t, nil)

	if n := op.deliv.count(); n != 0 {
		t.Fatalf("store holds %d deliveries after install, want 0 (no buffering, Q15)", n)
	}
	if !logsContain(f.logs, "2 alert delivery record(s) raised while it was pending were logged, not recorded") {
		t.Errorf("install line does not report the count; logs: %q", f.logs.all())
	}
	cs.recordRelayDelivery(ctx, "HostDown", "relay", "https://hooks.example.com/***", true, 200, "", 512, 40)
	if n := op.deliv.count(); n != 1 {
		t.Fatalf("deliveries recorded after install = %d, want 1", n)
	}
	if n := cs.unrecordedAlertDeliveries(); n != 2 {
		t.Fatalf("unrecorded count changed after install: %d", n)
	}

	unconfigured := &ContainerServer{}
	unconfigured.recordRelayDelivery(ctx, "HostDown", "relay", "u", true, 200, "", 1, 1)
	if n := unconfigured.unrecordedAlertDeliveries(); n != 0 {
		t.Fatalf("unconfigured alerting counted %d deliveries, want 0", n)
	}
	if n := std.count("alert_delivery_unrecorded"); n != 2 {
		t.Fatalf("unconfigured alerting logged a pending line (total %d, want 2)", n)
	}
}

// The install swaps the family in while RPCs and deliveries run; -race
// catches a plain field.
func TestAlertRecovery_SwapIsRaceSafe(t *testing.T) {
	_ = captureStdLog(t)
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	cs := &ContainerServer{}
	op := newFakeAlertOpen()
	setupAlertFamily(f.r, cs, alertSetup(op.open, failingConnect))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := adminAlertsCtx()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = cs.ListAlertRules(ctx, &pb.ListAlertRulesRequest{})
				_, _ = cs.GetAlertingInfo(ctx, &pb.GetAlertingInfoRequest{})
				cs.recordRelayDelivery(ctx, "A", "relay", "u", true, 200, "", 1, 1)
			}
		}()
	}
	f.runToCompletion(t, nil)
	close(stop)
	wg.Wait()
	if cs.loadAlerts() == nil {
		t.Fatal("not installed")
	}
}

// fakeWatchRunner records Start/Stop calls.
type fakeWatchRunner struct {
	mu     sync.Mutex
	starts []context.Context
	stops  int
}

func (r *fakeWatchRunner) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.starts = append(r.starts, ctx)
}

func (r *fakeWatchRunner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stops++
}

func (r *fakeWatchRunner) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.starts), r.stops
}

type daemonCtxKey struct{}

func watchSetup(open openCredentialWatchFunc, connect func() (*pgxpool.Pool, error)) credentialWatchSetup {
	return credentialWatchSetup{
		PostgresDSN:  "postgres://unused",
		DaemonConfig: &app.DaemonConfigStore{},
		Connect:      connect,
		Open:         open,
	}
}

// AC1/AC2 for the watch: NOT_SERVING while Postgres is down and nothing runs
// even after the daemon starts; the late install turns SERVING and starts
// the watcher exactly once, with the daemon's serving context (not the
// helper's). A second start or install does not start it again.
func TestCredentialWatchRecovery_DegradedStartThenStartsOnce(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 1})
	runner := &fakeWatchRunner{}
	cw := &credentialWatch{}
	opens := 0
	open := func(context.Context, *pgxpool.Pool) (credentialWatchRunner, error) { opens++; return runner, nil }

	setupCredentialWatchFamily(f.r, cw, watchSetup(open, failingConnect))
	if f.status(t, credentialWatchService) != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatal("credential watch is not NOT_SERVING while Postgres is down")
	}

	daemonCtx, cancel := context.WithCancel(context.WithValue(context.Background(), daemonCtxKey{}, "daemon"))
	defer cancel()
	cw.start(daemonCtx) // DualServer.Start runs before Postgres answers
	if s, _ := runner.counts(); s != 0 {
		t.Fatal("watcher started before it was installed")
	}

	f.runToCompletion(t, nil)
	if f.status(t, credentialWatchService) != healthpb.HealthCheckResponse_SERVING {
		t.Fatal("credential watch is not SERVING after recovery")
	}
	cw.start(daemonCtx)
	cw.setRunner(&fakeWatchRunner{})
	starts, _ := runner.counts()
	if starts != 1 || opens != 1 {
		t.Fatalf("watcher starts=%d opens=%d, want exactly 1 each", starts, opens)
	}
	if runner.starts[0].Value(daemonCtxKey{}) != "daemon" {
		t.Fatal("watcher was not started with the daemon's serving context")
	}

	cw.stop()
	if _, stops := runner.counts(); stops != 1 {
		t.Fatalf("stops = %d, want 1", stops)
	}
}

// The install may also land before Start; the watcher then starts at Start.
// After stop it never starts.
func TestCredentialWatch_StartOrderAndStop(t *testing.T) {
	r1 := &fakeWatchRunner{}
	cw := &credentialWatch{}
	cw.setRunner(r1)
	if s, _ := r1.counts(); s != 0 {
		t.Fatal("started without the serving context")
	}
	cw.start(context.Background())
	if s, _ := r1.counts(); s != 1 {
		t.Fatal("not started once the serving context arrived")
	}

	r2 := &fakeWatchRunner{}
	stopped := &credentialWatch{}
	stopped.stop()
	stopped.setRunner(r2)
	stopped.start(context.Background())
	if s, st := r2.counts(); s != 0 || st != 0 {
		t.Fatalf("stopped watch: starts=%d stops=%d, want none", s, st)
	}

	var nilWatch *credentialWatch
	nilWatch.start(context.Background())
	nilWatch.setRunner(r2)
	nilWatch.stop()
}

// Beyond the ACs (addendum): no Postgres or no daemon config store means the
// watch family does not exist and is not pending.
func TestCredentialWatchRecovery_NotConfiguredIsNotPending(t *testing.T) {
	for _, tc := range []struct {
		name string
		dsn  string
		dcs  *app.DaemonConfigStore
	}{
		{"no Postgres", "", &app.DaemonConfigStore{}},
		{"no daemon config store", "postgres://unused", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStoreRecoveryFixture(t, &fakePostgres{})
			dialed := false
			c := watchSetup(func(context.Context, *pgxpool.Pool) (credentialWatchRunner, error) {
				return &fakeWatchRunner{}, nil
			}, func() (*pgxpool.Pool, error) { dialed = true; return nil, errors.New("unexpected dial") })
			c.PostgresDSN, c.DaemonConfig = tc.dsn, tc.dcs
			setupCredentialWatchFamily(f.r, &credentialWatch{}, c)
			if dialed || f.r.pending() {
				t.Fatalf("unconfigured watch: dialed=%v pending=%v", dialed, f.r.pending())
			}
			if _, ok := f.readiness.entries[credentialWatchService]; ok {
				t.Fatal("unconfigured watch published a readiness entry")
			}
		})
	}
}

// fakeCredProber serves fixed targets and sources.
type fakeCredProber struct {
	targets []alert.CredentialWatchTarget
	src     map[string]pb.CodeCredentialSource
}

func (p *fakeCredProber) CredentialWatchTargets(context.Context) ([]alert.CredentialWatchTarget, error) {
	return p.targets, nil
}

func (p *fakeCredProber) ProbeCredential(_ context.Context, t alert.CredentialWatchTarget) (pb.CodeCredentialSource, error) {
	return p.src[t.SkillID], nil
}

// fakeCredState is the Postgres last-seen table, in memory.
type fakeCredState struct {
	mu    sync.Mutex
	seen  map[string]pb.CodeCredentialSource
	reads map[string]int
}

func (s *fakeCredState) LastSeen(_ context.Context, id string) (pb.CodeCredentialSource, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads[id]++
	src, ok := s.seen[id]
	return src, ok, nil
}

func (s *fakeCredState) Record(_ context.Context, id string, src pb.CodeCredentialSource, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[id] = src
	return nil
}

func (s *fakeCredState) readCount(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads[id]
}

type fakeCredNotifier struct {
	mu     sync.Mutex
	alerts []alert.CredentialExpiredAlert
}

func (n *fakeCredNotifier) NotifyCredentialExpired(_ context.Context, a alert.CredentialExpiredAlert) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.alerts = append(n.alerts, a)
}

func (n *fakeCredNotifier) sent() []alert.CredentialExpiredAlert {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]alert.CredentialExpiredAlert(nil), n.alerts...)
}

// Beyond the ACs (addendum): the late-installed watcher reads its last-seen
// state from Postgres before alerting, so a box whose expiry was alerted
// before the outage is not alerted again, while a box seen expired for the
// first time (the control that proves the sweep ran) is alerted once.
func TestCredentialWatchRecovery_LateInstallDoesNotRefireRecordedState(t *testing.T) {
	expired := pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_EXPIRED
	prober := &fakeCredProber{
		targets: []alert.CredentialWatchTarget{
			{SkillID: "skill-alerted", Box: "box-a"},
			{SkillID: "skill-new", Box: "box-b"},
		},
		src: map[string]pb.CodeCredentialSource{"skill-alerted": expired, "skill-new": expired},
	}
	state := &fakeCredState{
		seen:  map[string]pb.CodeCredentialSource{"skill-alerted": expired}, // alerted before the outage
		reads: map[string]int{},
	}
	notifier := &fakeCredNotifier{}

	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 1})
	cw := &credentialWatch{}
	open := func(context.Context, *pgxpool.Pool) (credentialWatchRunner, error) {
		return alert.NewCredentialWatcher(prober, state, notifier), nil
	}
	setupCredentialWatchFamily(f.r, cw, watchSetup(open, failingConnect))
	daemonCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cw.start(daemonCtx)
	f.runToCompletion(t, nil)

	deadline := time.Now().Add(10 * time.Second)
	for len(notifier.sent()) < 1 || state.readCount("skill-alerted") < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the first sweep did not run after the late install")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cw.stop() // waits for the sweep loop to exit

	sent := notifier.sent()
	if len(sent) != 1 || sent[0].SkillID != "skill-new" {
		t.Fatalf("alerts after late install = %+v, want exactly one, for skill-new", sent)
	}
	if state.readCount("skill-alerted") < 1 {
		t.Fatal("the watcher did not read skill-alerted's last-seen state")
	}
}

// NewDualServer hands both families to the helper, wires the gateway's relay
// deliveries to the live recorder, and Start starts the watch once with its
// serving context.
func TestNewDualServer_WiresAlertFamilies(t *testing.T) {
	calls := dualServerFuncCalls(t, "NewDualServer")
	for _, want := range []string{"setupAlertFamily", "setupCredentialWatchFamily", "openAlertBackends", "openCredentialWatch"} {
		if indexOfCall(calls, want) < 0 {
			t.Errorf("NewDualServer does not call %s", want)
		}
	}
	for _, want := range []string{
		"gatewayServer.SetRecordDeliveryFn(containerServer.recordRelayDelivery)",
		"ds.credentialWatch.start(ctx)",
		"ds.credentialWatch.stop()",
	} {
		if !dualServerSourceContains(t, want) {
			t.Errorf("dual_server.go is missing %q", want)
		}
	}
	for _, gone := range []string{"alert.NewCredentialWatcher(", "alert.NewStore(", "SetAlertDeliveryStore("} {
		if dualServerSourceContains(t, gone) {
			t.Errorf("dual_server.go still builds the alert family inline (%q); it must go through the helper", gone)
		}
	}
}
