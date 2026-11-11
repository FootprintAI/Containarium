//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/pentest"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3332: the security, pentest and ZAP scan stores and their managers as
// late-install families on the #3326 helper. With Postgres down at startup
// the three services are registered anyway and answer UNAVAILABLE,
// `containarium.security`, `containarium.pentest` and `containarium.zap` are
// NOT_SERVING, and nothing is pending for a scanner the configuration
// disables. Once Postgres answers the stores and managers install over the
// shared pool in the running daemon, readiness turns SERVING, the scanner
// loops start exactly once on the daemon's serving context, the pentest
// server is armed with the audit store as boot arms it, and the managers
// read the route store through the live accessor from #3331. A failed Incus
// client is a configuration refusal, checked before Postgres is touched.

// fakeRegistrar records the gRPC services NewDualServer would register.
type fakeRegistrar struct {
	mu    sync.Mutex
	impls map[string]any
}

func (r *fakeRegistrar) RegisterService(desc *grpc.ServiceDesc, impl any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.impls == nil {
		r.impls = map[string]any{}
	}
	r.impls[desc.ServiceName] = impl
}

func (r *fakeRegistrar) registered(name string) (any, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	impl, ok := r.impls[name]
	return impl, ok
}

func (r *fakeRegistrar) security(t *testing.T) pb.SecurityServiceServer {
	t.Helper()
	impl, ok := r.registered(pb.SecurityService_ServiceDesc.ServiceName)
	if !ok {
		t.Fatal("SecurityService was not registered")
	}
	return impl.(pb.SecurityServiceServer)
}

func (r *fakeRegistrar) pentest(t *testing.T) pb.PentestServiceServer {
	t.Helper()
	impl, ok := r.registered(pb.PentestService_ServiceDesc.ServiceName)
	if !ok {
		t.Fatal("PentestService was not registered")
	}
	return impl.(pb.PentestServiceServer)
}

func (r *fakeRegistrar) zap(t *testing.T) pb.ZapServiceServer {
	t.Helper()
	impl, ok := r.registered(pb.ZapService_ServiceDesc.ServiceName)
	if !ok {
		t.Fatal("ZapService was not registered")
	}
	return impl.(pb.ZapServiceServer)
}

// fakeScanRunner records the contexts it was started with.
type fakeScanRunner struct {
	mu     sync.Mutex
	starts []context.Context
	stops  int
}

func (r *fakeScanRunner) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.starts = append(r.starts, ctx)
}

func (r *fakeScanRunner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stops++
}

func (r *fakeScanRunner) startContexts() []context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]context.Context(nil), r.starts...)
}

func (r *fakeScanRunner) stopCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stops
}

// fakeScanOpeners are the three families' openers under test: each records
// the pool it was handed and serves one server and one runner.
type fakeScanOpeners struct {
	mu       sync.Mutex
	pools    map[string][]*pgxpool.Pool
	fail     map[string]error
	security *SecurityServer
	pentest  *PentestServer
	zap      *ZapServer
	runners  map[string]*fakeScanRunner
}

func newFakeScanOpeners() *fakeScanOpeners {
	return &fakeScanOpeners{
		pools:    map[string][]*pgxpool.Pool{},
		fail:     map[string]error{},
		security: NewSecurityServer(nil, nil, nil),
		pentest:  NewPentestServer(nil, nil),
		zap:      NewZapServer(nil, nil),
		runners: map[string]*fakeScanRunner{
			securityScanService: {}, pentestScanService: {}, zapScanService: {},
		},
	}
}

func (o *fakeScanOpeners) record(service string, pool *pgxpool.Pool) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pools[service] = append(o.pools[service], pool)
	return o.fail[service]
}

func (o *fakeScanOpeners) openSecurity(_ context.Context, pool *pgxpool.Pool) (*SecurityServer, scanRunner, error) {
	if err := o.record(securityScanService, pool); err != nil {
		return nil, nil, err
	}
	return o.security, o.runners[securityScanService], nil
}

func (o *fakeScanOpeners) openPentest(_ context.Context, pool *pgxpool.Pool) (*PentestServer, scanRunner, error) {
	if err := o.record(pentestScanService, pool); err != nil {
		return nil, nil, err
	}
	return o.pentest, o.runners[pentestScanService], nil
}

func (o *fakeScanOpeners) openZap(_ context.Context, pool *pgxpool.Pool) (*ZapServer, scanRunner, error) {
	if err := o.record(zapScanService, pool); err != nil {
		return nil, nil, err
	}
	return o.zap, o.runners[zapScanService], nil
}

func (o *fakeScanOpeners) seenPools(service string) []*pgxpool.Pool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]*pgxpool.Pool(nil), o.pools[service]...)
}

func (o *fakeScanOpeners) setup(connect func() (*pgxpool.Pool, error)) scanStoreSetup {
	return scanStoreSetup{
		PostgresDSN:  "postgres://unused",
		Connect:      connect,
		OpenSecurity: o.openSecurity,
		OpenPentest:  o.openPentest,
		OpenZap:      o.openZap,
	}
}

// poolCloser records closed pools without touching a zero pgxpool.Pool,
// whose Close panics.
type poolCloser struct {
	mu     sync.Mutex
	closed []*pgxpool.Pool
}

func (c *poolCloser) close(p *pgxpool.Pool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = append(c.closed, p)
}

func (c *poolCloser) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.closed)
}

func scanConnectRefused() (*pgxpool.Pool, error) {
	return nil, errors.New("dial tcp: connection refused")
}

// assertScanRPCsUnavailable calls one store-backed RPC per scan service, as
// an admin allowed to make it, and wants UNAVAILABLE from each.
func assertScanRPCsUnavailable(t *testing.T, reg *fakeRegistrar) {
	t.Helper()
	ctx := kmsKeyTestCtx("op", "admin", "security:read")
	calls := map[string]func() error{
		"GetScanStatus": func() error {
			_, err := reg.security(t).GetScanStatus(ctx, &pb.GetScanStatusRequest{})
			return err
		},
		"GetPentestConfig": func() error {
			_, err := reg.pentest(t).GetPentestConfig(ctx, &pb.GetPentestConfigRequest{})
			return err
		},
		"GetZapConfig": func() error {
			_, err := reg.zap(t).GetZapConfig(ctx, &pb.GetZapConfigRequest{})
			return err
		},
	}
	for name, call := range calls {
		if code := status.Code(call()); code != codes.Unavailable {
			t.Errorf("%s with no scan store = %v, want Unavailable", name, code)
		}
	}
}

// Every RPC of the three services, taken from the generated service
// descriptors, answers UNAVAILABLE naming the readiness entry while the
// store is absent. The forwarders are hand-written: one dropped later would
// fall through to the embedded Unimplemented answer, and an RPC added to the
// protos is not forwarded until the count here is raised.
func TestScanRecovery_EveryStandInRPCAnswersUnavailable(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	reg := &fakeRegistrar{}
	setupScanStores(f.r, reg, newFakeScanOpeners().setup(scanConnectRefused))
	ctx := kmsKeyTestCtx("op", "admin", "security:read")

	services := []struct {
		desc    grpc.ServiceDesc
		service string
		methods int
	}{
		{pb.SecurityService_ServiceDesc, securityScanService, 5},
		{pb.PentestService_ServiceDesc, pentestScanService, 11},
		{pb.ZapService_ServiceDesc, zapScanService, 8},
	}
	for _, svc := range services {
		if len(svc.desc.Streams) != 0 {
			t.Errorf("%s has %d streaming RPC(s); the stand-in forwards unary RPCs only", svc.desc.ServiceName, len(svc.desc.Streams))
		}
		if len(svc.desc.Methods) != svc.methods {
			t.Errorf("%s has %d RPCs, the stand-in forwards %d: forward the new RPC in scan_store_recovery.go and raise this count", svc.desc.ServiceName, len(svc.desc.Methods), svc.methods)
		}
		impl, ok := reg.registered(svc.desc.ServiceName)
		if !ok {
			t.Fatalf("%s was not registered", svc.desc.ServiceName)
		}
		for _, m := range svc.desc.Methods {
			_, err := m.Handler(impl, ctx, func(any) error { return nil }, nil)
			st := status.Convert(err)
			if st.Code() != codes.Unavailable {
				t.Errorf("%s/%s with no store = %v, want Unavailable", svc.desc.ServiceName, m.MethodName, err)
				continue
			}
			if !strings.Contains(st.Message(), svc.service) {
				t.Errorf("%s/%s refusal %q does not name readiness %s", svc.desc.ServiceName, m.MethodName, st.Message(), svc.service)
			}
		}
	}
}

// AC1 + AC2: with Postgres down at startup the three services are
// registered, answer UNAVAILABLE and are NOT_SERVING; once Postgres answers
// the stores install over the shared pool with no restart, readiness turns
// SERVING, the stand-ins forward to the installed servers, and each scanner
// loop starts exactly once on the daemon's serving context, not the
// helper's.
func TestScanRecovery_DegradedStartThenInstalledInProcess(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 1})
	reg := &fakeRegistrar{}
	op := newFakeScanOpeners()
	s := setupScanStores(f.r, reg, op.setup(scanConnectRefused))

	for _, svc := range []string{securityScanService, pentestScanService, zapScanService} {
		if got := f.status(t, svc); got != healthpb.HealthCheckResponse_NOT_SERVING {
			t.Fatalf("%s readiness before recovery = %v, want NOT_SERVING", svc, got)
		}
	}
	assertScanRPCsUnavailable(t, reg)
	if !f.r.pending() || !f.r.holdsRestart() {
		t.Fatalf("pending=%v holdsRestart=%v before recovery; want both true", f.r.pending(), f.r.holdsRestart())
	}

	// The daemon serves before the stores arrive: no loop starts yet.
	serving, cancelServing := context.WithCancel(context.Background())
	defer cancelServing()
	s.start(serving)
	for svc, r := range op.runners {
		if n := len(r.startContexts()); n != 0 {
			t.Fatalf("%s runner started %d time(s) before its store installed", svc, n)
		}
	}

	f.runToCompletion(t, nil)

	for _, svc := range []string{securityScanService, pentestScanService, zapScanService} {
		if got := f.status(t, svc); got != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("%s readiness after recovery = %v, want SERVING", svc, got)
		}
		pools := op.seenPools(svc)
		if len(pools) != 1 {
			t.Fatalf("%s opened %d time(s), want once", svc, len(pools))
		}
		if pools[0] != op.seenPools(securityScanService)[0] {
			t.Errorf("%s opened over a different pool than the security store; want the one shared pool", svc)
		}
	}
	if n := f.pg.dialCount(); n != 2 {
		t.Errorf("dials = %d, want 2 (one refused, one shared by the three families)", n)
	}
	if f.r.pending() {
		t.Error("a scan family is still pending after every install succeeded")
	}
	if got := s.security.current(); got != op.security {
		t.Errorf("installed security server = %p, want the opened one %p", got, op.security)
	}
	ctx := kmsKeyTestCtx("op", "admin", "security:read")
	if resp, err := reg.zap(t).GetZapConfig(ctx, &pb.GetZapConfigRequest{}); err != nil || resp.GetConfig().GetEnabled() {
		t.Errorf("GetZapConfig after install = (%v, %v), want the installed server's answer (enabled=false, no manager)", resp, err)
	}
	if _, err := reg.pentest(t).GetPentestConfig(ctx, &pb.GetPentestConfigRequest{}); err != nil {
		t.Errorf("GetPentestConfig after install = %v, want the installed server's answer", err)
	}

	for svc, r := range op.runners {
		starts := r.startContexts()
		if len(starts) != 1 {
			t.Fatalf("%s runner started %d time(s), want exactly once", svc, len(starts))
		}
		if starts[0] != serving {
			t.Errorf("%s runner started with %v, want the daemon's serving context", svc, starts[0])
		}
	}
	s.start(context.Background()) // a second serving context changes nothing
	s.stop()
	s.stop()
	for svc, r := range op.runners {
		if n := len(r.startContexts()); n != 1 {
			t.Errorf("%s runner started %d time(s) after a second start, want 1", svc, n)
		}
		if n := r.stopCount(); n != 1 {
			t.Errorf("%s runner stopped %d time(s), want exactly once", svc, n)
		}
	}
}

// Boot with Postgres up: the three install over one boot pool and register
// installed, so nothing is pending; a family whose open fails on a Postgres
// error registers pending and holds the restart, and the pool stays open for
// the others. Loops start once from the serving context either way.
func TestScanRecovery_InstalledAtBootOrPendingPerFamily(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	reg := &fakeRegistrar{}
	op := newFakeScanOpeners()
	op.fail[zapScanService] = errors.New("create table zap_scan_runs: relation is locked")
	bootPool := new(pgxpool.Pool)
	closer := &poolCloser{}
	s := setupScanStores(f.r, reg, op.setup(func() (*pgxpool.Pool, error) { return bootPool, nil }))
	s.closePool = closer.close

	if got := f.status(t, securityScanService); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("security readiness at boot = %v, want SERVING", got)
	}
	if got := f.status(t, pentestScanService); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("pentest readiness at boot = %v, want SERVING", got)
	}
	if got := f.status(t, zapScanService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("zap readiness after a failed boot open = %v, want NOT_SERVING", got)
	}
	if !f.r.pending() || !f.r.holdsRestart() {
		t.Fatalf("pending=%v holdsRestart=%v; a Postgres open error must stay pending and hold the restart", f.r.pending(), f.r.holdsRestart())
	}
	if got := op.seenPools(securityScanService); len(got) != 1 || got[0] != bootPool {
		t.Fatalf("security opened over %v, want the boot pool once", got)
	}
	if closer.count() != 0 {
		t.Fatal("boot pool closed while installed families use it")
	}

	serving := context.Background()
	s.start(serving)
	if n := len(op.runners[securityScanService].startContexts()); n != 1 {
		t.Errorf("security runner started %d time(s) at boot, want 1", n)
	}
	if n := len(op.runners[zapScanService].startContexts()); n != 0 {
		t.Errorf("zap runner started %d time(s) with no store, want 0", n)
	}

	// The ZAP family installs late over the shared pool and starts once.
	op.fail[zapScanService] = nil
	f.runToCompletion(t, nil)
	if got := f.status(t, zapScanService); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("zap readiness after the late install = %v, want SERVING", got)
	}
	if n := len(op.runners[zapScanService].startContexts()); n != 1 {
		t.Errorf("zap runner started %d time(s) after the late install, want 1", n)
	}

	s.stop()
	if closer.count() != 1 {
		t.Errorf("boot pool closed %d time(s) at stop, want 1", closer.count())
	}
}

// A scanner disabled by configuration registers no service and no readiness
// entry, and is not pending; with every scanner disabled nothing registers
// and the helper has nothing to retry.
func TestScanRecovery_DisabledScannerHasNoReadinessEntry(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	reg := &fakeRegistrar{}
	op := newFakeScanOpeners()
	c := op.setup(scanConnectRefused)
	c.DisablePentest = true
	s := setupScanStores(f.r, reg, c)

	if _, ok := reg.registered(pb.PentestService_ServiceDesc.ServiceName); ok {
		t.Fatal("PentestService registered although the pentest scanner is disabled")
	}
	if s.pentest != nil {
		t.Fatal("a disabled pentest scanner has a family")
	}
	f.readiness.mu.Lock()
	_, published := f.readiness.entries[pentestScanService]
	f.readiness.mu.Unlock()
	if published {
		t.Fatal("a disabled pentest scanner published a readiness entry")
	}
	if _, err := f.health.Check(context.Background(), &healthpb.HealthCheckRequest{Service: pentestScanService}); status.Code(err) != codes.NotFound {
		t.Fatalf("health.Check(%s) = %v, want NotFound (no entry)", pentestScanService, err)
	}
	if names := f.r.serviceNames(f.r.pendingFamilies()); names != securityScanService+", "+zapScanService {
		t.Fatalf("pending families = %q, want only the enabled ones", names)
	}
	// Nil-safe hooks for the absent family.
	s.setAuditStore(&audit.Store{})
	s.setPeerPool(nil)
	s.start(context.Background())
	s.stop()

	all := op.setup(scanConnectRefused)
	all.DisableSecurity, all.DisablePentest, all.DisableZap = true, true, true
	g := newStoreRecoveryFixture(t, &fakePostgres{})
	none := setupScanStores(g.r, &fakeRegistrar{}, all)
	if g.r.pending() {
		t.Fatal("every scanner disabled, yet a family is pending")
	}
	if none.security != nil || none.pentest != nil || none.zap != nil {
		t.Fatal("every scanner disabled, yet a family was built")
	}
	// No Postgres configured: nothing is registered either.
	noPG := op.setup(scanConnectRefused)
	noPG.PostgresDSN = ""
	h := newStoreRecoveryFixture(t, &fakePostgres{})
	hReg := &fakeRegistrar{}
	setupScanStores(h.r, hReg, noPG)
	if _, ok := hReg.registered(pb.SecurityService_ServiceDesc.ServiceName); ok || h.r.pending() {
		t.Fatal("no Postgres configured, yet a scan service registered or is pending")
	}
}

// The security scanner and the pentest manager need an Incus client; without
// one the install is a configuration refusal (#3378), checked before
// Postgres is touched: the family stays pending and NOT_SERVING but does not
// hold the self-restart, and the refusal is logged once.
func TestScanRecovery_IncusFailureIsConfigRefusal(t *testing.T) {
	noIncus := func() (*incus.Client, error) { return nil, errors.New("incus socket not found") }
	// A zero pool panics if used, so a refusal that touched Postgres first
	// fails this test loudly.
	if _, _, err := openSecurityScan(securityScanDeps{NewIncus: noIncus})(context.Background(), new(pgxpool.Pool)); !isStoreConfigRefusal(err) {
		t.Fatalf("security open without Incus = %v, want a storeConfigRefusal", err)
	}
	if _, _, err := openPentestScan(pentestScanDeps{NewIncus: noIncus})(context.Background(), new(pgxpool.Pool)); !isStoreConfigRefusal(err) {
		t.Fatalf("pentest open without Incus = %v, want a storeConfigRefusal", err)
	}

	f := newStoreRecoveryFixture(t, &fakePostgres{})
	f.clock.stopAfter = 4
	reg := &fakeRegistrar{}
	c := scanStoreSetup{
		PostgresDSN:  "postgres://unused",
		Connect:      scanConnectRefused,
		OpenSecurity: openSecurityScan(securityScanDeps{NewIncus: noIncus}),
		OpenPentest:  openPentestScan(pentestScanDeps{NewIncus: noIncus}),
		DisableZap:   true,
	}
	s := setupScanStores(f.r, reg, c)
	f.r.Run(f.ctx, nil)

	if s.security.current() != nil || s.pentest.current() != nil {
		t.Fatal("a scan family installed without an Incus client")
	}
	for _, svc := range []string{securityScanService, pentestScanService} {
		if got := f.status(t, svc); got != healthpb.HealthCheckResponse_NOT_SERVING {
			t.Errorf("%s readiness = %v, want NOT_SERVING", svc, got)
		}
	}
	if !f.r.pending() || f.r.holdsRestart() {
		t.Fatalf("refused families: pending=%v holdsRestart=%v; want pending, not holding", f.r.pending(), f.r.holdsRestart())
	}
	refusals := 0
	for _, line := range f.logs.all() {
		if strings.Contains(line, "install refused by configuration") {
			refusals++
		}
	}
	if refusals != 2 {
		t.Errorf("refusal logged %d time(s) over several retries, want once per family (2)", refusals)
	}
	ctx := kmsKeyTestCtx("op", "admin", "security:read")
	if _, err := reg.security(t).GetScanStatus(ctx, &pb.GetScanStatusRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("GetScanStatus on a refused family = %v, want Unavailable", err)
	}
	if _, err := reg.pentest(t).GetPentestConfig(ctx, &pb.GetPentestConfigRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("GetPentestConfig on a refused family = %v, want Unavailable", err)
	}
}

// The late install arms the pentest server with the audit store as boot
// does (the store set during startup, applied to the server when it exists),
// and Start's peer pool reaches a security server installed before or after
// it. The hooks run before the server is visible to RPCs.
func TestScanRecovery_LateInstallArmsPentestAuditStoreAndSecurityPeerPool(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	reg := &fakeRegistrar{}
	op := newFakeScanOpeners()
	s := setupScanStores(f.r, reg, op.setup(scanConnectRefused))

	auditStore := &audit.Store{}
	s.setAuditStore(auditStore) // NewDualServer: the audit store exists, the pentest server does not yet
	if op.pentest.auditStore != nil {
		t.Fatal("audit store applied to a pentest server that is not installed")
	}
	visibleWhenArmed := false
	s.pentest.arm(func(*PentestServer) { visibleWhenArmed = s.pentest.current() != nil })
	f.runToCompletion(t, nil)
	if op.pentest.auditStore != auditStore {
		t.Fatalf("installed pentest server audit store = %p, want the one set before the install %p", op.pentest.auditStore, auditStore)
	}
	if visibleWhenArmed {
		t.Fatal("the pentest server was visible to RPCs before its hooks ran")
	}

	peers := &PeerPool{}
	s.setPeerPool(peers) // DualServer.Start, after the install this time
	if op.security.peerPool != peers {
		t.Fatalf("installed security server peer pool = %p, want %p", op.security.peerPool, peers)
	}

	// Boot order: server installed first, audit store arrives later.
	g := newStoreRecoveryFixture(t, &fakePostgres{})
	op2 := newFakeScanOpeners()
	s2 := setupScanStores(g.r, &fakeRegistrar{}, op2.setup(func() (*pgxpool.Pool, error) { return new(pgxpool.Pool), nil }))
	s2.setAuditStore(auditStore)
	if op2.pentest.auditStore != auditStore {
		t.Fatal("audit store not applied to the pentest server installed at boot")
	}
}

// The pentest and ZAP managers read the route store through the live
// accessor (#3331): a daemon with no route family hands them a true nil,
// and with one the lister resolves to the store installed after the
// managers were built. The List delegation itself runs against Postgres
// below.
func TestScanRecovery_RouteListerFollowsLateInstalledRouteStore(t *testing.T) {
	if l := scanRouteLister(nil); l != nil {
		t.Fatalf("scanRouteLister(no route family) = %#v, want a nil interface", l)
	}
	h := newRouteHostingWithEdge(nil, &fakeRouteEdge{})
	lister := scanRouteLister(h)
	if lister == nil {
		t.Fatal("scanRouteLister(route family) = nil")
	}
	tc := pentest.NewTargetCollector(lister, nil)
	if got := tc.Collect(context.Background(), ""); len(got) != 0 {
		t.Fatalf("targets before the route store installed = %v, want none", got)
	}
	if _, err := lister.List(context.Background(), true); status.Code(err) != codes.Unavailable {
		t.Fatalf("List before the route store installed = %v, want Unavailable", err)
	}
	st := &app.RouteStore{}
	h.store().install(st)
	if got, err := h.store().current(); err != nil || got != st {
		t.Fatalf("accessor after install = (%p, %v), want the installed store %p", got, err, st)
	}
}

// Against Postgres (the store-integration lane): a route saved to a store
// that installs after the collector was built is a scan target on the next
// collect.
func TestScanRecovery_CollectorSeesRouteSavedToLateInstalledStore(t *testing.T) {
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres (the store-integration lane does)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	st, err := app.NewRouteStore(ctx, pool)
	if err != nil {
		t.Fatalf("NewRouteStore: %v", err)
	}
	domain := fmt.Sprintf("scan-%s-%d.example.test", t.Name(), os.Getpid())
	t.Cleanup(func() { _ = st.Delete(context.Background(), domain) })

	live := newLiveRouteStore()
	tc := pentest.NewTargetCollector(live, nil)
	if got := tc.Collect(ctx, ""); len(got) != 0 {
		t.Fatalf("targets before the route store installed = %v, want none", got)
	}
	if err := st.Save(ctx, &app.RouteRecord{Subdomain: "scan", FullDomain: domain, TargetIP: "10.0.0.9", TargetPort: 8080, Protocol: "http", ContainerName: "scan-test-container", Active: true}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	live.install(st)
	var seen bool
	for _, target := range tc.Collect(ctx, "scan-test-container") {
		seen = seen || target.FullDomain == domain
	}
	if !seen {
		t.Fatalf("the route saved to the late-installed store is not a scan target")
	}
}
