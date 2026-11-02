//go:build !containarium_client

package server

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/pentest"
	"github.com/footprintai/containarium/internal/security"
	zapscanner "github.com/footprintai/containarium/internal/zap"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The security, pentest and ZAP scan stores and their managers as
// late-install families (#3332, on the #3326 helper). Each used to dial its
// own pool and register its service only when Postgres answered at boot;
// after a degraded start all three stayed off until a restart.
//
// Each enabled scanner is one family with its own readiness entry. Its
// service is registered through a stand-in whose RPCs answer UNAVAILABLE
// until the real server installs, at boot (over one boot pool shared by the
// three) or late (over the helper's shared pool). A scanner disabled by
// configuration, or a daemon with no Postgres, registers nothing and is not
// pending. The security scanner and the pentest manager need an Incus
// client: failing to get one is a configuration refusal (storeConfigRefusal,
// #3378), checked before Postgres is touched, so it does not hold the
// self-restart. The pentest and ZAP managers read the route store through
// the live accessor from #3331, so a route store that installs after them
// reaches them. Each scanner loop starts exactly once, when it has both its
// manager and the daemon's serving context (DualServer.Start), and stops at
// the daemon's shutdown. The hooks boot runs on a server after construction
// (the pentest server's audit store, the security server's peer pool) run
// on a late-installed server too, before it is visible to RPCs.

const (
	securityScanService = "containarium.security"
	securityScanDisplay = "security scan store and ClamAV scanner"
	pentestScanService  = "containarium.pentest"
	pentestScanDisplay  = "pentest scan store and manager"
	zapScanService      = "containarium.zap"
	zapScanDisplay      = "ZAP scan store and manager"
)

func scanNotInstalled(what, service string) error {
	return status.Error(codes.Unavailable, what+" is not available yet (Postgres unavailable at startup); it installs in-process once Postgres answers — readiness "+service)
}

var (
	errSecurityScanNotInstalled = scanNotInstalled("security scan store", securityScanService)
	errPentestScanNotInstalled  = scanNotInstalled("pentest scan store", pentestScanService)
	errZapScanNotInstalled      = scanNotInstalled("ZAP scan store", zapScanService)
)

// viaSlot forwards one RPC to the server installed in slot, or answers
// notInstalled while there is none.
func viaSlot[S any, Req any, Resp any](ctx context.Context, slot *storeSlot[*S], notInstalled error, req Req, call func(*S, context.Context, Req) (Resp, error)) (Resp, error) {
	srv := slot.Load()
	if srv == nil {
		var zero Resp
		return zero, notInstalled
	}
	return call(srv, ctx, req)
}

// securityScanRPCs is the SecurityService registration, made before the
// store exists.
type securityScanRPCs struct {
	pb.UnimplementedSecurityServiceServer
	live *storeSlot[*SecurityServer]
}

func (s *securityScanRPCs) ListClamavReports(ctx context.Context, req *pb.ListClamavReportsRequest) (*pb.ListClamavReportsResponse, error) {
	return viaSlot(ctx, s.live, errSecurityScanNotInstalled, req, (*SecurityServer).ListClamavReports)
}

func (s *securityScanRPCs) TriggerClamavScan(ctx context.Context, req *pb.TriggerClamavScanRequest) (*pb.TriggerClamavScanResponse, error) {
	return viaSlot(ctx, s.live, errSecurityScanNotInstalled, req, (*SecurityServer).TriggerClamavScan)
}

func (s *securityScanRPCs) InstallClamav(ctx context.Context, req *pb.InstallClamavRequest) (*pb.InstallClamavResponse, error) {
	return viaSlot(ctx, s.live, errSecurityScanNotInstalled, req, (*SecurityServer).InstallClamav)
}

func (s *securityScanRPCs) GetClamavSummary(ctx context.Context, req *pb.GetClamavSummaryRequest) (*pb.GetClamavSummaryResponse, error) {
	return viaSlot(ctx, s.live, errSecurityScanNotInstalled, req, (*SecurityServer).GetClamavSummary)
}

func (s *securityScanRPCs) GetScanStatus(ctx context.Context, req *pb.GetScanStatusRequest) (*pb.GetScanStatusResponse, error) {
	return viaSlot(ctx, s.live, errSecurityScanNotInstalled, req, (*SecurityServer).GetScanStatus)
}

// pentestScanRPCs is the PentestService registration, made before the store
// exists.
type pentestScanRPCs struct {
	pb.UnimplementedPentestServiceServer
	live *storeSlot[*PentestServer]
}

func (s *pentestScanRPCs) TriggerPentestScan(ctx context.Context, req *pb.TriggerPentestScanRequest) (*pb.TriggerPentestScanResponse, error) {
	return viaSlot(ctx, s.live, errPentestScanNotInstalled, req, (*PentestServer).TriggerPentestScan)
}

func (s *pentestScanRPCs) ListPentestScanRuns(ctx context.Context, req *pb.ListPentestScanRunsRequest) (*pb.ListPentestScanRunsResponse, error) {
	return viaSlot(ctx, s.live, errPentestScanNotInstalled, req, (*PentestServer).ListPentestScanRuns)
}

func (s *pentestScanRPCs) GetPentestScanRun(ctx context.Context, req *pb.GetPentestScanRunRequest) (*pb.GetPentestScanRunResponse, error) {
	return viaSlot(ctx, s.live, errPentestScanNotInstalled, req, (*PentestServer).GetPentestScanRun)
}

func (s *pentestScanRPCs) ListPentestFindings(ctx context.Context, req *pb.ListPentestFindingsRequest) (*pb.ListPentestFindingsResponse, error) {
	return viaSlot(ctx, s.live, errPentestScanNotInstalled, req, (*PentestServer).ListPentestFindings)
}

func (s *pentestScanRPCs) GetPentestFindingSummary(ctx context.Context, req *pb.GetPentestFindingSummaryRequest) (*pb.GetPentestFindingSummaryResponse, error) {
	return viaSlot(ctx, s.live, errPentestScanNotInstalled, req, (*PentestServer).GetPentestFindingSummary)
}

func (s *pentestScanRPCs) SuppressPentestFinding(ctx context.Context, req *pb.SuppressPentestFindingRequest) (*pb.SuppressPentestFindingResponse, error) {
	return viaSlot(ctx, s.live, errPentestScanNotInstalled, req, (*PentestServer).SuppressPentestFinding)
}

func (s *pentestScanRPCs) GetPentestConfig(ctx context.Context, req *pb.GetPentestConfigRequest) (*pb.GetPentestConfigResponse, error) {
	return viaSlot(ctx, s.live, errPentestScanNotInstalled, req, (*PentestServer).GetPentestConfig)
}

func (s *pentestScanRPCs) InstallPentestTool(ctx context.Context, req *pb.InstallPentestToolRequest) (*pb.InstallPentestToolResponse, error) {
	return viaSlot(ctx, s.live, errPentestScanNotInstalled, req, (*PentestServer).InstallPentestTool)
}

func (s *pentestScanRPCs) RemediatePentestFinding(ctx context.Context, req *pb.RemediatePentestFindingRequest) (*pb.RemediatePentestFindingResponse, error) {
	return viaSlot(ctx, s.live, errPentestScanNotInstalled, req, (*PentestServer).RemediatePentestFinding)
}

func (s *pentestScanRPCs) SetPentestScanOptIn(ctx context.Context, req *pb.SetPentestScanOptInRequest) (*pb.SetPentestScanOptInResponse, error) {
	return viaSlot(ctx, s.live, errPentestScanNotInstalled, req, (*PentestServer).SetPentestScanOptIn)
}

func (s *pentestScanRPCs) ListPentestScanOptIns(ctx context.Context, req *pb.ListPentestScanOptInsRequest) (*pb.ListPentestScanOptInsResponse, error) {
	return viaSlot(ctx, s.live, errPentestScanNotInstalled, req, (*PentestServer).ListPentestScanOptIns)
}

// zapScanRPCs is the ZapService registration, made before the store exists.
type zapScanRPCs struct {
	pb.UnimplementedZapServiceServer
	live *storeSlot[*ZapServer]
}

func (s *zapScanRPCs) TriggerZapScan(ctx context.Context, req *pb.TriggerZapScanRequest) (*pb.TriggerZapScanResponse, error) {
	return viaSlot(ctx, s.live, errZapScanNotInstalled, req, (*ZapServer).TriggerZapScan)
}

func (s *zapScanRPCs) ListZapScanRuns(ctx context.Context, req *pb.ListZapScanRunsRequest) (*pb.ListZapScanRunsResponse, error) {
	return viaSlot(ctx, s.live, errZapScanNotInstalled, req, (*ZapServer).ListZapScanRuns)
}

func (s *zapScanRPCs) ListZapAlerts(ctx context.Context, req *pb.ListZapAlertsRequest) (*pb.ListZapAlertsResponse, error) {
	return viaSlot(ctx, s.live, errZapScanNotInstalled, req, (*ZapServer).ListZapAlerts)
}

func (s *zapScanRPCs) GetZapAlertSummary(ctx context.Context, req *pb.GetZapAlertSummaryRequest) (*pb.GetZapAlertSummaryResponse, error) {
	return viaSlot(ctx, s.live, errZapScanNotInstalled, req, (*ZapServer).GetZapAlertSummary)
}

func (s *zapScanRPCs) SuppressZapAlert(ctx context.Context, req *pb.SuppressZapAlertRequest) (*pb.SuppressZapAlertResponse, error) {
	return viaSlot(ctx, s.live, errZapScanNotInstalled, req, (*ZapServer).SuppressZapAlert)
}

func (s *zapScanRPCs) GetZapConfig(ctx context.Context, req *pb.GetZapConfigRequest) (*pb.GetZapConfigResponse, error) {
	return viaSlot(ctx, s.live, errZapScanNotInstalled, req, (*ZapServer).GetZapConfig)
}

func (s *zapScanRPCs) GetZapReport(ctx context.Context, req *pb.GetZapReportRequest) (*pb.GetZapReportResponse, error) {
	return viaSlot(ctx, s.live, errZapScanNotInstalled, req, (*ZapServer).GetZapReport)
}

func (s *zapScanRPCs) InstallZap(ctx context.Context, req *pb.InstallZapRequest) (*pb.InstallZapResponse, error) {
	return viaSlot(ctx, s.live, errZapScanNotInstalled, req, (*ZapServer).InstallZap)
}

// scanRunner is a scanner loop's lifecycle: the security scanner, the pentest
// manager and the ZAP manager implement it.
type scanRunner interface {
	Start(ctx context.Context)
	Stop()
}

var (
	_ scanRunner = (*security.Scanner)(nil)
	_ scanRunner = (*pentest.Manager)(nil)
	_ scanRunner = (*zapscanner.Manager)(nil)
)

// scanOpener opens one family over a pool: its server (to replace the
// stand-in) and the loop to run. On error nothing is installed.
type scanOpener[S any] func(ctx context.Context, pool *pgxpool.Pool) (*S, scanRunner, error)

// scanFamily is one scanner family: the stand-in's slot, the loop started
// once, and the hooks boot runs on the server after construction. A nil
// *scanFamily is a disabled scanner.
type scanFamily[S any] struct {
	service, display, name string
	slot                   *storeSlot[*S]
	logf                   func(format string, args ...any)

	mu        sync.Mutex
	installed *S
	arms      []func(*S)
	runner    scanRunner
	serving   context.Context
	started   bool
	stopped   bool
}

func newScanFamily[S any](service, display, name string) *scanFamily[S] {
	return &scanFamily[S]{service: service, display: display, name: name, slot: newStoreSlot[*S](nil), logf: log.Printf}
}

// current is the installed server, or nil.
func (f *scanFamily[S]) current() *S {
	if f == nil {
		return nil
	}
	return f.slot.Load()
}

// arm registers a hook boot runs on the server after construction: now when
// one is installed, and on the install otherwise.
func (f *scanFamily[S]) arm(fn func(*S)) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.arms = append(f.arms, fn)
	if f.installed != nil {
		fn(f.installed)
	}
}

// install arms srv, publishes it to the RPCs and starts runner if the daemon
// already serves. Only the first install counts.
func (f *scanFamily[S]) install(srv *S, runner scanRunner) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.installed != nil {
		return
	}
	f.installed, f.runner = srv, runner
	for _, fn := range f.arms {
		fn(srv)
	}
	f.slot.Store(srv)
	f.maybeStartLocked()
}

// start hands over the daemon's serving context; the first one wins.
func (f *scanFamily[S]) start(ctx context.Context) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.serving == nil {
		f.serving = ctx
	}
	f.maybeStartLocked()
}

func (f *scanFamily[S]) maybeStartLocked() {
	if f.started || f.stopped || f.runner == nil || f.serving == nil {
		return
	}
	f.started = true
	f.runner.Start(f.serving)
	f.logf("%s started", f.name)
}

// stop ends a started loop and prevents a later start.
func (f *scanFamily[S]) stop() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopped {
		return
	}
	f.stopped = true
	if f.started {
		f.runner.Stop()
	}
}

// family is the helper registration over open.
func (f *scanFamily[S]) family(open scanOpener[S]) storeFamily {
	return storeFamily{
		Service: f.service,
		Display: f.display,
		Install: func(ctx context.Context, pool *pgxpool.Pool) error {
			srv, runner, err := open(ctx, pool)
			if err != nil {
				return err
			}
			f.install(srv, runner)
			return nil
		},
	}
}

// scanStoreSetup is what NewDualServer hands setupScanStores.
type scanStoreSetup struct {
	PostgresDSN string
	// Disable* mirror the daemon config's DisableSecurityScanner,
	// DisablePentestScanner and DisableZapScanner.
	DisableSecurity, DisablePentest, DisableZap bool
	// Connect opens the boot pool the three families share.
	Connect      func() (*pgxpool.Pool, error)
	OpenSecurity scanOpener[SecurityServer]
	OpenPentest  scanOpener[PentestServer]
	OpenZap      scanOpener[ZapServer]
}

// scanStores are the three scanner families; a nil family is a disabled
// scanner. A nil *scanStores is a daemon with no Postgres configured.
type scanStores struct {
	security *scanFamily[SecurityServer]
	pentest  *scanFamily[PentestServer]
	zap      *scanFamily[ZapServer]

	bootPool  *pgxpool.Pool // the pool the boot installs share; closed at stop
	closePool func(*pgxpool.Pool)
}

// setupScanStores registers each enabled scanner's service through its
// stand-in and installs it at startup over one boot pool, or registers it
// with r for a late install when the connect or the open fails.
func setupScanStores(r *storeRecovery, reg grpc.ServiceRegistrar, c scanStoreSetup) *scanStores {
	s := &scanStores{closePool: (*pgxpool.Pool).Close}
	if c.PostgresDSN == "" {
		return s
	}
	var families []storeFamily
	if !c.DisableSecurity {
		s.security = newScanFamily[SecurityServer](securityScanService, securityScanDisplay, "Security scanner")
		pb.RegisterSecurityServiceServer(reg, &securityScanRPCs{live: s.security.slot})
		families = append(families, s.security.family(c.OpenSecurity))
	}
	if !c.DisablePentest {
		s.pentest = newScanFamily[PentestServer](pentestScanService, pentestScanDisplay, "Pentest manager")
		pb.RegisterPentestServiceServer(reg, &pentestScanRPCs{live: s.pentest.slot})
		families = append(families, s.pentest.family(c.OpenPentest))
	}
	if !c.DisableZap {
		s.zap = newScanFamily[ZapServer](zapScanService, zapScanDisplay, "ZAP manager")
		pb.RegisterZapServiceServer(reg, &zapScanRPCs{live: s.zap.slot})
		families = append(families, s.zap.family(c.OpenZap))
	}
	if len(families) == 0 {
		return s
	}
	pool, err := c.Connect()
	if err != nil {
		r.logf("Warning: Failed to connect to PostgreSQL for the scan stores: %v", err)
		for _, fam := range families {
			r.logf("Warning: %s not installed: its RPCs answer UNAVAILABLE until it installs in-process; readiness %s is NOT_SERVING", fam.Display, fam.Service)
			r.Register(fam)
		}
		return s
	}
	installed := 0
	for _, fam := range families {
		if err := fam.Install(context.Background(), pool); err != nil {
			r.logf("Warning: %s not installed at startup: %v. Its RPCs answer UNAVAILABLE until it installs in-process; readiness %s is NOT_SERVING", fam.Display, err, fam.Service)
			r.Register(fam)
			continue
		}
		r.RegisterInstalled(fam)
		r.logf("%s enabled", fam.Display)
		installed++
	}
	if installed == 0 {
		s.closePool(pool)
		return s
	}
	s.bootPool = pool
	return s
}

// securityStore is the security store installed at boot, for the gateway's
// CSV export, which registers its route only at mux build time.
func (s *scanStores) securityStore() *security.Store {
	if srv := s.security.current(); srv != nil {
		return srv.store
	}
	return nil
}

// setAuditStore arms the pentest server with the audit store, as boot does
// once the store exists: now if the server is installed, at install otherwise.
func (s *scanStores) setAuditStore(st *audit.Store) {
	if s == nil || st == nil {
		return
	}
	s.pentest.arm(func(srv *PentestServer) { srv.SetAuditStore(st) })
}

// setPeerPool hands the security server the peer pool DualServer.Start
// builds, so peer containers show in summaries after a late install too.
func (s *scanStores) setPeerPool(p *PeerPool) {
	if s == nil || p == nil {
		return
	}
	s.security.arm(func(srv *SecurityServer) { srv.SetPeerPool(p) })
}

// start hands the daemon's serving context to every family; a loop starts
// once it also has its manager.
func (s *scanStores) start(ctx context.Context) {
	if s == nil {
		return
	}
	s.security.start(ctx)
	s.pentest.start(ctx)
	s.zap.start(ctx)
}

// stop stops the started loops and closes the boot pool. Nothing starts
// after it.
func (s *scanStores) stop() {
	if s == nil {
		return
	}
	s.security.stop()
	s.pentest.stop()
	s.zap.stop()
	if s.bootPool != nil {
		s.closePool(s.bootPool)
		s.bootPool = nil
	}
}

// scanRouteLister is the route store as the pentest and ZAP managers read
// it: the live accessor when the daemon has a route family, a true nil
// interface otherwise, so the managers' nil check keeps working.
func scanRouteLister(h *routeHosting) app.RouteLister {
	if h == nil {
		return nil
	}
	return h.store()
}

// securityScanDeps is what the security opener needs besides Postgres.
type securityScanDeps struct {
	NewIncus func() (*incus.Client, error)
	// ConfigureScanner wires the scan-result hook (auto-quarantine, #659)
	// before the scanner starts; nil leaves it off.
	ConfigureScanner func(*security.Scanner)
	// EnsureSecurityContainer provisions the security container in the
	// background once the service is up; nil skips it.
	EnsureSecurityContainer func(*incus.Client)
}

// openSecurityScan is the production security opener. The Incus client is
// checked first: without it no scan can run, which is a configuration
// refusal however long Postgres stays up.
func openSecurityScan(d securityScanDeps) scanOpener[SecurityServer] {
	return func(ctx context.Context, pool *pgxpool.Pool) (*SecurityServer, scanRunner, error) {
		ic, err := d.NewIncus()
		if err != nil {
			return nil, nil, &storeConfigRefusal{Err: fmt.Errorf("security scanner needs an Incus client: %w", err)}
		}
		st, err := security.NewStore(ctx, pool)
		if err != nil {
			return nil, nil, fmt.Errorf("security store: %w", err)
		}
		scanner := security.NewScanner(st, ic)
		if d.ConfigureScanner != nil {
			d.ConfigureScanner(scanner)
		}
		if d.EnsureSecurityContainer != nil {
			go d.EnsureSecurityContainer(ic)
		}
		return NewSecurityServer(st, ic, scanner), scanner, nil
	}
}

// pentestScanDeps is what the pentest opener needs besides Postgres.
type pentestScanDeps struct {
	NewIncus      func() (*incus.Client, error)
	Routes        app.RouteLister // nil without route persistence
	MeterProvider *sdkmetric.MeterProvider
}

// openPentestScan is the production pentest opener; the Incus client is
// checked first, as for security.
func openPentestScan(d pentestScanDeps) scanOpener[PentestServer] {
	return func(ctx context.Context, pool *pgxpool.Pool) (*PentestServer, scanRunner, error) {
		ic, err := d.NewIncus()
		if err != nil {
			return nil, nil, &storeConfigRefusal{Err: fmt.Errorf("pentest manager needs an Incus client: %w", err)}
		}
		st, err := pentest.NewStore(ctx, pool)
		if err != nil {
			return nil, nil, fmt.Errorf("pentest store: %w", err)
		}
		manager := pentest.NewManager(st, ic, d.Routes, d.MeterProvider, pentest.ManagerConfig{})
		return NewPentestServer(st, manager), manager, nil
	}
}

// openZapScan is the production ZAP opener; the manager takes no Incus
// client.
func openZapScan(routes app.RouteLister) scanOpener[ZapServer] {
	return func(ctx context.Context, pool *pgxpool.Pool) (*ZapServer, scanRunner, error) {
		st, err := zapscanner.NewStore(ctx, pool)
		if err != nil {
			return nil, nil, fmt.Errorf("ZAP store: %w", err)
		}
		manager := zapscanner.NewManager(st, routes, zapscanner.ManagerConfig{})
		return NewZapServer(st, manager), manager, nil
	}
}
