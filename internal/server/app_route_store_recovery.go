//go:build !containarium_client

package server

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/app"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The app-hosting store and the route store as late-install families
// (#3331, on the #3326 helper; decision Q12 on #3335). Both used to install
// only when Postgres answered at boot and stayed off until a restart.
//
//   - App hosting: the AppService is registered through a stand-in whose
//     RPCs answer UNAVAILABLE until the store installs, at boot or late;
//     install builds the manager and the real AppServer over the store.
//   - Routes: the proxy managers come from configuration, so they exist
//     from the start. The store installs over the shared pool, the Caddy
//     set-up boot would have run (server config, PROXY protocol, client-IP
//     trust, wildcard TLS, the L4 manager) runs once when it does, the sync
//     job is created once, and it starts when it has both the store and
//     the daemon's serving context, in whichever order they arrive; stop
//     is the daemon's shutdown, not the helper's context. While the store
//     is absent every route RPC answers UNAVAILABLE and nothing is applied
//     in Caddy (Q13): the direct-to-Caddy fallback stays only for a daemon
//     with no route persistence configured at all.
//
// Every consumer that captured the store by value reads it through
// liveRouteStore: the network server, the container server's route
// cleanup, the cloud actuator and the wake proxy. The pentest and ZAP
// managers still take the store installed at boot; #3332 re-points them.
// Traffic persistence stays boot-only (#3401).

const (
	// appHostingStoreService is the family's grpc.health.v1 readiness entry.
	appHostingStoreService = "containarium.app_hosting"
	appHostingStoreDisplay = "app-hosting store"
	// routeStoreService, the route family's readiness entry, is declared in
	// live_route_store.go with the refusal that names it.
	routeStoreDisplay = "route store and Caddy route sync"

	defaultRouteSyncInterval = 5 * time.Second
)

// errAppHostingNotInstalled is every AppService answer until the store
// installs.
var errAppHostingNotInstalled = status.Error(codes.Unavailable,
	"app hosting store is not available yet (Postgres unavailable at startup); it installs in-process once Postgres answers — readiness "+appHostingStoreService)

// appHostingService is the AppService registration, made before the store
// exists. Each call goes to the AppServer swapped in by install, or answers
// UNAVAILABLE while there is none.
type appHostingService struct {
	pb.UnimplementedAppServiceServer
	live *storeSlot[*AppServer]
}

func newAppHostingService() *appHostingService {
	return &appHostingService{live: newStoreSlot[*AppServer](nil)}
}

func (s *appHostingService) install(srv *AppServer) { s.live.Store(srv) }

func (s *appHostingService) current() (*AppServer, error) {
	if srv := s.live.Load(); srv != nil {
		return srv, nil
	}
	return nil, errAppHostingNotInstalled
}

func (s *appHostingService) DeployApp(ctx context.Context, req *pb.DeployAppRequest) (*pb.DeployAppResponse, error) {
	srv, err := s.current()
	if err != nil {
		return nil, err
	}
	return srv.DeployApp(ctx, req)
}

func (s *appHostingService) ListApps(ctx context.Context, req *pb.ListAppsRequest) (*pb.ListAppsResponse, error) {
	srv, err := s.current()
	if err != nil {
		return nil, err
	}
	return srv.ListApps(ctx, req)
}

func (s *appHostingService) GetApp(ctx context.Context, req *pb.GetAppRequest) (*pb.GetAppResponse, error) {
	srv, err := s.current()
	if err != nil {
		return nil, err
	}
	return srv.GetApp(ctx, req)
}

func (s *appHostingService) StopApp(ctx context.Context, req *pb.StopAppRequest) (*pb.StopAppResponse, error) {
	srv, err := s.current()
	if err != nil {
		return nil, err
	}
	return srv.StopApp(ctx, req)
}

func (s *appHostingService) StartApp(ctx context.Context, req *pb.StartAppRequest) (*pb.StartAppResponse, error) {
	srv, err := s.current()
	if err != nil {
		return nil, err
	}
	return srv.StartApp(ctx, req)
}

func (s *appHostingService) RestartApp(ctx context.Context, req *pb.RestartAppRequest) (*pb.RestartAppResponse, error) {
	srv, err := s.current()
	if err != nil {
		return nil, err
	}
	return srv.RestartApp(ctx, req)
}

func (s *appHostingService) DeleteApp(ctx context.Context, req *pb.DeleteAppRequest) (*pb.DeleteAppResponse, error) {
	srv, err := s.current()
	if err != nil {
		return nil, err
	}
	return srv.DeleteApp(ctx, req)
}

func (s *appHostingService) GetAppLogs(req *pb.GetAppLogsRequest, stream pb.AppService_GetAppLogsServer) error {
	srv, err := s.current()
	if err != nil {
		return err
	}
	return srv.GetAppLogs(req, stream)
}

// liveAppLister is the network server's view of the app store: the
// installed store on every call, UNAVAILABLE while there is none.
type liveAppLister struct {
	slot *storeSlot[*app.Store]
}

var _ appLister = (*liveAppLister)(nil)

// List implements appLister.
func (l *liveAppLister) List(ctx context.Context, username string, stateFilter pb.AppState) ([]*pb.App, error) {
	st := l.slot.Load()
	if st == nil {
		return nil, errAppHostingNotInstalled
	}
	return st.List(ctx, username, stateFilter)
}

// appHosting is the app-hosting family: the AppService stand-in, the store
// slot the network server reads, and how to build the real server over an
// installed store.
type appHosting struct {
	service   *appHostingService
	slot      *storeSlot[*app.Store]
	newServer func(*app.Store) *AppServer
}

func newAppHosting(newServer func(*app.Store) *AppServer) *appHosting {
	return &appHosting{
		service:   newAppHostingService(),
		slot:      newStoreSlot[*app.Store](nil),
		newServer: newServer,
	}
}

// install swaps st into the store slot and the real AppServer into the
// service. The store goes in first: by the time a call reaches the server,
// the lister sees the same store.
func (a *appHosting) install(st *app.Store) {
	a.slot.Store(st)
	a.service.install(a.newServer(st))
}

// current returns the installed store, or nil.
func (a *appHosting) current() *app.Store { return a.slot.Load() }

// lister is the network server's live view.
func (a *appHosting) lister() *liveAppLister { return &liveAppLister{slot: a.slot} }

// family is the helper registration: open the store over the shared pool
// and install it. On error nothing is swapped in.
func (a *appHosting) family(open func(context.Context, *pgxpool.Pool) (*app.Store, error)) storeFamily {
	return storeFamily{
		Service: appHostingStoreService,
		Display: appHostingStoreDisplay,
		Install: func(ctx context.Context, pool *pgxpool.Pool) error {
			st, err := open(ctx, pool)
			if err != nil {
				return err
			}
			a.install(st)
			return nil
		},
	}
}

// liveRouteStore, the accessor the route family installs into, is in
// live_route_store.go (no build tag: the network server reads it in the
// client build too).

// routeSyncJob is the part of *app.RouteSyncJob the route family drives.
type routeSyncJob interface {
	Start(ctx context.Context)
	Stop()
	SetWakeTracker(app.WakeTracker)
}

var _ routeSyncJob = (*app.RouteSyncJob)(nil)

// routeEdge is the Caddy side of the route family: the one-time set-up, the
// sync job over an installed store, and the management routes. The real one
// is caddyRouteEdge; tests substitute a fake.
type routeEdge interface {
	setUp()
	newSyncJob(*app.RouteStore) routeSyncJob
	ensureManagementRoutes(ctx context.Context, st *app.RouteStore)
}

// routeHostingConfig is what the route family needs from the daemon config.
type routeHostingConfig struct {
	CaddyAdminURL        string
	BaseDomain           string
	ProxyProtocol        bool
	ProxyProtocolTrusted []string
	ClientIPHeaders      []string
	TrustedProxyCIDRs    []string
	SyncInterval         time.Duration
	HostIP               string
	HTTPPort             int
	// ManagementDomains are the apexes the management UI route is ensured
	// for (managementRouteDomains); none when HostIP is unset.
	ManagementDomains []string
}

// routeHostingConfigFrom reads the route family's configuration. caddyAdminURL
// is passed separately because core services may have set it up at boot.
func routeHostingConfigFrom(cfg *DualServerConfig, caddyAdminURL string) routeHostingConfig {
	interval := cfg.RouteSyncInterval
	if interval == 0 {
		interval = defaultRouteSyncInterval
	}
	return routeHostingConfig{
		CaddyAdminURL:        caddyAdminURL,
		BaseDomain:           cfg.BaseDomain,
		ProxyProtocol:        cfg.ProxyProtocol,
		ProxyProtocolTrusted: cfg.ProxyProtocolTrusted,
		ClientIPHeaders:      cfg.ClientIPHeaders,
		TrustedProxyCIDRs:    cfg.TrustedProxyCIDRs,
		SyncInterval:         interval,
		HostIP:               cfg.HostIP,
		HTTPPort:             cfg.HTTPPort,
		ManagementDomains:    managementRouteDomains(cfg),
	}
}

// caddyRouteEdge is the real routeEdge over the proxy managers.
type caddyRouteEdge struct {
	cfg   routeHostingConfig
	proxy *app.ProxyManager
	l4    *app.L4ProxyManager
	logf  func(format string, args ...any)
}

// setUp is the Caddy set-up boot ran once the route store existed: server
// config, PROXY protocol, client-IP trust, the wildcard certificate, and
// PROXY protocol on the L4 manager. Every step is best-effort and logged.
func (e *caddyRouteEdge) setUp() {
	if err := e.proxy.EnsureServerConfig(); err != nil {
		e.logf("Warning: Failed to ensure Caddy server config: %v", err)
	}
	if e.cfg.ProxyProtocol {
		if err := e.proxy.EnableProxyProtocol(e.cfg.ProxyProtocolTrusted); err != nil {
			e.logf("Warning: Failed to enable PROXY protocol on Caddy: %v", err)
		} else {
			e.logf("Caddy listener_wrappers: PROXY v2 enabled, trusted=%v", e.cfg.ProxyProtocolTrusted)
		}
		if err := e.l4.EnableL4ProxyProtocol(e.cfg.ProxyProtocolTrusted); err != nil {
			e.logf("Warning: Failed to enable PROXY protocol on caddy-l4: %v", err)
		}
	}
	if len(e.cfg.ClientIPHeaders) > 0 || len(e.cfg.TrustedProxyCIDRs) > 0 {
		if err := e.proxy.ConfigureClientIP(e.cfg.ClientIPHeaders, e.cfg.TrustedProxyCIDRs); err != nil {
			e.logf("Warning: Failed to configure client-IP trust on Caddy: %v", err)
		} else {
			e.logf("Caddy client-IP trust: headers=%v extra_trusted=%v", e.cfg.ClientIPHeaders, e.cfg.TrustedProxyCIDRs)
		}
	}
	// With DNS-01 configured, one `*.<base-domain>` wildcard covers every
	// subdomain from one issuance (#389). Best-effort; per-route
	// ProvisionTLS still covers individual hostnames if this is skipped.
	if e.proxy.HasDNSChallenge() {
		if err := e.proxy.ProvisionWildcardTLS(); err != nil {
			e.logf("Warning: failed to provision wildcard TLS (*.%s): %v", e.cfg.BaseDomain, err)
		} else {
			e.logf("Caddy TLS: provisioned wildcard *.%s via DNS-01", e.cfg.BaseDomain)
		}
	}
}

// newSyncJob builds the PostgreSQL -> Caddy sync job over st. L4 is
// activated lazily by the job when passthrough routes exist.
func (e *caddyRouteEdge) newSyncJob(st *app.RouteStore) routeSyncJob {
	j := app.NewRouteSyncJob(st, e.proxy, e.cfg.SyncInterval)
	j.SetL4ProxyManager(e.l4)
	e.logf("Route persistence enabled with %v sync interval", e.cfg.SyncInterval)
	return j
}

// ensureManagementRoutes persists a management route per served base
// domain (#213); the sync job pushes each to Caddy. Nothing without a host
// IP.
func (e *caddyRouteEdge) ensureManagementRoutes(ctx context.Context, st *app.RouteStore) {
	if e.cfg.HostIP == "" {
		return
	}
	for _, domain := range e.cfg.ManagementDomains {
		mgmtRoute := &app.RouteRecord{
			Subdomain:   domain,
			FullDomain:  domain,
			TargetIP:    e.cfg.HostIP,
			TargetPort:  e.cfg.HTTPPort,
			Protocol:    "http",
			Description: "Containarium management UI",
			Active:      true,
			CreatedBy:   string(app.RouteCreatorSystem),
		}
		if err := st.Save(ctx, mgmtRoute); err != nil {
			e.logf("Warning: Failed to ensure management route for %s: %v", domain, err)
		} else {
			e.logf("Management route ensured: %s -> %s:%d", domain, e.cfg.HostIP, e.cfg.HTTPPort)
		}
	}
}

// routeHosting is the route family: the proxy manager (from configuration,
// so present from the start), the live store its consumers read, and the
// sync job, created once at install and served once it also has the
// daemon's serving context.
type routeHosting struct {
	proxy *app.ProxyManager
	edge  routeEdge
	live  *liveRouteStore
	logf  func(format string, args ...any)

	setUpOnce sync.Once

	mu          sync.Mutex
	job         routeSyncJob // created by the first successful install
	wakeTracker app.WakeTracker
	serving     context.Context // from start
	started     bool
	stopped     bool
}

// newRouteHosting builds the family over cfg: the proxy managers and the
// Caddy edge, no Postgres.
func newRouteHosting(cfg routeHostingConfig) *routeHosting {
	proxy := byocIngressFromEnv(wafIngressFromEnv(app.NewProxyManager(cfg.CaddyAdminURL, cfg.BaseDomain).WithDNSChallenge(app.DNSChallengeFromEnv())))
	edge := &caddyRouteEdge{cfg: cfg, proxy: proxy, l4: app.NewL4ProxyManager(cfg.CaddyAdminURL), logf: log.Printf}
	return newRouteHostingWithEdge(proxy, edge)
}

// newRouteHostingWithEdge is newRouteHosting with the edge injected.
func newRouteHostingWithEdge(proxy *app.ProxyManager, edge routeEdge) *routeHosting {
	return &routeHosting{proxy: proxy, edge: edge, live: newLiveRouteStore(), logf: log.Printf}
}

// store is the live accessor every consumer reads.
func (h *routeHosting) store() *liveRouteStore { return h.live }

// lister is store as the cloud actuator's routeLister; a true nil interface
// on a daemon with no route family, so its nil check keeps working.
func (h *routeHosting) lister() routeLister {
	if h == nil {
		return nil
	}
	return h.live
}

// installedStore is the store installed so far, or nil. For consumers not
// yet on the accessor (#3332).
func (h *routeHosting) installedStore() *app.RouteStore {
	if h == nil {
		return nil
	}
	st, _ := h.live.current()
	return st
}

// proxyManager is the Caddy proxy manager, present from construction.
func (h *routeHosting) proxyManager() *app.ProxyManager { return h.proxy }

// family is the helper registration: open the store over the shared pool
// and install it.
func (h *routeHosting) family(open func(context.Context, *pgxpool.Pool) (*app.RouteStore, error)) storeFamily {
	return storeFamily{
		Service: routeStoreService,
		Display: routeStoreDisplay,
		Install: func(ctx context.Context, pool *pgxpool.Pool) error {
			return h.install(ctx, pool, open)
		},
	}
}

// install opens the store, runs the Caddy set-up once, swaps the store in,
// creates the sync job once and serves if the serving context is already
// here. On an open error nothing changes.
func (h *routeHosting) install(ctx context.Context, pool *pgxpool.Pool, open func(context.Context, *pgxpool.Pool) (*app.RouteStore, error)) error {
	st, err := open(ctx, pool)
	if err != nil {
		return err
	}
	h.setUpOnce.Do(h.edge.setUp)
	h.live.install(st)
	h.mu.Lock()
	if h.job == nil {
		h.job = h.edge.newSyncJob(st)
		if h.wakeTracker != nil {
			h.job.SetWakeTracker(h.wakeTracker)
		}
	}
	h.mu.Unlock()
	h.maybeServe()
	return nil
}

// registerAtBoot installs the family now, over pool when the app store
// already opened one, else over a pool from connect, and registers it
// installed; on any failure it registers the family pending, so the helper
// installs it in-process once Postgres answers.
func (h *routeHosting) registerAtBoot(r *storeRecovery, pool *pgxpool.Pool, connect func() (*pgxpool.Pool, error), open func(context.Context, *pgxpool.Pool) (*app.RouteStore, error)) {
	fam := h.family(open)
	own := false
	if pool == nil {
		p, err := connect()
		if err != nil {
			h.logf("Warning: Failed to connect to PostgreSQL for route store: %v. Route RPCs answer UNAVAILABLE until it installs in-process; readiness %s is NOT_SERVING", err, routeStoreService)
			r.Register(fam)
			return
		}
		pool, own = p, true
	}
	if err := fam.Install(context.Background(), pool); err != nil {
		h.logf("Warning: Failed to create route store: %v. Route RPCs answer UNAVAILABLE until it installs in-process; readiness %s is NOT_SERVING", err, routeStoreService)
		if own {
			pool.Close()
		}
		r.Register(fam)
		return
	}
	r.RegisterInstalled(fam)
}

// setWakeTracker wires the wake-state tracker into the sync job, now or when
// the job is created.
func (h *routeHosting) setWakeTracker(t app.WakeTracker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.wakeTracker = t
	if h.job != nil {
		h.job.SetWakeTracker(t)
	}
}

// start hands over the daemon's serving context (DualServer.Start); the
// first one wins. A nil *routeHosting is a daemon with no route family.
func (h *routeHosting) start(ctx context.Context) {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.serving == nil {
		h.serving = ctx
	}
	h.mu.Unlock()
	h.maybeServe()
}

// maybeServe runs once both the store (so the job) and the serving context
// are in: ensure the management routes, then start the sync job, which
// pushes them to Caddy on its first pass.
func (h *routeHosting) maybeServe() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.started || h.stopped || h.job == nil || h.serving == nil {
		return
	}
	h.started = true
	st, err := h.live.current()
	if err == nil {
		h.edge.ensureManagementRoutes(h.serving, st)
	}
	h.job.Start(h.serving)
	h.logf("Route sync job started")
}

// stop stops the sync job at daemon shutdown; a job not started yet, or no
// family at all, is a no-op. Nothing starts after it.
func (h *routeHosting) stop() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.stopped = true
	var job routeSyncJob
	if h.started {
		job = h.job
	}
	h.mu.Unlock()
	if job != nil {
		job.Stop()
	}
}
