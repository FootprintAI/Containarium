package server

import (
	"context"
	"sync/atomic"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/wake"
)

// routeStoreService is the route family's grpc.health.v1 readiness entry
// (#3331). Declared here, outside the daemon-only build, because the
// network server names it in its refusal.
const routeStoreService = "containarium.routes"

// errRouteStoreNotInstalled is every route RPC answer, and every consumer
// read or write, until the route store installs. No route is applied in
// Caddy meanwhile (decision Q13 on #3335).
var errRouteStoreNotInstalled = status.Error(codes.Unavailable,
	"route store is not available yet (Postgres unavailable at startup); route writes are refused and nothing is applied in Caddy until it installs in-process — readiness "+routeStoreService)

// liveRouteStore is the route store as its consumers read it: the installed
// store on every call, UNAVAILABLE while there is none. It is the container
// server's routeLister, the wake proxy's RouteStore and lookup, the cloud
// actuator's store, and what the network server reads through
// routeStoreNow. The route family (app_route_store_recovery.go) installs
// into it; this file has no build tag because the network server is also
// compiled into the client binary.
type liveRouteStore struct {
	cur atomic.Pointer[app.RouteStore]
}

var (
	_ routeLister       = (*liveRouteStore)(nil)
	_ wake.RouteStore   = (*liveRouteStore)(nil)
	_ routeDomainLookup = (*liveRouteStore)(nil)
)

func newLiveRouteStore() *liveRouteStore { return &liveRouteStore{} }

// install swaps st in. Safe while serving.
func (l *liveRouteStore) install(st *app.RouteStore) { l.cur.Store(st) }

// current returns the installed store, or errRouteStoreNotInstalled.
func (l *liveRouteStore) current() (*app.RouteStore, error) {
	if st := l.cur.Load(); st != nil {
		return st, nil
	}
	return nil, errRouteStoreNotInstalled
}

func (l *liveRouteStore) ListByContainer(ctx context.Context, containerName string) ([]*app.RouteRecord, error) {
	st, err := l.current()
	if err != nil {
		return nil, err
	}
	return st.ListByContainer(ctx, containerName)
}

func (l *liveRouteStore) Save(ctx context.Context, route *app.RouteRecord) error {
	st, err := l.current()
	if err != nil {
		return err
	}
	return st.Save(ctx, route)
}

func (l *liveRouteStore) Delete(ctx context.Context, fullDomain string) error {
	st, err := l.current()
	if err != nil {
		return err
	}
	return st.Delete(ctx, fullDomain)
}

func (l *liveRouteStore) GetByDomain(ctx context.Context, fullDomain string) (*app.RouteRecord, error) {
	st, err := l.current()
	if err != nil {
		return nil, err
	}
	return st.GetByDomain(ctx, fullDomain)
}
