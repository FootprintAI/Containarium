package server

import (
	"context"
	"errors"
	"strings"

	"github.com/footprintai/containarium/internal/app"
)

// routeLookupAdapter satisfies wake.RouteLookup by querying the
// RouteStore. Defined here (rather than in package wake) so it can
// import *app.RouteStore directly — wake imports app for RouteRecord
// only, and we want to keep that one-way.
type routeLookupAdapter struct {
	store *app.RouteStore
}

// ResolveByHost strips an optional :port from the incoming Host
// header, then looks up the route by FullDomain. Returns ok=false on
// no-match (the wake proxy responds 404 in that case). Hard errors
// from the store bubble out — they indicate a Postgres issue, and
// surfacing a 502 is more useful than a silent 404.
func (a *routeLookupAdapter) ResolveByHost(ctx context.Context, host string) (*app.RouteRecord, bool, error) {
	if a == nil || a.store == nil {
		return nil, false, nil
	}
	// Strip port if present (Host header may be "example.test:8080")
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	rec, err := a.store.GetByDomain(ctx, host)
	if err != nil {
		if errors.Is(err, app.ErrRouteNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if rec == nil {
		return nil, false, nil
	}
	return rec, true, nil
}
