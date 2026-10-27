//go:build !containarium_client

package server

import (
	"context"
	"log"
	"sort"

	"github.com/footprintai/containarium/internal/app"
)

// A tunnel-joined (BYOC) backend can end up holding a base domain it does
// not own — a stored daemon_config value outlives the flag that set it —
// and serving it breaks the whole host: an apex route and certificate order
// for a name that is not served here, and TLS failures for every client
// (#2262; recovery runbook docs/BYOC-BACKEND-BRINGUP.md). On a host marked
// --byoc-backend the daemon therefore serves no base domain at all.
//
// What a BYOC backend still does with BaseDomain: name ingress routes.
// ProxyManager strips the base domain to form a route's ID, so routes the
// cloud pushed while a value was stored live under those IDs. Keeping the
// stored value for naming means existing routes are neither duplicated nor
// orphaned. The bridge-DNS wildcard is not handled here: #2263 removes it
// for every host.

// The three places that act on it: managementRouteDomains (no apex route),
// dropStaleManagementRoutes (removes the apex route saved before the host was
// marked), and the wildcard-certificate step in Start (no `*.<base-domain>`).

// managementRouteDescription marks the system route the daemon keeps for its
// own UI/API apex.
const managementRouteDescription = "Containarium management UI"

// staleManagementRoutes returns the full domains of the management apex
// routes a BYOC backend must drop: the system routes the daemon itself saved
// on an earlier start, before the host was marked. Routes pushed by the cloud
// or created by users are never included. Sorted for stable logs.
func staleManagementRoutes(routes []*app.RouteRecord) []string {
	var out []string
	for _, r := range routes {
		if r != nil && r.CreatedBy == string(app.RouteCreatorSystem) && r.Description == managementRouteDescription {
			out = append(out, r.FullDomain)
		}
	}
	sort.Strings(out)
	return out
}

// managementRouteStore is the part of *app.RouteStore dropStaleManagementRoutes needs.
type managementRouteStore interface {
	List(ctx context.Context, activeOnly bool) ([]*app.RouteRecord, error)
	Delete(ctx context.Context, fullDomain string) error
}

// dropStaleManagementRoutes deletes the management apex routes a BYOC backend
// saved before it was marked. Deleting them from the store is enough: the
// route sync removes a route missing from the store from Caddy, together
// with its TLS subject, so the certificate order stops too. Best-effort and
// logged; returns the domains it removed.
func dropStaleManagementRoutes(ctx context.Context, store managementRouteStore) []string {
	routes, err := store.List(ctx, false)
	if err != nil {
		log.Printf("Warning: BYOC backend: cannot list routes to drop the management apex: %v", err)
		return nil
	}
	var removed []string
	for _, domain := range staleManagementRoutes(routes) {
		if err := store.Delete(ctx, domain); err != nil {
			log.Printf("Warning: BYOC backend: failed to drop management route %s: %v", domain, err)
			continue
		}
		log.Printf("BYOC backend: dropped management route %s (this host serves no base domain, #2262)", domain)
		removed = append(removed, domain)
	}
	return removed
}
