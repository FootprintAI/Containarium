package app

import (
	"encoding/json"
	"strings"
	"testing"
)

// #1618: syncHTTPRoutes reaps a Caddy route that no longer exists in the DB,
// but RemoveRoute only deletes the ROUTE. The TLS automation subject that
// route created stays behind forever — EnsureTLSSubjects (#1584) is add-only
// by design, so nothing on the reconcile path can ever clean it up.
//
// The orphan is not inert. Caddy keeps trying to obtain a certificate for a
// hostname that routes nowhere, and repeated failed validations accumulate
// against the ACME account — Let's Encrypt pauses accounts that rack them up.
// RemoveTLSSubject's own doc comment names exactly this cost; only the
// container-delete cascade was calling it.
//
// Observed live: one orphaned subject accounted for effectively all
// certificate-obtain errors on a production host while every other subject
// sat quiet.

// caddyConfigWithRoutesAndPolicy builds a fake Caddy config carrying both an
// http server with routes and a TLS policy, so the reap path can be driven
// end to end.
func caddyConfigWithRoutesAndPolicy(t *testing.T, hosts []string, subjects []string) map[string]interface{} {
	t.Helper()

	routes := make([]interface{}, 0, len(hosts))
	for _, h := range hosts {
		// AddRoute stores @id as the subdomain with the base domain stripped,
		// and RemoveRoute reconstructs it the same way — the fixture has to
		// match or the delete-by-id lookup misses.
		id := strings.TrimSuffix(h, ".example.com")
		r := caddyRouteJSON{
			ID:    id,
			Match: []CaddyMatchTyped{{Host: []string{h}}},
			Handle: []CaddyHandler{CaddyReverseProxyHandler{
				Handler:   "reverse_proxy",
				Upstreams: []CaddyUpstreamTyped{{Dial: "10.0.3.9:8080"}},
			}},
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal route: %v", err)
		}
		var any interface{}
		if err := json.Unmarshal(raw, &any); err != nil {
			t.Fatalf("unmarshal route: %v", err)
		}
		routes = append(routes, any)
	}

	polRaw, err := json.Marshal([]CaddyTLSAutomationPolicy{{
		Subjects: subjects,
		Issuers:  []CaddyTLSIssuer{NewACMEIssuer()},
	}})
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	var policies []interface{}
	if err := json.Unmarshal(polRaw, &policies); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	return map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					DefaultCaddyServerName: map[string]interface{}{"routes": routes},
				},
			},
			"tls": map[string]interface{}{
				"automation": map[string]interface{}{"policies": policies},
			},
		},
	}
}

func activeRoute(domain string) *RouteRecord {
	return &RouteRecord{
		FullDomain: domain,
		TargetIP:   "10.0.3.9",
		TargetPort: 8080,
		Protocol:   string(RouteProtocolHTTP),
		Active:     true,
	}
}

// THE #1618 regression: a route present in Caddy but gone from the DB is
// reaped, and its TLS subject must go with it.
func TestSyncHTTPRoutes_ReapingARouteAlsoRemovesItsTLSSubject(t *testing.T) {
	srv, fc := newRWFakeCaddy(caddyConfigWithRoutesAndPolicy(t,
		[]string{"kept.example.com", "gone.example.com"},
		[]string{"kept.example.com", "gone.example.com"},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	j := &RouteSyncJob{proxyManager: p}

	// Only "kept" remains in the DB — "gone" was deactivated or deleted.
	if err := j.syncHTTPRoutes([]*RouteRecord{activeRoute("kept.example.com")}); err != nil {
		t.Fatalf("syncHTTPRoutes: %v", err)
	}

	policies := readPolicies(t, fc)
	if hasSubject(policies, "gone.example.com") {
		t.Fatalf("reaped route's TLS subject was left behind — Caddy will retry ACME for it "+
			"forever, burning rate-limit budget with no route and no host (#1618); subjects: %v",
			subjectsOf(policies))
	}
	if !hasSubject(policies, "kept.example.com") {
		t.Fatalf("a still-active route's subject must not be removed; subjects: %v", subjectsOf(policies))
	}
}

// A wildcard subject is per-cluster (ProvisionWildcardTLS), not route-derived,
// and covers hosts beyond the one being reaped. Removing it would take TLS
// away from every sibling — strictly worse than the orphan being fixed.
func TestSyncHTTPRoutes_ReapNeverRemovesWildcardSubject(t *testing.T) {
	srv, fc := newRWFakeCaddy(caddyConfigWithRoutesAndPolicy(t,
		[]string{"*.example.com"},
		[]string{"*.example.com", "kept.example.com"},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	j := &RouteSyncJob{proxyManager: p}

	// The DB has no route named "*.example.com", so the reap path sees it as
	// removable. It must be skipped anyway.
	if err := j.syncHTTPRoutes([]*RouteRecord{activeRoute("kept.example.com")}); err != nil {
		t.Fatalf("syncHTTPRoutes: %v", err)
	}

	policies := readPolicies(t, fc)
	if !hasSubject(policies, "*.example.com") {
		t.Fatalf("wildcard subject was removed — every host it covers loses TLS; subjects: %v",
			subjectsOf(policies))
	}
}

// Steady state must stay silent: nothing to reap means no writes at all, so a
// quiet fleet doesn't churn Caddy's config every tick.
func TestSyncHTTPRoutes_NoReapMeansNoSubjectWrites(t *testing.T) {
	srv, fc := newRWFakeCaddy(caddyConfigWithRoutesAndPolicy(t,
		[]string{"kept.example.com"},
		[]string{"kept.example.com"},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	j := &RouteSyncJob{proxyManager: p}
	before := fc.puts

	if err := j.syncHTTPRoutes([]*RouteRecord{activeRoute("kept.example.com")}); err != nil {
		t.Fatalf("syncHTTPRoutes: %v", err)
	}

	if fc.puts != before {
		t.Fatalf("in-sync tick performed %d config write(s); it must be a no-op", fc.puts-before)
	}
}

// Several routes can disappear at once (a container delete, a batch cleanup).
// Every orphan must go, not just the first.
func TestSyncHTTPRoutes_ReapsAllOrphanedSubjects(t *testing.T) {
	srv, fc := newRWFakeCaddy(caddyConfigWithRoutesAndPolicy(t,
		[]string{"kept.example.com", "a.example.com", "b.example.com"},
		[]string{"kept.example.com", "a.example.com", "b.example.com"},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	j := &RouteSyncJob{proxyManager: p}

	if err := j.syncHTTPRoutes([]*RouteRecord{activeRoute("kept.example.com")}); err != nil {
		t.Fatalf("syncHTTPRoutes: %v", err)
	}

	policies := readPolicies(t, fc)
	for _, gone := range []string{"a.example.com", "b.example.com"} {
		if hasSubject(policies, gone) {
			t.Errorf("orphaned subject %q survived the reap; subjects: %v", gone, subjectsOf(policies))
		}
	}
	if !hasSubject(policies, "kept.example.com") {
		t.Error("active route's subject was removed")
	}
}
