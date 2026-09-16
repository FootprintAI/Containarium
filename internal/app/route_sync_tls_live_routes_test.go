package app

import (
	"testing"
)

// withHTTPRoutes adds routes to the fake Caddy's http app server (the same
// path ProxyManager.ListRoutes() reads), matching the config layered under
// tlsConfigWithPolicy's "apps" map.
func withHTTPRoutes(config map[string]interface{}, domains ...string) map[string]interface{} {
	apps, _ := config["apps"].(map[string]interface{})
	if apps == nil {
		apps = map[string]interface{}{}
		config["apps"] = apps
	}
	routes := make([]interface{}, 0, len(domains))
	for _, d := range domains {
		routes = append(routes, map[string]interface{}{
			"match": []interface{}{
				map[string]interface{}{"host": []interface{}{d}},
			},
		})
	}
	apps["http"] = map[string]interface{}{
		"servers": map[string]interface{}{
			DefaultCaddyServerName: map[string]interface{}{
				"routes": routes,
			},
		},
	}
	return config
}

// TestSyncTLSSubjects_CoversHostnamesCaddyServesButDBDoesNotKnowAbout is the
// regression test for #1880: ActivateL4 moves the http app's server off :443
// to :8443, and Caddy's own automatic-HTTPS subject discovery stops covering
// hostnames the http app was already terminating TLS for. syncTLSSubjects
// sourced its domain list ONLY from dbRoutes — but a hostname reaching Caddy
// via a route that predates/lives outside Containarium's own route
// management (e.g. a tunnel-declared --public-aliases hostname, see #1872)
// has no row in dbRoutes at all, so it never got an explicit automation
// policy and its renewal silently broke the moment Caddy's own discovery
// stopped covering it.
//
// The fix: union dbRoutes' domains with whatever Caddy's http app is
// CURRENTLY, actually serving (ListRoutes()) — the live source of truth for
// "what needs a certificate," independent of whether Containarium's DB has
// a row for it.
func TestSyncTLSSubjects_CoversHostnamesCaddyServesButDBDoesNotKnowAbout(t *testing.T) {
	config := tlsConfigWithPolicy(
		[]string{"unrelated.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	)
	withHTTPRoutes(config, "api.kafeido.app")

	srv, fc := newRWFakeCaddy(config)
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	j := &RouteSyncJob{proxyManager: p}

	// No dbRoutes at all — api.kafeido.app is a tunnel-declared alias, never
	// added via AddRoute, so the DB has no row for it whatsoever.
	if err := j.syncTLSSubjects(nil); err != nil {
		t.Fatalf("syncTLSSubjects: %v", err)
	}

	if !hasSubject(readPolicies(t, fc), "api.kafeido.app") {
		t.Fatal("a hostname Caddy's http app already serves must get an explicit TLS " +
			"automation policy even when Containarium's route DB has no row for it (#1880)")
	}
}

// TestSyncTLSSubjects_DedupesDomainKnownToBothDBAndLiveCaddy proves a
// hostname present in both sources doesn't produce a duplicate subject or
// an error.
func TestSyncTLSSubjects_DedupesDomainKnownToBothDBAndLiveCaddy(t *testing.T) {
	config := tlsConfigWithPolicy(nil, []CaddyTLSIssuer{NewACMEIssuer()})
	withHTTPRoutes(config, "app.example.com")

	srv, fc := newRWFakeCaddy(config)
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	j := &RouteSyncJob{proxyManager: p}

	if err := j.syncTLSSubjects([]*RouteRecord{httpRoute("app.example.com")}); err != nil {
		t.Fatalf("syncTLSSubjects: %v", err)
	}

	policies := readPolicies(t, fc)
	count := 0
	for _, s := range subjectsOf(policies) {
		if s == "app.example.com" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("app.example.com appears %d times across policies, want exactly 1 (no duplicate from being known to both sources)", count)
	}
}

// TestSyncTLSSubjects_LiveCaddyLookupFailureStillReconcilesDBRoutes proves a
// failure fetching Caddy's live http routes (e.g. the http app doesn't exist
// yet) doesn't block reconciling the domains syncTLSSubjects already knew
// about from dbRoutes — the live-Caddy union is additive, not a new failure
// mode for the existing behavior.
func TestSyncTLSSubjects_LiveCaddyLookupFailureStillReconcilesDBRoutes(t *testing.T) {
	// No "apps.http" at all: ListRoutes() hits Caddy's "invalid traversal
	// path" 400 for a missing app and returns an empty slice, nil error —
	// but exercising this with no http app at all pins that a genuinely
	// empty/missing live-route set is harmless too.
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"unrelated.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	j := &RouteSyncJob{proxyManager: p}

	if err := j.syncTLSSubjects([]*RouteRecord{httpRoute("app.example.com")}); err != nil {
		t.Fatalf("syncTLSSubjects: %v", err)
	}

	if !hasSubject(readPolicies(t, fc), "app.example.com") {
		t.Fatal("dbRoutes-known domain must still be reconciled even with no live http routes present")
	}
}
