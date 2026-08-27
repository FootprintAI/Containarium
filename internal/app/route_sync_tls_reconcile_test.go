package app

import (
	"testing"
)

// #1584 at the sync-loop level. The reported host was serving its route on
// :80 with no certificate on :443, and every 5s tick left it that way:
//
//   - syncHTTPRoutes re-provisions (AddRoute → ProvisionTLS) only when the
//     domain is MISSING from Caddy. This route was present.
//   - needsUpdate, the branch taken when the route IS present, compares
//     upstream IP, upstream port and protocol. It never looked at TLS
//     automation subjects.
//
// So "route exists, subject doesn't" was indistinguishable from "in sync".
// syncTLSSubjects closes that hole.

func httpRoute(domain string) *RouteRecord {
	return &RouteRecord{
		FullDomain: domain,
		TargetIP:   "10.0.3.7",
		TargetPort: 8080,
		Protocol:   string(RouteProtocolHTTP),
		Active:     true,
	}
}

// The exact reported state: route live in Caddy and in the DB, subject absent.
// Before the fix this tick was a no-op and the host stayed certificate-less.
func TestSyncTLSSubjects_ReconcilesRoutePresentInCaddyButMissingSubject(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"unrelated.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	j := &RouteSyncJob{proxyManager: p}

	routes := []*RouteRecord{httpRoute("app.example.com")}
	if err := j.syncTLSSubjects(routes); err != nil {
		t.Fatalf("syncTLSSubjects: %v", err)
	}

	if !hasSubject(readPolicies(t, fc), "app.example.com") {
		t.Fatal("sync tick did not reconcile the missing TLS subject — the host serves on :80 " +
			"and returns `tls: internal error` on :443 indefinitely (#1584)")
	}
}

// gRPC routes reach Caddy through AddGRPCRoute, the same ProvisionTLS path,
// so they are equally exposed to #1584 and must reconcile identically.
func TestSyncTLSSubjects_CoversGRPCRoutes(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"unrelated.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	j := &RouteSyncJob{proxyManager: p}

	grpc := httpRoute("grpc.example.com")
	grpc.Protocol = string(RouteProtocolGRPC)

	if err := j.syncTLSSubjects([]*RouteRecord{grpc}); err != nil {
		t.Fatalf("syncTLSSubjects: %v", err)
	}

	if !hasSubject(readPolicies(t, fc), "grpc.example.com") {
		t.Fatal("gRPC route did not get a TLS subject reconciled (#1584)")
	}
}

// TLS-passthrough routes terminate TLS at the backend, not at Caddy, so Caddy
// must NOT try to obtain a certificate for them. Provisioning one would send
// Caddy after a cert for a hostname it never terminates.
func TestSyncTLSSubjects_SkipsTLSPassthroughRoutes(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"unrelated.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	j := &RouteSyncJob{proxyManager: p}

	pt := httpRoute("passthrough.example.com")
	pt.Protocol = string(RouteProtocolTLSPassthrough)

	if err := j.syncTLSSubjects([]*RouteRecord{pt}); err != nil {
		t.Fatalf("syncTLSSubjects: %v", err)
	}

	if hasSubject(readPolicies(t, fc), "passthrough.example.com") {
		t.Fatal("TLS-passthrough route must not get a Caddy TLS subject — Caddy does not " +
			"terminate TLS for it")
	}
}

// Inactive routes aren't served, so chasing certificates for them wastes ACME
// budget — the same reasoning RemoveTLSSubject applies on the delete cascade.
func TestSyncTLSSubjects_SkipsInactiveRoutes(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"unrelated.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	j := &RouteSyncJob{proxyManager: p}

	inactive := httpRoute("sleeping.example.com")
	inactive.Active = false

	if err := j.syncTLSSubjects([]*RouteRecord{inactive}); err != nil {
		t.Fatalf("syncTLSSubjects: %v", err)
	}

	if hasSubject(readPolicies(t, fc), "sleeping.example.com") {
		t.Fatal("inactive route should not have a TLS subject provisioned")
	}
}

// A nil proxy manager must not panic the sync loop — other tests construct
// RouteSyncJob as a bare struct literal, and the L4-only paths do too.
func TestSyncTLSSubjects_NilProxyManagerIsNoOp(t *testing.T) {
	j := &RouteSyncJob{}
	if err := j.syncTLSSubjects([]*RouteRecord{httpRoute("app.example.com")}); err != nil {
		t.Fatalf("want nil error with no proxy manager, got %v", err)
	}
}
