package app

import (
	"testing"
)

// #1584: TLS automation subjects were written exactly once, at route-add time
// (addRouteWithProtocol → ProvisionTLS). If that write didn't land — because
// ProvisionTLS failed and the error was swallowed (#1585), or because the
// route reached Caddy by some other path — nothing ever put the subject back.
//
// RouteSyncJob couldn't heal it either: syncHTTPRoutes only re-provisions when
// the domain is MISSING from Caddy, and needsUpdate compares upstream IP, port
// and protocol only. A route present in both the DB and Caddy but absent from
// the TLS policy was therefore classified "in sync" on every tick, forever —
// serving happily on :80 while :443 returned `tls: internal error` (alert 80,
// no peer certificate) with no error and no log line anywhere.
//
// EnsureTLSSubjects is the reconciliation these tests lock down: it is
// idempotent, batches its writes, and understands wildcard coverage so it
// doesn't burn ACME budget re-issuing what `*.<base-domain>` already covers.

// subjectsOf flattens every subject across every policy.
func subjectsOf(policies []CaddyTLSAutomationPolicy) []string {
	var out []string
	for _, p := range policies {
		out = append(out, p.Subjects...)
	}
	return out
}

func hasSubject(policies []CaddyTLSAutomationPolicy, want string) bool {
	for _, s := range subjectsOf(policies) {
		if s == want {
			return true
		}
	}
	return false
}

// THE #1584 regression: the route serves on :80, the subject was never
// written, and every prior tick considered that state correct.
func TestEnsureTLSSubjects_AddsSubjectMissingFromPolicy(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"other.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")

	if err := p.EnsureTLSSubjects([]string{"app.example.com"}); err != nil {
		t.Fatalf("EnsureTLSSubjects: %v", err)
	}

	policies := readPolicies(t, fc)
	if !hasSubject(policies, "app.example.com") {
		t.Fatalf("subject was not reconciled into any policy — the host would serve on :80 "+
			"and never get a certificate (#1584); subjects: %v", subjectsOf(policies))
	}
}

// Reconciliation runs on every sync tick, so a no-op must actually be a no-op.
// Rewriting the policy array each tick would churn Caddy's config and could
// restart certificate management for every subject on the host.
func TestEnsureTLSSubjects_NoWriteWhenAllSubjectsPresent(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"app.example.com", "api.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	before := fc.puts

	if err := p.EnsureTLSSubjects([]string{"app.example.com", "api.example.com"}); err != nil {
		t.Fatalf("EnsureTLSSubjects: %v", err)
	}

	if fc.puts != before {
		t.Fatalf("expected no config write when every subject is already present, got %d write(s)",
			fc.puts-before)
	}
}

// A `*.<base-domain>` wildcard already covers every direct child. Adding an
// explicit per-host subject on top would make Caddy issue a redundant
// single-host certificate, which is exactly the Let's Encrypt rate-limit
// exposure the wildcard path (#378) exists to avoid.
func TestEnsureTLSSubjects_WildcardCoversDirectChild(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"*.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	before := fc.puts

	if err := p.EnsureTLSSubjects([]string{"app.example.com"}); err != nil {
		t.Fatalf("EnsureTLSSubjects: %v", err)
	}

	if fc.puts != before {
		t.Fatalf("wildcard *.example.com already covers app.example.com; adding an explicit "+
			"subject burns ACME budget on a redundant cert (#378). Writes: %d", fc.puts-before)
	}
}

// A wildcard is exactly one label deep — `*.example.com` does NOT cover
// `a.b.example.com`. Treating it as covered would leave the deeper host with
// no certificate and no signal, reintroducing #1584 for multi-label hosts.
func TestEnsureTLSSubjects_WildcardDoesNotCoverDeeperLabel(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"*.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")

	if err := p.EnsureTLSSubjects([]string{"a.b.example.com"}); err != nil {
		t.Fatalf("EnsureTLSSubjects: %v", err)
	}

	policies := readPolicies(t, fc)
	if !hasSubject(policies, "a.b.example.com") {
		t.Fatalf("*.example.com does not cover a.b.example.com, so it must be added explicitly; "+
			"subjects: %v", subjectsOf(policies))
	}
}

// Several routes can be missing subjects at once — after a Caddy config
// rebuild, or on a host that hit #1585 repeatedly. One write, not N.
func TestEnsureTLSSubjects_BatchesMissingSubjectsIntoOneWrite(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"kept.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	before := fc.puts

	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if err := p.EnsureTLSSubjects(want); err != nil {
		t.Fatalf("EnsureTLSSubjects: %v", err)
	}

	if got := fc.puts - before; got != 1 {
		t.Errorf("want exactly 1 batched write for 3 missing subjects, got %d", got)
	}

	policies := readPolicies(t, fc)
	for _, w := range want {
		if !hasSubject(policies, w) {
			t.Errorf("subject %q missing after batch reconcile; subjects: %v", w, subjectsOf(policies))
		}
	}
	if !hasSubject(policies, "kept.example.com") {
		t.Error("reconciliation dropped a pre-existing subject — it must only add")
	}
}

// A host whose TLS app has no policies at all (fresh Caddy, or one that just
// reverted to the stub Caddyfile per #400) must still get its subjects.
func TestEnsureTLSSubjects_CreatesPolicyWhenNoneExist(t *testing.T) {
	srv, fc := newRWFakeCaddy(nil)
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")

	if err := p.EnsureTLSSubjects([]string{"app.example.com"}); err != nil {
		t.Fatalf("EnsureTLSSubjects: %v", err)
	}

	policies := readPolicies(t, fc)
	if !hasSubject(policies, "app.example.com") {
		t.Fatalf("no policy existed and none was created; subjects: %v", subjectsOf(policies))
	}
	if len(policies) == 0 || len(policies[0].Issuers) == 0 {
		t.Fatal("created policy has no issuers — Caddy would never attempt the certificate")
	}
}

// A policy that predates DNS-01 carries issuers that cannot solve a wildcard
// (#1066). Reconciliation appends to that same policy, so it must repair the
// issuers the way ProvisionTLS does — otherwise the reconciled subject sits
// there unissued, which is the very symptom #1584 is about.
func TestEnsureTLSSubjects_RepairsIssuersWhenAppending(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"other.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer(), NewZeroSSLIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com").WithDNSChallenge(testDNSChallenge())

	if err := p.EnsureTLSSubjects([]string{"app.example.com"}); err != nil {
		t.Fatalf("EnsureTLSSubjects: %v", err)
	}

	policies := readPolicies(t, fc)
	if len(policies) != 1 {
		t.Fatalf("want 1 policy, got %d", len(policies))
	}
	assertAllIssuersSolveDNS(t, policies[0])
}

// Empty input must not touch Caddy — a host with no routes yet reconciles on
// every tick too.
func TestEnsureTLSSubjects_EmptyInputIsNoOp(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"app.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")
	before := fc.puts

	if err := p.EnsureTLSSubjects(nil); err != nil {
		t.Fatalf("EnsureTLSSubjects(nil): %v", err)
	}
	if fc.puts != before {
		t.Fatalf("empty input wrote to Caddy %d time(s)", fc.puts-before)
	}
}

// The same domain appearing twice (two routes, one hostname) must not produce
// a duplicate subject entry.
func TestEnsureTLSSubjects_DeduplicatesInput(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"kept.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")

	if err := p.EnsureTLSSubjects([]string{"app.example.com", "app.example.com"}); err != nil {
		t.Fatalf("EnsureTLSSubjects: %v", err)
	}

	var count int
	for _, s := range subjectsOf(readPolicies(t, fc)) {
		if s == "app.example.com" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("want subject exactly once, got %d occurrences", count)
	}
}
