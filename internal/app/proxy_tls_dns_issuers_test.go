package app

import (
	"encoding/json"
	"testing"
)

// #1066: ProvisionTLS appended a subject to an existing TLS automation policy
// without touching that policy's issuers. A policy created before DNS-01 was
// configured carries HTTP-01 / TLS-ALPN-01 issuers, and those categorically
// CANNOT solve a wildcard subject — so `*.<domain>` landed in the subjects
// array and Caddy never even attempted the certificate. No error, no log line,
// no certificate: the subject just sat there indefinitely.

// dnsChallenge builds a DNS-01 challenge config for tests.
func testDNSChallenge() *CaddyACMEChallenges {
	return &CaddyACMEChallenges{
		DNS: &CaddyDNSChallenge{Provider: map[string]interface{}{"name": "cloudflare"}},
	}
}

// tlsConfigWithPolicy returns a Caddy config whose TLS app already has one
// automation policy — the common case, since any host already serving a
// hostname has one.
func tlsConfigWithPolicy(subjects []string, issuers []CaddyTLSIssuer) map[string]interface{} {
	policy := CaddyTLSAutomationPolicy{Subjects: subjects, Issuers: issuers}
	raw, _ := json.Marshal([]CaddyTLSAutomationPolicy{policy})
	var policiesAny []interface{}
	_ = json.Unmarshal(raw, &policiesAny)

	return map[string]interface{}{
		"apps": map[string]interface{}{
			"tls": map[string]interface{}{
				"automation": map[string]interface{}{"policies": policiesAny},
			},
		},
	}
}

// readPolicies pulls the policy array back out of the fake.
func readPolicies(t *testing.T, fc *rwFakeCaddy) []CaddyTLSAutomationPolicy {
	t.Helper()
	apps, _ := fc.config["apps"].(map[string]interface{})
	tls, _ := apps["tls"].(map[string]interface{})
	automation, _ := tls["automation"].(map[string]interface{})
	raw, err := json.Marshal(automation["policies"])
	if err != nil {
		t.Fatalf("marshal policies: %v", err)
	}
	var policies []CaddyTLSAutomationPolicy
	if err := json.Unmarshal(raw, &policies); err != nil {
		t.Fatalf("unmarshal policies: %v", err)
	}
	return policies
}

func assertAllIssuersSolveDNS(t *testing.T, policy CaddyTLSAutomationPolicy) {
	t.Helper()
	if len(policy.Issuers) == 0 {
		t.Fatal("policy has no issuers at all")
	}
	for i, issuer := range policy.Issuers {
		if issuer.Challenges == nil || issuer.Challenges.DNS == nil {
			t.Errorf("issuer %d (%s) cannot solve DNS-01, so a wildcard subject in this policy "+
				"will never be issued — no cert, no error (#1066)", i, issuer.Module)
		}
	}
}

// Appending a wildcard to a policy whose issuers predate DNS-01 must also fix
// the issuers.
func TestProvisionTLS_AddsDNSIssuersWhenAppendingToExistingPolicy(t *testing.T) {
	// A policy as it exists on a host that was already serving a hostname:
	// default issuers, no challenges config.
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"app.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer(), NewZeroSSLIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com").WithDNSChallenge(testDNSChallenge())

	if err := p.ProvisionTLS("*.example.com"); err != nil {
		t.Fatalf("ProvisionTLS: %v", err)
	}

	policies := readPolicies(t, fc)
	if len(policies) != 1 {
		t.Fatalf("want 1 policy, got %d", len(policies))
	}

	var sawWildcard bool
	for _, s := range policies[0].Subjects {
		if s == "*.example.com" {
			sawWildcard = true
		}
	}
	if !sawWildcard {
		t.Fatalf("wildcard subject was not added: %v", policies[0].Subjects)
	}
	assertAllIssuersSolveDNS(t, policies[0])
}

// THE case an append-only fix misses, and the state the reported host is
// already in: the wildcard subject is ALREADY in the policy from a previous
// run, so ProvisionTLS returns early. If the repair only happened on append,
// that host would stay broken forever — the fix would help only hosts that
// had not yet hit the bug.
func TestProvisionTLS_RepairsIssuersWhenSubjectAlreadyPresent(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"app.example.com", "*.example.com"},          // wildcard already there
		[]CaddyTLSIssuer{NewACMEIssuer(), NewZeroSSLIssuer()}, // but no DNS-01
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com").WithDNSChallenge(testDNSChallenge())

	if err := p.ProvisionTLS("*.example.com"); err != nil {
		t.Fatalf("ProvisionTLS: %v", err)
	}

	policies := readPolicies(t, fc)
	assertAllIssuersSolveDNS(t, policies[0])
}

// Idempotent: a policy that already solves DNS-01 must not be rewritten. A
// needless PATCH on every route sync would churn Caddy's config for nothing.
func TestProvisionTLS_NoWriteWhenIssuersAlreadySolveDNS(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"*.example.com"},
		issuersFor(testDNSChallenge()),
	))
	defer srv.Close()

	before := fc.puts
	p := NewProxyManager(srv.URL, "example.com").WithDNSChallenge(testDNSChallenge())
	if err := p.ProvisionTLS("*.example.com"); err != nil {
		t.Fatalf("ProvisionTLS: %v", err)
	}
	if fc.puts != before {
		t.Errorf("policy was rewritten though its issuers already solved DNS-01 (%d writes)", fc.puts-before)
	}
}

// Without DNS-01 configured there is nothing to add, and an existing HTTP-01
// setup must not be clobbered — the repair only ever ADDS a capability.
func TestProvisionTLS_LeavesIssuersAloneWithoutDNSChallenge(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"app.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com") // no WithDNSChallenge

	if err := p.ProvisionTLS("second.example.com"); err != nil {
		t.Fatalf("ProvisionTLS: %v", err)
	}

	policies := readPolicies(t, fc)
	for _, issuer := range policies[0].Issuers {
		if issuer.Challenges != nil {
			t.Error("DNS-01 challenges were added though none are configured — that would point " +
				"Caddy at a provider that does not exist")
		}
	}
}

// Every issuer must solve DNS-01, not merely one. Caddy tries issuers in
// order, so one that cannot solve the challenge is a failed attempt for the
// wildcard rather than a skipped one.
func TestPolicyHasDNSChallengeRequiresEveryIssuer(t *testing.T) {
	dns := testDNSChallenge()
	withDNS := NewACMEIssuer()
	withDNS.Challenges = dns

	mixed := CaddyTLSAutomationPolicy{Issuers: []CaddyTLSIssuer{withDNS, NewZeroSSLIssuer()}}
	if policyHasDNSChallenge(mixed) {
		t.Error("a policy where only SOME issuers solve DNS-01 was reported as covered")
	}

	all := CaddyTLSAutomationPolicy{Issuers: issuersFor(dns)}
	if !policyHasDNSChallenge(all) {
		t.Error("a policy where every issuer solves DNS-01 was reported as not covered")
	}
}

// #1671 — ensureDNSIssuers used to replace policy.Issuers wholesale, which
// silently discarded any field issuersFor doesn't itself reproduce:
// external_account (EAB), trusted_roots_pem_files, a non-default CA, and the
// issuer count itself. These tests exercise ensureDNSIssuers directly so the
// assertions are about specific fields, not just "the policy still works".

// newTestProxyManagerWithDNS returns a ProxyManager configured with a DNS-01
// challenge and nothing else — ensureDNSIssuers never touches the network,
// so the fake-Caddy-server machinery the rest of this file uses isn't needed.
func newTestProxyManagerWithDNS() *ProxyManager {
	return NewProxyManager("http://unused.invalid", "example.com").WithDNSChallenge(testDNSChallenge())
}

func TestEnsureDNSIssuers_PreservesExternalAccountKey(t *testing.T) {
	p := newTestProxyManagerWithDNS()
	issuer := NewACMEIssuer()
	issuer.CA = "https://acme.zerossl.com/v2/DV90"
	issuer.ExternalAccountKey = "kid:hmac-base64"
	policy := &CaddyTLSAutomationPolicy{Issuers: []CaddyTLSIssuer{issuer}}

	if !p.ensureDNSIssuers(policy) {
		t.Fatal("ensureDNSIssuers reported no change, but the issuer had no DNS-01 challenge")
	}
	if policy.Issuers[0].ExternalAccountKey != "kid:hmac-base64" {
		t.Errorf("ExternalAccountKey = %q, want it preserved — EAB ties issuance to a paid/authorised "+
			"ACME account and losing it silently breaks the next issuance against that CA",
			policy.Issuers[0].ExternalAccountKey)
	}
	if policy.Issuers[0].CA != "https://acme.zerossl.com/v2/DV90" {
		t.Errorf("CA = %q, want the hand-set CA preserved", policy.Issuers[0].CA)
	}
	assertAllIssuersSolveDNS(t, *policy)
}

func TestEnsureDNSIssuers_PreservesTrustedRootsPEMFiles(t *testing.T) {
	p := newTestProxyManagerWithDNS()
	issuer := NewACMEIssuer()
	issuer.CA = "https://private-ca.example.internal/acme/directory"
	issuer.TrustedRootsPEMFiles = []string{"/etc/containarium/private-ca-root.pem"}
	policy := &CaddyTLSAutomationPolicy{Issuers: []CaddyTLSIssuer{issuer}}

	p.ensureDNSIssuers(policy)

	got := policy.Issuers[0].TrustedRootsPEMFiles
	if len(got) != 1 || got[0] != "/etc/containarium/private-ca-root.pem" {
		t.Errorf("TrustedRootsPEMFiles = %v, want [/etc/containarium/private-ca-root.pem] preserved — "+
			"a private CA's issuer is unusable without its trust root", got)
	}
}

func TestEnsureDNSIssuers_PreservesIssuerCount(t *testing.T) {
	p := newTestProxyManagerWithDNS()
	custom := NewACMEIssuer()
	custom.CA = "https://private-ca.example.internal/acme/directory"
	policy := &CaddyTLSAutomationPolicy{
		Issuers: []CaddyTLSIssuer{NewACMEIssuer(), NewZeroSSLIssuer(), custom},
	}

	p.ensureDNSIssuers(policy)

	if len(policy.Issuers) != 3 {
		t.Fatalf("got %d issuers, want 3 preserved (a three-issuer policy silently becoming one or two "+
			"is the #1671 bug)", len(policy.Issuers))
	}
	assertAllIssuersSolveDNS(t, *policy)
}

// A non-ACME issuer (e.g. Caddy's own "internal" CA, kept deliberately off
// public ACME) must be left completely alone — attaching challenges.dns to
// it is meaningless, and replacing it would attempt public issuance for a
// subject someone explicitly kept internal-only.
func TestEnsureDNSIssuers_LeavesNonACMEIssuerAlone(t *testing.T) {
	p := newTestProxyManagerWithDNS()
	internal := CaddyTLSIssuer{Module: "internal"}
	policy := &CaddyTLSAutomationPolicy{
		Issuers: []CaddyTLSIssuer{internal, NewACMEIssuer()},
	}

	if !p.ensureDNSIssuers(policy) {
		t.Fatal("ensureDNSIssuers reported no change, but the acme issuer had no DNS-01 challenge")
	}

	if policy.Issuers[0].Module != "internal" || policy.Issuers[0].Challenges != nil {
		t.Errorf("the internal issuer was modified: %+v, want it untouched", policy.Issuers[0])
	}
	if policy.Issuers[1].Challenges == nil || policy.Issuers[1].Challenges.DNS == nil {
		t.Error("the acme issuer did not get a DNS-01 challenge attached")
	}

	// Idempotent: a second call must not report a change — the internal
	// issuer permanently lacks challenges by design, so the outer guard
	// must not mistake that for "still needs repair" forever.
	if p.ensureDNSIssuers(policy) {
		t.Error("ensureDNSIssuers reported a change on a policy already fully repaired")
	}
}

func TestEnsureDNSIssuers_NoOpWhenAllACMEIssuersAlreadySolveDNS(t *testing.T) {
	p := newTestProxyManagerWithDNS()
	policy := &CaddyTLSAutomationPolicy{
		Issuers: []CaddyTLSIssuer{{Module: "internal"}, issuersFor(testDNSChallenge())[0]},
	}
	if p.ensureDNSIssuers(policy) {
		t.Error("ensureDNSIssuers reported a change though the only ACME issuer already solves DNS-01")
	}
}
