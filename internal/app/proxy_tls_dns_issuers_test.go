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
