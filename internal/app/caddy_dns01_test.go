package app

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestIssuersFor_NoDNS_MatchesLegacyDefault locks in that, without a DNS
// challenge, the emitted issuers JSON is byte-identical to the pre-#378
// default (acme + zerossl, no `challenges` field) — so existing HTTP-01
// deployments are unaffected.
func TestIssuersFor_NoDNS_MatchesLegacyDefault(t *testing.T) {
	got, err := json.Marshal(issuersFor(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"module":"acme"},{"module":"acme","ca":"https://acme.zerossl.com/v2/DV90"}]`
	if string(got) != want {
		t.Errorf("no-DNS issuers changed shape:\n got: %s\nwant: %s", got, want)
	}
}

// TestIssuersFor_DNS_AttachesChallengeToBoth verifies the DNS-01 challenge
// block lands on both the ACME and ZeroSSL issuers.
func TestIssuersFor_DNS_AttachesChallengeToBoth(t *testing.T) {
	dns := &CaddyACMEChallenges{DNS: &CaddyDNSChallenge{Provider: map[string]interface{}{
		"name": "cloudflare", "api_token": "{env.CF_API_TOKEN}",
	}}}
	issuers := issuersFor(dns)
	if len(issuers) != 2 {
		t.Fatalf("want 2 issuers, got %d", len(issuers))
	}
	for i, iss := range issuers {
		if iss.Challenges == nil || iss.Challenges.DNS == nil {
			t.Fatalf("issuer %d missing DNS challenge", i)
		}
		if iss.Challenges.DNS.Provider["name"] != "cloudflare" {
			t.Errorf("issuer %d provider name = %v, want cloudflare", i, iss.Challenges.DNS.Provider["name"])
		}
	}
	// And it serializes into Caddy's expected nesting.
	out, _ := json.Marshal(issuers[0])
	if !strings.Contains(string(out), `"challenges":{"dns":{"provider":{"api_token":"{env.CF_API_TOKEN}","name":"cloudflare"}}}`) {
		t.Errorf("unexpected DNS-01 issuer JSON: %s", out)
	}
}

func TestDNSChallengeFromEnv(t *testing.T) {
	t.Run("unset → nil (default HTTP-01)", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "")
		if got := DNSChallengeFromEnv(); got != nil {
			t.Errorf("want nil when provider unset, got %+v", got)
		}
	})

	t.Run("cloudflare default api_token", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
		t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")
		got := DNSChallengeFromEnv()
		if got == nil || got.DNS == nil {
			t.Fatal("want a DNS challenge")
		}
		if got.DNS.Provider["name"] != "cloudflare" {
			t.Errorf("name = %v", got.DNS.Provider["name"])
		}
		if got.DNS.Provider["api_token"] != "{env.CF_API_TOKEN}" {
			t.Errorf("api_token = %v, want the CF_API_TOKEN env placeholder", got.DNS.Provider["api_token"])
		}
	})

	t.Run("arbitrary provider via JSON config", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "route53")
		t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", `{"max_retries":10}`)
		got := DNSChallengeFromEnv()
		if got == nil || got.DNS == nil {
			t.Fatal("want a DNS challenge")
		}
		if got.DNS.Provider["name"] != "route53" {
			t.Errorf("name = %v", got.DNS.Provider["name"])
		}
		// route53 reads AWS env, so no token field is injected.
		if _, ok := got.DNS.Provider["api_token"]; ok {
			t.Error("did not expect api_token for route53")
		}
		if got.DNS.Provider["max_retries"] != float64(10) {
			t.Errorf("max_retries = %v, want extra JSON field merged in", got.DNS.Provider["max_retries"])
		}
	})

	t.Run("explicit config overrides cloudflare default", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
		t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", `{"api_token":"{env.MY_TOKEN}"}`)
		got := DNSChallengeFromEnv()
		if got.DNS.Provider["api_token"] != "{env.MY_TOKEN}" {
			t.Errorf("api_token = %v, want explicit override", got.DNS.Provider["api_token"])
		}
	})
}

// TestNewTLSPolicyWithDNS_Wildcard checks a wildcard subject pairs with the
// DNS-01 issuers (the combination HTTP-01 can't do).
func TestNewTLSPolicyWithDNS_Wildcard(t *testing.T) {
	dns := DNSChallengeFromEnvWith(t, "cloudflare")
	pol := NewTLSPolicyWithDNS([]string{"*.example.com"}, dns)
	if len(pol.Subjects) != 1 || pol.Subjects[0] != "*.example.com" {
		t.Fatalf("subjects = %v", pol.Subjects)
	}
	if pol.Issuers[0].Challenges == nil {
		t.Error("wildcard policy issuer missing DNS-01 challenge")
	}
}

// DNSChallengeFromEnvWith is a tiny test helper that sets the provider env and
// returns the resulting challenge.
func DNSChallengeFromEnvWith(t *testing.T, provider string) *CaddyACMEChallenges {
	t.Helper()
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", provider)
	return DNSChallengeFromEnv()
}
