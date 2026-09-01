package app

import (
	"testing"
)

// #1616: CaddyTLSIssuer.Email was declared but nothing could set it — no env
// var, no flag, nothing in the tree. Because ZeroSSL refuses ACME account
// registration without a contact address, the second issuer on every policy
// was permanently dead:
//
//	"could not get certificate from issuer","issuer":"acme.zerossl.com-v2-DV90",
//	"error":"account pre-registration callback: your email address is required"
//
// Corroborated on both production primaries: the Caddy certificate store held
// only a Let's Encrypt account directory — no ZeroSSL account had ever been
// created anywhere. So every host ran with exactly one working issuer and a
// fallback that looked configured and could not function.
//
// Missing contact also means no expiry warnings from either CA, which is one
// of the few external signals that would have surfaced the stalled renewals
// behind #1068 and the cloud-side ACME issues.

func TestACMEEmailFromEnv_ReadsTheVariable(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_EMAIL", "ops@example.com")
	if got := ACMEEmailFromEnv(); got != "ops@example.com" {
		t.Errorf("ACMEEmailFromEnv() = %q, want ops@example.com", got)
	}
}

func TestACMEEmailFromEnv_TrimsAndTolerAtesUnset(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_EMAIL", "   ops@example.com  ")
	if got := ACMEEmailFromEnv(); got != "ops@example.com" {
		t.Errorf("whitespace not trimmed: %q", got)
	}
	t.Setenv("CONTAINARIUM_ACME_EMAIL", "")
	if got := ACMEEmailFromEnv(); got != "" {
		t.Errorf("unset should yield empty, got %q", got)
	}
}

// With an email configured, both CAs are usable and both must carry it —
// ZeroSSL because it refuses to register without one, Let's Encrypt because
// that is where expiry warnings are sent.
func TestIssuersFor_AppliesEmailToEveryIssuer(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_EMAIL", "ops@example.com")

	issuers := issuersFor(nil)
	if len(issuers) != 2 {
		t.Fatalf("want 2 issuers when an email is configured, got %d", len(issuers))
	}
	for i, is := range issuers {
		if is.Email != "ops@example.com" {
			t.Errorf("issuer %d (%s) has email %q, want ops@example.com", i, is.CA, is.Email)
		}
	}
}

// THE fix for the dead fallback: with no email, ZeroSSL cannot register, so
// emitting it buys a guaranteed-failed round trip and a log line on every
// issuance. Emit only the issuer that can actually work.
func TestIssuersFor_OmitsZeroSSLWithoutAnEmail(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_EMAIL", "")

	issuers := issuersFor(nil)
	for _, is := range issuers {
		if is.CA == zeroSSLDirectory {
			t.Fatalf("ZeroSSL emitted with no email — it cannot register, so every " +
				"issuance pays a failed attempt for an issuer that can never succeed (#1616)")
		}
	}
	if len(issuers) != 1 {
		t.Errorf("want just the Let's Encrypt issuer, got %d", len(issuers))
	}
}

// The DNS-01 wiring must survive the email change: issuers still need their
// challenge config, or wildcard subjects silently never issue (#1066).
func TestIssuersFor_StillAttachesDNSChallenge(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_EMAIL", "ops@example.com")

	for i, is := range issuersFor(testDNSChallenge()) {
		if is.Challenges == nil || is.Challenges.DNS == nil {
			t.Errorf("issuer %d lost its DNS-01 challenge config", i)
		}
	}
}

// Existing hosts already have policies, and ProvisionTLS/EnsureTLSSubjects
// only append subjects — issuers are left alone unless something repairs
// them. Without this, configuring the email would fix nothing on any host
// that is already running, which is every host we have.
func TestEnsureIssuerEmail_RepairsAPolicyMissingIt(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_EMAIL", "ops@example.com")
	p := NewProxyManager("http://127.0.0.1:1", "example.com")

	policy := CaddyTLSAutomationPolicy{
		Subjects: []string{"app.example.com"},
		Issuers:  []CaddyTLSIssuer{{Module: "acme"}, {Module: "acme", CA: zeroSSLDirectory}},
	}

	if !p.ensureIssuerEmail(&policy) {
		t.Fatal("expected a repair when issuers carry no email")
	}
	for i, is := range policy.Issuers {
		if is.Email != "ops@example.com" {
			t.Errorf("issuer %d still has email %q after repair", i, is.Email)
		}
	}
}

// Runs on every reconcile tick, so a no-change tick must write nothing.
func TestEnsureIssuerEmail_NoOpWhenAlreadySet(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_EMAIL", "ops@example.com")
	p := NewProxyManager("http://127.0.0.1:1", "example.com")

	policy := CaddyTLSAutomationPolicy{
		Issuers: []CaddyTLSIssuer{{Module: "acme", Email: "ops@example.com"}},
	}
	if p.ensureIssuerEmail(&policy) {
		t.Error("reported a change when the email was already correct — this runs every tick")
	}
}

// With nothing configured there is nothing to repair. Critically it must not
// blank an email an operator set by hand outside the daemon.
func TestEnsureIssuerEmail_LeavesPolicyAloneWhenUnset(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_EMAIL", "")
	p := NewProxyManager("http://127.0.0.1:1", "example.com")

	policy := CaddyTLSAutomationPolicy{
		Issuers: []CaddyTLSIssuer{{Module: "acme", Email: "set-by-hand@example.com"}},
	}
	if p.ensureIssuerEmail(&policy) {
		t.Error("reported a change when no email is configured")
	}
	if policy.Issuers[0].Email != "set-by-hand@example.com" {
		t.Errorf("clobbered an operator-set email: %q", policy.Issuers[0].Email)
	}
}

// The decision to omit ZeroSSL without an email has to reach hosts that are
// already running, not just newly-created policies — otherwise every host in
// the fleet keeps the dead issuer it has today and goes on paying a
// guaranteed-failed issuance attempt per certificate (#1616).
func TestEnsureIssuerEmail_DropsUnregisterableZeroSSLWhenUnset(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_EMAIL", "")
	p := NewProxyManager("http://127.0.0.1:1", "example.com")

	policy := CaddyTLSAutomationPolicy{
		Subjects: []string{"app.example.com"},
		Issuers:  []CaddyTLSIssuer{{Module: "acme"}, {Module: "acme", CA: zeroSSLDirectory}},
	}

	if !p.ensureIssuerEmail(&policy) {
		t.Fatal("expected the unregisterable ZeroSSL issuer to be dropped")
	}
	if len(policy.Issuers) != 1 || policy.Issuers[0].CA == zeroSSLDirectory {
		t.Fatalf("want only the Let's Encrypt issuer left, got %+v", policy.Issuers)
	}
	// Idempotent — this runs on every reconcile tick.
	if p.ensureIssuerEmail(&policy) {
		t.Error("second pass reported a change; every tick would write to Caddy")
	}
}

// A ZeroSSL issuer carrying an address an operator set by hand through Caddy's
// admin API can register perfectly well. Dropping it because the daemon's own
// env is unset would delete a working fallback.
func TestEnsureIssuerEmail_KeepsZeroSSLThatHasItsOwnEmail(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_EMAIL", "")
	p := NewProxyManager("http://127.0.0.1:1", "example.com")

	policy := CaddyTLSAutomationPolicy{
		Issuers: []CaddyTLSIssuer{
			{Module: "acme", Email: "set-by-hand@example.com"},
			{Module: "acme", CA: zeroSSLDirectory, Email: "set-by-hand@example.com"},
		},
	}
	if p.ensureIssuerEmail(&policy) {
		t.Error("reported a change against issuers that are already registerable")
	}
	if len(policy.Issuers) != 2 {
		t.Fatalf("dropped a ZeroSSL issuer that has its own contact address: %+v", policy.Issuers)
	}
}

// Dropping the dead issuer must never empty the list: `issuers` is
// `omitempty`, so an empty array disappears from the emitted JSON and Caddy
// silently falls back to its own defaults — reinstating the very ZeroSSL
// issuer we just removed.
func TestEnsureIssuerEmail_NeverLeavesAPolicyWithNoIssuers(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_EMAIL", "")
	p := NewProxyManager("http://127.0.0.1:1", "example.com")

	policy := CaddyTLSAutomationPolicy{
		Subjects: []string{"app.example.com"},
		Issuers:  []CaddyTLSIssuer{{Module: "acme", CA: zeroSSLDirectory}},
	}

	p.ensureIssuerEmail(&policy)
	if len(policy.Issuers) == 0 {
		t.Fatal("policy left with no issuers — Caddy would fall back to its defaults")
	}
	for _, is := range policy.Issuers {
		if is.CA == zeroSSLDirectory {
			t.Errorf("unregisterable ZeroSSL issuer survived: %+v", is)
		}
	}
}
