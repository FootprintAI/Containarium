package sentinel

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPrimaryRegistry_LookupByBaseDomainSuffix covers the suffix-match
// path: containers exposed under a primary's BaseDomain (e.g.
// blog.example.org) route to that primary without each name
// being a registered alias.
func TestPrimaryRegistry_LookupByBaseDomainSuffix(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:        "prod",
		Hostname:    "prod.example.com",
		BaseDomains: []string{"example.com"},
		IP:          "10.0.0.10",
		Port:        443,
	})
	r.Register(Primary{
		Pool:        "demo",
		Hostname:    "demo.example.org",
		BaseDomains: []string{"example.org"},
		IP:          "10.0.0.20",
		Port:        443,
	})

	t.Run("matches by suffix", func(t *testing.T) {
		p := r.LookupByBaseDomainSuffix("blog.example.org")
		if assert.NotNil(t, p) {
			assert.Equal(t, Pool("demo"), p.Pool)
		}
	})

	t.Run("deeper subdomain also matches", func(t *testing.T) {
		p := r.LookupByBaseDomainSuffix("a.b.c.example.org")
		if assert.NotNil(t, p) {
			assert.Equal(t, Pool("demo"), p.Pool)
		}
	})

	t.Run("base domain itself is not a match", func(t *testing.T) {
		// "example.org" is NOT "*.example.org" — proper-suffix only.
		// This keeps the apex hostname usable as a separate Hostname/Alias
		// without ambiguity.
		assert.Nil(t, r.LookupByBaseDomainSuffix("example.org"))
	})

	t.Run("unrelated hostname returns nil", func(t *testing.T) {
		assert.Nil(t, r.LookupByBaseDomainSuffix("evil.invalid"))
	})

	t.Run("empty hostname returns nil", func(t *testing.T) {
		assert.Nil(t, r.LookupByBaseDomainSuffix(""))
	})
}

// TestPrimaryRegistry_LookupByBaseDomainSuffix_LongestWins ensures that
// when one BaseDomain is a tail of another (lab.example.com vs
// example.com), the more-specific match wins.
func TestPrimaryRegistry_LookupByBaseDomainSuffix_LongestWins(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:        "prod",
		Hostname:    "prod.example.com",
		BaseDomains: []string{"example.com"},
		IP:          "10.0.0.10",
		Port:        443,
	})
	r.Register(Primary{
		Pool:        "lab",
		Hostname:    "lab-primary.example.com",
		BaseDomains: []string{"lab.example.com"},
		IP:          "10.0.0.30",
		Port:        443,
	})

	// notebook.lab.example.com could match both, but the longer suffix
	// (lab.example.com) is more specific and should win.
	p := r.LookupByBaseDomainSuffix("notebook.lab.example.com")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("lab"), p.Pool, "longer suffix should win")
	}

	// A sibling that only matches the shorter suffix still routes correctly.
	p = r.LookupByBaseDomainSuffix("api.example.com")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("prod"), p.Pool)
	}
}

// TestPrimaryRegistry_LookupByBaseDomainSuffix_AmbiguousFailsClosed
// asserts that two primaries advertising the SAME BaseDomain — a
// configuration error — make suffix lookups return nil rather than
// pick one arbitrarily.
func TestPrimaryRegistry_LookupByBaseDomainSuffix_AmbiguousFailsClosed(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:        "a",
		Hostname:    "a.example.com",
		BaseDomains: []string{"example.com"},
		IP:          "10.0.0.10",
		Port:        443,
	})
	r.Register(Primary{
		Pool:        "b",
		Hostname:    "b.example.com",
		BaseDomains: []string{"example.com"},
		IP:          "10.0.0.11",
		Port:        443,
	})

	assert.Nil(t, r.LookupByBaseDomainSuffix("blog.example.com"),
		"ambiguous suffix should fail closed, not pick arbitrarily")
}

// TestPrimaryRegistry_LookupByBaseDomainSuffix_EmptyBaseDomainSkipped
// confirms that a primary with no BaseDomains is invisible to suffix
// lookup. This keeps single-pool / legacy deployments unaffected.
func TestPrimaryRegistry_LookupByBaseDomainSuffix_EmptyBaseDomainSkipped(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:     "legacy",
		Hostname: "legacy.example.com",
		IP:       "10.0.0.10",
		Port:     443,
	})

	assert.Nil(t, r.LookupByBaseDomainSuffix("blog.example.com"),
		"primary without BaseDomains must not match suffix lookups")
}

// TestPrimaryRegistry_ExactHostnameBeatsSuffix verifies that the SNI
// router precedence works at the registry level: an exact-alias entry
// on a different primary wins over a suffix match. The router is
// expected to try LookupByHostname before LookupByBaseDomainSuffix;
// these two methods are tested in isolation here, but the test asserts
// both return what they should so the router can apply that precedence
// straightforwardly.
func TestPrimaryRegistry_ExactHostnameBeatsSuffix(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:     "prod",
		Hostname: "prod.example.com",
		Aliases:  []string{"blog.example.org"}, // explicit override
		IP:       "10.0.0.10",
		Port:     443,
	})
	r.Register(Primary{
		Pool:        "demo",
		Hostname:    "demo.example.org",
		BaseDomains: []string{"example.org"},
		IP:          "10.0.0.20",
		Port:        443,
	})

	// Exact alias on prod points at prod.
	p := r.LookupByHostname("blog.example.org")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("prod"), p.Pool)
	}

	// Suffix match would otherwise pick demo. Router runs exact first,
	// so the alias override stands.
	pSuffix := r.LookupByBaseDomainSuffix("blog.example.org")
	if assert.NotNil(t, pSuffix) {
		assert.Equal(t, Pool("demo"), pSuffix.Pool,
			"suffix lookup still resolves to demo in isolation; router precedence is what decides")
	}
}

// TestPrimaryRegistry_LookupByBaseDomainSuffix_MultipleOnOnePrimary
// exercises the multi-domain feature: a single primary advertises
// several base domains so one backend can host workloads under
// different parent domains (the lab-hosts-demo use case from
// docs/PLAN-DEMO-CONTAINER-MIGRATION.md).
func TestPrimaryRegistry_LookupByBaseDomainSuffix_MultipleOnOnePrimary(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:     "lab",
		Hostname: "lab-primary.example.com",
		// Lab backend hosts both its own pool's workloads AND migrated
		// demo workloads published under example.org.
		BaseDomains: []string{"lab.example.com", "demo.example.org"},
		IP:          "10.0.0.30",
		Port:        443,
	})

	// First base domain matches.
	p := r.LookupByBaseDomainSuffix("notebook.lab.example.com")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("lab"), p.Pool)
	}

	// Second base domain matches the same primary.
	p = r.LookupByBaseDomainSuffix("blog.demo.example.org")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("lab"), p.Pool,
			"demo subdomain should route to the lab primary that hosts it")
	}

	// Neither base domain matches → nil.
	assert.Nil(t, r.LookupByBaseDomainSuffix("api.example.com"),
		"only lab.example.com is advertised, not the parent example.com")
}

// TestPrimaryRegistry_LookupByBaseDomainSuffix_MultiDomainLosesToMoreSpecific
// verifies the longest-wins rule still applies when one primary's
// BaseDomain is the suffix of another primary's BaseDomain — even if
// the latter has multiple base domains listed.
func TestPrimaryRegistry_LookupByBaseDomainSuffix_MultiDomainLosesToMoreSpecific(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:        "lab",
		Hostname:    "lab-primary.example.com",
		BaseDomains: []string{"example.com", "demo.example.org"},
		IP:          "10.0.0.30",
		Port:        443,
	})
	r.Register(Primary{
		Pool:        "lab2",
		Hostname:    "lab2-primary.example.com",
		BaseDomains: []string{"sub.example.com"},
		IP:          "10.0.0.31",
		Port:        443,
	})

	// "notebook.sub.example.com" matches both lab's "example.com" and
	// lab2's "sub.example.com". Longer suffix wins.
	p := r.LookupByBaseDomainSuffix("notebook.sub.example.com")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("lab2"), p.Pool, "more-specific suffix wins across multi-domain primaries")
	}

	// "blog.example.com" only matches lab's first base domain.
	p = r.LookupByBaseDomainSuffix("blog.example.com")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("lab"), p.Pool)
	}
}

// TestPrimaryRegistry_LookupByBaseDomainSuffix_AmbiguousAcrossMultiDomain
// ensures that ambiguity detection still fires when the same base
// domain appears on two primaries — even if it's only one entry in
// each primary's multi-domain list.
func TestPrimaryRegistry_LookupByBaseDomainSuffix_AmbiguousAcrossMultiDomain(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:        "a",
		Hostname:    "a.example.com",
		BaseDomains: []string{"example.com", "extra-a.example.net"},
		IP:          "10.0.0.10",
		Port:        443,
	})
	r.Register(Primary{
		Pool:        "b",
		Hostname:    "b.example.com",
		BaseDomains: []string{"extra-b.example.net", "example.com"},
		IP:          "10.0.0.11",
		Port:        443,
	})

	assert.Nil(t, r.LookupByBaseDomainSuffix("blog.example.com"),
		"shared base domain across primaries must still fail closed regardless of slot order")

	// Each primary's unique domains still resolve cleanly.
	p := r.LookupByBaseDomainSuffix("foo.extra-a.example.net")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("a"), p.Pool)
	}
	p = r.LookupByBaseDomainSuffix("foo.extra-b.example.net")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("b"), p.Pool)
	}
}

// TestSNIRouting_BaseDomainSuffix is an end-to-end check on the SNI
// router: a BaseDomain-tagged primary captures inbound SNI for its
// suffix without each subdomain being a registered alias, and an
// explicit alias on a different primary still wins (exact > suffix
// precedence). Uses the same dialThroughHandler / startEchoListener
// harness as TestSNIRouting_DispatchToPrimaryOrFallback in sni_test.go.
func TestSNIRouting_BaseDomainSuffix(t *testing.T) {
	demoAddr, demoHits := startEchoListener(t, "DEMO")
	prodAddr, prodHits := startEchoListener(t, "PROD")
	fallbackAddr, fallbackHits := startEchoListener(t, "FALLBACK")

	m := &Manager{primaries: NewPrimaryRegistry()}

	demoHost, demoPortStr, err := net.SplitHostPort(demoAddr)
	require.NoError(t, err)
	m.primaries.Register(Primary{
		Pool:        "demo",
		Hostname:    "demo.example.org",
		BaseDomains: []string{"example.org"},
		IP:          demoHost,
		Port:        mustAtoi(t, demoPortStr),
	})

	prodHost, prodPortStr, err := net.SplitHostPort(prodAddr)
	require.NoError(t, err)
	m.primaries.Register(Primary{
		Pool:     "prod",
		Hostname: "prod.example.com",
		// Explicit alias for a name that ALSO matches demo's BaseDomain.
		// Exact match must win — operator's explicit choice beats the
		// implicit suffix routing.
		Aliases:     []string{"override.example.org"},
		BaseDomains: []string{"example.com"},
		IP:          prodHost,
		Port:        mustAtoi(t, prodPortStr),
	})

	handler := m.buildSNIRoutingHandler(fallbackAddr)

	// Suffix match: any subdomain of example.org → demo.
	got := dialThroughHandler(t, handler, &tls.Config{
		ServerName: "blog.example.org", InsecureSkipVerify: true,
	})
	assert.Equal(t, "DEMO", got, "blog.example.org should suffix-match demo")

	// Suffix match: any subdomain of example.com → prod.
	got = dialThroughHandler(t, handler, &tls.Config{
		ServerName: "api.example.com", InsecureSkipVerify: true,
	})
	assert.Equal(t, "PROD", got, "api.example.com should suffix-match prod")

	// Exact alias wins over suffix: override.example.org → prod
	// even though example.org is demo's BaseDomain.
	got = dialThroughHandler(t, handler, &tls.Config{
		ServerName: "override.example.org", InsecureSkipVerify: true,
	})
	assert.Equal(t, "PROD", got, "exact alias must beat suffix match")

	// Exact hostname still works.
	got = dialThroughHandler(t, handler, &tls.Config{
		ServerName: "prod.example.com", InsecureSkipVerify: true,
	})
	assert.Equal(t, "PROD", got, "exact hostname must hit prod")

	// Nothing matches → fallback.
	got = dialThroughHandler(t, handler, &tls.Config{
		ServerName: "evil.invalid", InsecureSkipVerify: true,
	})
	assert.Equal(t, "FALLBACK", got, "unrelated SNI must fall through")

	assert.Equal(t, 1, demoHits(), "demo hit once (suffix)")
	assert.Equal(t, 3, prodHits(), "prod hit thrice (suffix kafeido + exact alias + exact hostname)")
	assert.Equal(t, 1, fallbackHits(), "fallback hit once (unmatched)")
}

// TestSNIRouting_MultiBaseDomainOnOneBackend is the end-to-end of the
// lab-hosts-demo pattern: one backend, two base domains, both routed.
func TestSNIRouting_MultiBaseDomainOnOneBackend(t *testing.T) {
	labAddr, labHits := startEchoListener(t, "LAB")
	fallbackAddr, _ := startEchoListener(t, "FALLBACK")

	m := &Manager{primaries: NewPrimaryRegistry()}

	labHost, labPortStr, err := net.SplitHostPort(labAddr)
	require.NoError(t, err)
	m.primaries.Register(Primary{
		Pool:        "lab",
		Hostname:    "lab-primary.example.com",
		BaseDomains: []string{"lab.example.com", "demo.example.org"},
		IP:          labHost,
		Port:        mustAtoi(t, labPortStr),
	})

	handler := m.buildSNIRoutingHandler(fallbackAddr)

	// Lab's own pool subdomain.
	got := dialThroughHandler(t, handler, &tls.Config{
		ServerName: "notebook.lab.example.com", InsecureSkipVerify: true,
	})
	assert.Equal(t, "LAB", got, "lab.example.com subdomain should hit lab")

	// Migrated demo subdomain on the same backend.
	got = dialThroughHandler(t, handler, &tls.Config{
		ServerName: "blog.demo.example.org", InsecureSkipVerify: true,
	})
	assert.Equal(t, "LAB", got, "demo.example.org subdomain should also hit lab")

	assert.Equal(t, 2, labHits(), "both SNI suffixes route to the same backend")
}

// TestPrimaryRegistry_RegisterUpdatesBaseDomain ensures that a
// re-registration with a different BaseDomains list replaces the old
// value. Otherwise stale base-domain bindings would persist across
// daemon restarts. Uses disjoint old/new domains so a longer-suffix
// match on either side can't muddy the assertion.
func TestPrimaryRegistry_RegisterUpdatesBaseDomain(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:        "demo",
		Hostname:    "demo.example.test",
		BaseDomains: []string{"example.test"},
		IP:          "10.0.0.20",
		Port:        443,
	})
	r.Register(Primary{
		Pool:        "demo",
		Hostname:    "demo.example.test",
		BaseDomains: []string{"example.org"},
		IP:          "10.0.0.20",
		Port:        443,
	})

	assert.Nil(t, r.LookupByBaseDomainSuffix("blog.example.test"),
		"old BaseDomains should be gone after re-register")
	p := r.LookupByBaseDomainSuffix("blog.example.org")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("demo"), p.Pool)
	}
}
