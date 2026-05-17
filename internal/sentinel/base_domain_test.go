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
// blog.containarium.dev) route to that primary without each name
// being a registered alias.
func TestPrimaryRegistry_LookupByBaseDomainSuffix(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:       "prod",
		Hostname:   "containarium-prod.kafeido.app",
		BaseDomain: "kafeido.app",
		IP:         "10.0.0.10",
		Port:       443,
	})
	r.Register(Primary{
		Pool:       "demo",
		Hostname:   "demo.containarium.dev",
		BaseDomain: "containarium.dev",
		IP:         "10.0.0.20",
		Port:       443,
	})

	t.Run("matches by suffix", func(t *testing.T) {
		p := r.LookupByBaseDomainSuffix("blog.containarium.dev")
		if assert.NotNil(t, p) {
			assert.Equal(t, Pool("demo"), p.Pool)
		}
	})

	t.Run("deeper subdomain also matches", func(t *testing.T) {
		p := r.LookupByBaseDomainSuffix("a.b.c.containarium.dev")
		if assert.NotNil(t, p) {
			assert.Equal(t, Pool("demo"), p.Pool)
		}
	})

	t.Run("base domain itself is not a match", func(t *testing.T) {
		// "containarium.dev" is NOT "*.containarium.dev" — proper-suffix only.
		// This keeps the apex hostname usable as a separate Hostname/Alias
		// without ambiguity.
		assert.Nil(t, r.LookupByBaseDomainSuffix("containarium.dev"))
	})

	t.Run("unrelated hostname returns nil", func(t *testing.T) {
		assert.Nil(t, r.LookupByBaseDomainSuffix("evil.example.com"))
	})

	t.Run("empty hostname returns nil", func(t *testing.T) {
		assert.Nil(t, r.LookupByBaseDomainSuffix(""))
	})
}

// TestPrimaryRegistry_LookupByBaseDomainSuffix_LongestWins ensures that
// when one BaseDomain is a tail of another (lab.kafeido.app vs
// kafeido.app), the more-specific match wins.
func TestPrimaryRegistry_LookupByBaseDomainSuffix_LongestWins(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:       "prod",
		Hostname:   "containarium-prod.kafeido.app",
		BaseDomain: "kafeido.app",
		IP:         "10.0.0.10",
		Port:       443,
	})
	r.Register(Primary{
		Pool:       "lab",
		Hostname:   "containarium-lab.kafeido.app",
		BaseDomain: "lab.kafeido.app",
		IP:         "10.0.0.30",
		Port:       443,
	})

	// notebook.lab.kafeido.app could match both, but the longer suffix
	// (lab.kafeido.app) is more specific and should win.
	p := r.LookupByBaseDomainSuffix("notebook.lab.kafeido.app")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("lab"), p.Pool, "longer suffix should win")
	}

	// A sibling that only matches the shorter suffix still routes correctly.
	p = r.LookupByBaseDomainSuffix("api.kafeido.app")
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
		Pool:       "a",
		Hostname:   "a.kafeido.app",
		BaseDomain: "kafeido.app",
		IP:         "10.0.0.10",
		Port:       443,
	})
	r.Register(Primary{
		Pool:       "b",
		Hostname:   "b.kafeido.app",
		BaseDomain: "kafeido.app",
		IP:         "10.0.0.11",
		Port:       443,
	})

	assert.Nil(t, r.LookupByBaseDomainSuffix("blog.kafeido.app"),
		"ambiguous suffix should fail closed, not pick arbitrarily")
}

// TestPrimaryRegistry_LookupByBaseDomainSuffix_EmptyBaseDomainSkipped
// confirms that a primary with no BaseDomain is invisible to suffix
// lookup. This keeps single-pool / legacy deployments unaffected.
func TestPrimaryRegistry_LookupByBaseDomainSuffix_EmptyBaseDomainSkipped(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:     "legacy",
		Hostname: "legacy.kafeido.app",
		IP:       "10.0.0.10",
		Port:     443,
	})

	assert.Nil(t, r.LookupByBaseDomainSuffix("blog.kafeido.app"),
		"primary without BaseDomain must not match suffix lookups")
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
		Hostname: "containarium-prod.kafeido.app",
		Aliases:  []string{"blog.containarium.dev"}, // explicit override
		IP:       "10.0.0.10",
		Port:     443,
	})
	r.Register(Primary{
		Pool:       "demo",
		Hostname:   "demo.containarium.dev",
		BaseDomain: "containarium.dev",
		IP:         "10.0.0.20",
		Port:       443,
	})

	// Exact alias on prod points at prod.
	p := r.LookupByHostname("blog.containarium.dev")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("prod"), p.Pool)
	}

	// Suffix match would otherwise pick demo. Router runs exact first,
	// so the alias override stands.
	pSuffix := r.LookupByBaseDomainSuffix("blog.containarium.dev")
	if assert.NotNil(t, pSuffix) {
		assert.Equal(t, Pool("demo"), pSuffix.Pool,
			"suffix lookup still resolves to demo in isolation; router precedence is what decides")
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
		Pool:       "demo",
		Hostname:   "demo.containarium.dev",
		BaseDomain: "containarium.dev",
		IP:         demoHost,
		Port:       mustAtoi(t, demoPortStr),
	})

	prodHost, prodPortStr, err := net.SplitHostPort(prodAddr)
	require.NoError(t, err)
	m.primaries.Register(Primary{
		Pool:       "prod",
		Hostname:   "containarium-prod.kafeido.app",
		// Explicit alias for a name that ALSO matches demo's BaseDomain.
		// Exact match must win — operator's explicit choice beats the
		// implicit suffix routing.
		Aliases:    []string{"override.containarium.dev"},
		BaseDomain: "kafeido.app",
		IP:         prodHost,
		Port:       mustAtoi(t, prodPortStr),
	})

	handler := m.buildSNIRoutingHandler(fallbackAddr)

	// Suffix match: any subdomain of containarium.dev → demo.
	got := dialThroughHandler(t, handler, &tls.Config{
		ServerName: "blog.containarium.dev", InsecureSkipVerify: true,
	})
	assert.Equal(t, "DEMO", got, "blog.containarium.dev should suffix-match demo")

	// Suffix match: any subdomain of kafeido.app → prod.
	got = dialThroughHandler(t, handler, &tls.Config{
		ServerName: "api.kafeido.app", InsecureSkipVerify: true,
	})
	assert.Equal(t, "PROD", got, "api.kafeido.app should suffix-match prod")

	// Exact alias wins over suffix: override.containarium.dev → prod
	// even though containarium.dev is demo's BaseDomain.
	got = dialThroughHandler(t, handler, &tls.Config{
		ServerName: "override.containarium.dev", InsecureSkipVerify: true,
	})
	assert.Equal(t, "PROD", got, "exact alias must beat suffix match")

	// Exact hostname still works.
	got = dialThroughHandler(t, handler, &tls.Config{
		ServerName: "containarium-prod.kafeido.app", InsecureSkipVerify: true,
	})
	assert.Equal(t, "PROD", got, "exact hostname must hit prod")

	// Nothing matches → fallback.
	got = dialThroughHandler(t, handler, &tls.Config{
		ServerName: "evil.example.com", InsecureSkipVerify: true,
	})
	assert.Equal(t, "FALLBACK", got, "unrelated SNI must fall through")

	assert.Equal(t, 1, demoHits(), "demo hit once (suffix)")
	assert.Equal(t, 3, prodHits(), "prod hit thrice (suffix kafeido + exact alias + exact hostname)")
	assert.Equal(t, 1, fallbackHits(), "fallback hit once (unmatched)")
}

// TestPrimaryRegistry_RegisterUpdatesBaseDomain ensures that a
// re-registration with a different BaseDomain replaces the old value.
// Otherwise stale base-domain bindings would persist across daemon
// restarts. Uses disjoint old/new domains so a longer-suffix match on
// either side can't muddy the assertion.
func TestPrimaryRegistry_RegisterUpdatesBaseDomain(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:       "demo",
		Hostname:   "demo.example.org",
		BaseDomain: "example.org",
		IP:         "10.0.0.20",
		Port:       443,
	})
	r.Register(Primary{
		Pool:       "demo",
		Hostname:   "demo.example.org",
		BaseDomain: "containarium.dev",
		IP:         "10.0.0.20",
		Port:       443,
	})

	assert.Nil(t, r.LookupByBaseDomainSuffix("blog.example.org"),
		"old BaseDomain should be gone after re-register")
	p := r.LookupByBaseDomainSuffix("blog.containarium.dev")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("demo"), p.Pool)
	}
}
