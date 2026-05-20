package wake

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Phase 1.9 — tests for the wake source-IP gate (audit A-MED-5).

func withEnv(t *testing.T, val string) {
	t.Helper()
	prev := getEnv
	getEnv = func(string) string { return val }
	t.Cleanup(func() { getEnv = prev })
}

func TestLoadTrustedProxies_EmptyWarnsAndReturnsNil(t *testing.T) {
	withEnv(t, "")
	got, err := LoadTrustedProxies()
	if err != nil {
		t.Fatalf("unset env should not error, got %v", err)
	}
	if got != nil {
		t.Fatalf("unset env should return nil, got %v", got)
	}
}

func TestLoadTrustedProxies_ParsesCIDR(t *testing.T) {
	withEnv(t, "10.0.0.0/8, 192.168.1.0/24")
	got, err := LoadTrustedProxies()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 prefixes, got %d", len(got))
	}
	if got[0].String() != "10.0.0.0/8" {
		t.Fatalf("first prefix: got %s", got[0])
	}
	if got[1].String() != "192.168.1.0/24" {
		t.Fatalf("second prefix: got %s", got[1])
	}
}

func TestLoadTrustedProxies_BareIPBecomesHostPrefix(t *testing.T) {
	withEnv(t, "192.168.1.5, ::1")
	got, err := LoadTrustedProxies()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 prefixes, got %d", len(got))
	}
	if got[0].String() != "192.168.1.5/32" {
		t.Fatalf("bare v4 should become /32, got %s", got[0])
	}
	if got[1].String() != "::1/128" {
		t.Fatalf("bare v6 should become /128, got %s", got[1])
	}
}

func TestLoadTrustedProxies_RejectsWildcard(t *testing.T) {
	withEnv(t, "0.0.0.0/0")
	_, err := LoadTrustedProxies()
	if err == nil {
		t.Fatal("wildcard /0 should be refused")
	}
	if !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("error should mention wildcard: %v", err)
	}
}

func TestLoadTrustedProxies_RejectsMalformed(t *testing.T) {
	cases := []string{
		"not-an-ip",
		"10.0.0.0/garbage",
		"999.999.999.999",
		"10.0.0.0/33",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			withEnv(t, c)
			_, err := LoadTrustedProxies()
			if err == nil {
				t.Fatalf("malformed entry %q should error", c)
			}
		})
	}
}

func TestLoadTrustedProxies_IgnoresEmptyElements(t *testing.T) {
	withEnv(t, "10.0.0.0/8,,, ,192.168.0.0/16")
	got, err := LoadTrustedProxies()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 prefixes after dropping empties, got %d", len(got))
	}
}

func mkReq(remote string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	return r
}

func TestIsTrustedSource_LoopbackAlwaysAllowed(t *testing.T) {
	// Even with a non-empty allowlist that excludes loopback,
	// loopback must always be accepted — Caddy on the same host
	// is the canonical production shape.
	allow := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []string{"127.0.0.1:54321", "[::1]:54321"}
	for _, rem := range cases {
		t.Run(rem, func(t *testing.T) {
			if !isTrustedSource(mkReq(rem), allow) {
				t.Fatalf("%s should be trusted (loopback)", rem)
			}
		})
	}
}

func TestIsTrustedSource_EmptyAllowlistPermissive(t *testing.T) {
	// Rollout mode: no allowlist configured -> accept anything
	// (with the startup WARNING from LoadTrustedProxies).
	if !isTrustedSource(mkReq("203.0.113.5:1234"), nil) {
		t.Fatal("empty allowlist should be permissive (rollout mode)")
	}
}

func TestIsTrustedSource_AllowlistMatches(t *testing.T) {
	allow := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.5/32"),
	}
	cases := map[string]bool{
		"10.0.0.5:1234":      true,
		"10.255.255.255:80":  true,
		"192.168.1.5:1234":   true,
		"192.168.1.6:1234":   false,
		"203.0.113.5:1234":   false,
	}
	for rem, want := range cases {
		t.Run(rem, func(t *testing.T) {
			got := isTrustedSource(mkReq(rem), allow)
			if got != want {
				t.Fatalf("%s: got %v want %v", rem, got, want)
			}
		})
	}
}

func TestIsTrustedSource_UnparseableRemoteAddrFailsClosed(t *testing.T) {
	// Loopback always-allow happens before the parse, so use a
	// genuinely unparseable RemoteAddr (no host part, no IP).
	allow := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if isTrustedSource(mkReq("garbage"), allow) {
		t.Fatal("unparseable RemoteAddr must fail closed")
	}
}

func TestIsTrustedSource_HostOnlyRemoteAddr(t *testing.T) {
	// SplitHostPort fails when there's no port — the code falls
	// back to using the whole RemoteAddr as the host. Make sure
	// that path still parses real IPs correctly.
	allow := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if !isTrustedSource(mkReq("10.0.0.5"), allow) {
		t.Fatal("host-only RemoteAddr should still be parsed and matched")
	}
}

// TestServeHTTP_RejectsUntrustedSource validates that the gate
// short-circuits ServeHTTP with 403 before any route lookup or
// wake side-effect. Uses the same fake harness as proxy_test.go;
// the test runs with an allowlist that excludes RemoteAddr.
func TestServeHTTP_RejectsUntrustedSource(t *testing.T) {
	const fullDomain = "alice-web.example.test"
	proxy := NewWakeProxy(
		&fakeStarter{ready: true},
		&fakeLookup{fullDomain: fullDomain, containerName: "alice-container"},
		&fakeRouteStore{},
		nil,
		nil,
		1*time.Second,
	)
	// Allowlist contains only 10.0.0.0/8; httptest.NewRequest's
	// default RemoteAddr is 192.0.2.1 (TEST-NET-1), which won't
	// match and isn't loopback.
	proxy.SetTrustedProxies([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})

	req := httptest.NewRequest(http.MethodGet, "http://"+fullDomain+"/", nil)
	req.Host = fullDomain
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("untrusted source: got %d, want 403; body=%q", rec.Code, rec.Body.String())
	}
}

// TestServeHTTP_AcceptsLoopbackEvenWithAllowlist confirms the
// loopback exemption — production deployments have Caddy on the
// same host as the daemon, so 127.0.0.1 must always work even
// when operators have set a strict allowlist that doesn't
// include loopback.
func TestServeHTTP_AcceptsLoopbackEvenWithAllowlist(t *testing.T) {
	const fullDomain = "alice-web.example.test"
	proxy := NewWakeProxy(
		&fakeStarter{ready: false, err: nil}, // wake will time-out → 503
		&fakeLookup{fullDomain: fullDomain, containerName: "alice-container"},
		&fakeRouteStore{},
		nil,
		nil,
		10*time.Millisecond,
	)
	proxy.SetTrustedProxies([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})

	req := httptest.NewRequest(http.MethodGet, "http://"+fullDomain+"/", nil)
	req.Host = fullDomain
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	// Loopback should pass the gate. Past the gate, the
	// (failing) wake takes over — anything other than 403 means
	// the gate let us through.
	if rec.Code == http.StatusForbidden {
		t.Fatalf("loopback should bypass the gate even with strict allowlist; got 403 body=%q", rec.Body.String())
	}
}
