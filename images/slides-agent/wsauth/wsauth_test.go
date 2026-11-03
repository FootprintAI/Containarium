package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is the injectable clock: tests move time instead of sleeping.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestStore() (*store, *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}
	return newStore(c.now), c
}

func mustMint(t *testing.T, s *store) string {
	t.Helper()
	tok, err := s.mint()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !secretPattern.MatchString(tok) {
		t.Fatalf("minted token %q is not 32 random bytes in base64url", tok)
	}
	return tok
}

func TestRedeemIsSingleUse(t *testing.T) {
	s, _ := newTestStore()
	tok := mustMint(t, s)
	sess, ok := s.redeem(tok)
	if !ok {
		t.Fatal("a fresh token must redeem")
	}
	if sess == tok {
		t.Fatal("the session value must differ from the login token")
	}
	if !s.valid(sess) {
		t.Fatal("the issued session must be valid")
	}
	if _, ok := s.redeem(tok); ok {
		t.Fatal("a redeemed token must be refused on replay")
	}
	if s.valid(tok) {
		t.Fatal("a login token must never be accepted as a session")
	}
}

func TestRedeemExpiry(t *testing.T) {
	s, clock := newTestStore()
	early := mustMint(t, s)
	late := mustMint(t, s)
	clock.advance(tokenTTL - time.Second)
	if _, ok := s.redeem(early); !ok {
		t.Fatal("a token one second before its TTL must redeem")
	}
	clock.advance(time.Second)
	if _, ok := s.redeem(late); ok {
		t.Fatal("a token at its TTL must be refused")
	}
}

func TestRedeemUnknownOrMalformed(t *testing.T) {
	s, _ := newTestStore()
	mustMint(t, s)
	for _, tok := range []string{"", "nope", strings.Repeat("A", 43), strings.Repeat("A", 44), strings.Repeat("!", 43)} {
		if _, ok := s.redeem(tok); ok {
			t.Errorf("redeem(%q) succeeded", tok)
		}
	}
}

func TestBurnedTokenIsRefused(t *testing.T) {
	s, _ := newTestStore()
	tok := mustMint(t, s)
	s.burn(tok)
	if _, ok := s.redeem(tok); ok {
		t.Fatal("a burned token must be refused")
	}
}

func TestConcurrentRedeemSucceedsOnce(t *testing.T) {
	s, _ := newTestStore()
	tok := mustMint(t, s)
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, ok := s.redeem(tok); ok {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("%d concurrent redemptions succeeded, want exactly 1", got)
	}
}

func TestSessionsAreDistinctRandom(t *testing.T) {
	s, _ := newTestStore()
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok := mustMint(t, s)
		sess, ok := s.redeem(tok)
		if !ok {
			t.Fatal("redeem failed")
		}
		if !secretPattern.MatchString(sess) {
			t.Fatalf("session %q is not 32 random bytes in base64url", sess)
		}
		if seen[sess] || seen[tok] {
			t.Fatalf("value repeated after %d rounds", i)
		}
		seen[sess], seen[tok] = true, true
	}
}

func TestSessionExpiryAndRestart(t *testing.T) {
	s, clock := newTestStore()
	sess, _ := s.redeem(mustMint(t, s))
	clock.advance(sessionTTL - time.Second)
	if !s.valid(sess) {
		t.Fatal("a session before its TTL must be valid")
	}
	// A restarted helper (the container is recreated when the box re-stages
	// its auth material) knows no session.
	restarted, _ := newTestStore()
	if restarted.valid(sess) {
		t.Fatal("a session must not survive a helper restart")
	}
	clock.advance(time.Second)
	if s.valid(sess) {
		t.Fatal("a session at its TTL must be invalid")
	}
	if s.valid("") || s.valid(strings.Repeat("A", 43)) {
		t.Fatal("unknown sessions must be invalid")
	}
}

func TestMintCapsPendingTokens(t *testing.T) {
	s, clock := newTestStore()
	for i := 0; i < maxPending; i++ {
		mustMint(t, s)
	}
	if _, err := s.mint(); !errors.Is(err, errTooManyPending) {
		t.Fatalf("mint past the cap: %v, want errTooManyPending", err)
	}
	clock.advance(tokenTTL)
	mustMint(t, s) // expired tokens are collected
}

func TestSessionCapEvictsOldest(t *testing.T) {
	s, clock := newTestStore()
	first, _ := s.redeem(mustMint(t, s))
	clock.advance(time.Second)
	second, _ := s.redeem(mustMint(t, s))
	for i := 2; i < maxSessions; i++ {
		if _, ok := s.redeem(mustMint(t, s)); !ok {
			t.Fatal("redeem failed")
		}
	}
	if !s.valid(first) {
		t.Fatal("at the cap nothing is evicted yet")
	}
	last, _ := s.redeem(mustMint(t, s))
	if s.valid(first) || !s.valid(second) || !s.valid(last) {
		t.Fatal("past the cap exactly the oldest session is evicted")
	}
}

func TestSecretFailsClosed(t *testing.T) {
	s, _ := newTestStore()
	tok := mustMint(t, s)
	s.random = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	if _, err := s.mint(); err == nil {
		t.Fatal("mint must fail without entropy")
	}
	if _, ok := s.redeem(tok); ok {
		t.Fatal("redeem must fail without entropy")
	}
}

// --- HTTP surface --------------------------------------------------------

func mintOver(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/__mint", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("mint: %d %v", rec.Code, rec.Header())
	}
	var m mintResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || !secretPattern.MatchString(m.Token) {
		t.Fatalf("mint body %q: %v", rec.Body, err)
	}
	return m.Token
}

func postLogin(h http.Handler, tok, site string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/__ws_login", strings.NewReader(url.Values{"t": {tok}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if site != "" {
		req.Header.Set("Sec-Fetch-Site", site)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func checkNoStore(t *testing.T, h http.Header) {
	t.Helper()
	if h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("bootstrap response must be no-store and no-referrer: %v", h)
	}
}

func sessionFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatalf("no %s cookie in %v", sessionCookie, rec.Header())
	return nil
}

func TestHTTPLoginFlow(t *testing.T) {
	s, _ := newTestStore()
	mint, proxy := mintHandler(s), proxyHandler(s)
	tok := mintOver(t, mint)

	rec := postLogin(proxy, tok, "same-origin")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("redeem: %d %v", rec.Code, rec.Header())
	}
	checkNoStore(t, rec.Header())
	c := sessionFrom(t, rec)
	if c.Value == tok || !c.HttpOnly || !c.Secure || c.Path != "/" || c.SameSite != cookieSameSite {
		t.Fatalf("session cookie %+v", c)
	}
	if raw := rec.Header().Get("Set-Cookie"); !strings.Contains(raw, "SameSite=None") {
		t.Errorf("Set-Cookie %q must carry SameSite=None for the cross-site embed", raw)
	}

	// The session passes the forward_auth check.
	req := httptest.NewRequest(http.MethodGet, "/__session", nil)
	req.AddCookie(c)
	auth := httptest.NewRecorder()
	proxy.ServeHTTP(auth, req)
	if auth.Code != http.StatusNoContent {
		t.Fatalf("valid session: %d", auth.Code)
	}

	// Replay of the redeemed token is refused, with no cookie.
	replay := postLogin(proxy, tok, "same-origin")
	if replay.Code != http.StatusForbidden || len(replay.Result().Cookies()) != 0 {
		t.Fatalf("replay: %d %v", replay.Code, replay.Header())
	}
	checkNoStore(t, replay.Header())

	// The same link reloaded by a browser that holds the live session goes
	// on to the app with no new cookie; with a dead session it is refused.
	for _, tc := range []struct {
		cookie string
		want   int
	}{{c.Value, http.StatusSeeOther}, {strings.Repeat("A", 43), http.StatusForbidden}} {
		req := httptest.NewRequest(http.MethodPost, "/__ws_login", strings.NewReader(url.Values{"t": {tok}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: tc.cookie})
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)
		if rec.Code != tc.want || len(rec.Result().Cookies()) != 0 {
			t.Errorf("reload with session %q: %d %v, want %d and no cookie", tc.cookie[:4], rec.Code, rec.Header(), tc.want)
		}
	}
}

func TestHTTPSessionRefusalFallsBackToBasic(t *testing.T) {
	s, _ := newTestStore()
	proxy := proxyHandler(s)
	for _, cookie := range []*http.Cookie{nil, {Name: sessionCookie, Value: strings.Repeat("A", 43)}} {
		req := httptest.NewRequest(http.MethodGet, "/__session", nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != basicRealm {
			t.Fatalf("unknown session: %d %v", rec.Code, rec.Header())
		}
		if c := sessionFrom(t, rec); c.MaxAge >= 0 || c.Value != "" {
			t.Errorf("refusal must clear the cookie: %+v", c)
		}
	}
}

func TestHTTPLoginRefusals(t *testing.T) {
	s, _ := newTestStore()
	mint, proxy := mintHandler(s), proxyHandler(s)

	// Cross-site posts are refused and do not consume the token.
	tok := mintOver(t, mint)
	if rec := postLogin(proxy, tok, "cross-site"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site post: %d", rec.Code)
	}
	if rec := postLogin(proxy, tok, ""); rec.Code != http.StatusSeeOther {
		t.Fatalf("a post without Sec-Fetch-Site (older browser, curl) must redeem: %d", rec.Code)
	}

	// A token in the query string is burned and never redeemed.
	tok = mintOver(t, mint)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/__ws_login?t="+tok, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("query token: %d", rec.Code)
	}
	checkNoStore(t, rec.Header())
	if rec := postLogin(proxy, tok, "same-origin"); rec.Code != http.StatusForbidden {
		t.Fatalf("a token seen in a query must be burned: %d", rec.Code)
	}

	// The daemon listener refuses anything that came through a proxy.
	req := httptest.NewRequest(http.MethodGet, "/__mint", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	rec = httptest.NewRecorder()
	mint.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("proxied mint: %d", rec.Code)
	}
	// Neither listener serves the other's routes.
	for _, tc := range []struct {
		h    http.Handler
		path string
	}{{mint, "/__ws_login"}, {mint, "/__session"}, {proxy, "/__mint"}} {
		rec := httptest.NewRecorder()
		tc.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s on the wrong listener: %d", tc.path, rec.Code)
		}
	}
	// Mint refuses past the cap.
	for i := 0; i < maxPending; i++ {
		_, _ = s.mint()
	}
	rec = httptest.NewRecorder()
	mint.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/__mint", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("mint past the cap: %d", rec.Code)
	}
}

func TestHTTPBootstrapPage(t *testing.T) {
	s, _ := newTestStore()
	rec := httptest.NewRecorder()
	proxyHandler(s).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/__ws_login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap page: %d", rec.Code)
	}
	checkNoStore(t, rec.Header())
	body := rec.Body.String()
	for _, want := range []string{
		`location.hash`,              // the token comes from the fragment
		`history.replaceState`,       // and is dropped from the address bar
		`method="post"`,              // and travels in a POST body
		`action="/__ws_login"`,       // to this origin
		`content="no-referrer"`,      // belt and braces with the header
		"<script>" + bootstrapScript, // the script the CSP hash covers
	} {
		if !strings.Contains(body, want) {
			t.Errorf("bootstrap page missing %q", want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "form-action 'self'") || !strings.Contains(csp, "'sha256-") {
		t.Errorf("CSP %q", csp)
	}
	if rec := postLogin(proxyHandler(s), "", "same-origin"); rec.Code != http.StatusForbidden {
		t.Errorf("empty post: %d", rec.Code)
	}
}

// The redemption reads at most 1 KiB of form body.
func TestHTTPLoginBodyLimit(t *testing.T) {
	s, _ := newTestStore()
	tok, _ := s.mint()
	body := url.Values{"pad": {strings.Repeat("x", 2048)}, "t": {tok}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/__ws_login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	proxyHandler(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("oversized body: %d, want 403", rec.Code)
	}
}
