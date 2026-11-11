package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCaddyfileProxy runs the image's real Caddyfile with a real caddy binary
// in front of this helper and a stand-in dev server, on the ports the image
// uses. It is the proxy-level proof of #3486: a redeemed token is refused on
// replay, the token never reaches a request line the dev server or the proxy
// sees, every path stays behind the cookie or basic auth, and websockets pass
// on the cookie path. Skipped when caddy is not on PATH, unless
// WSAUTH_REQUIRE_CADDY=1 (the slides-agent image workflow sets it and runs
// this with the image's own caddy).
func TestCaddyfileProxy(t *testing.T) {
	caddy, err := exec.LookPath("caddy")
	if err != nil {
		if os.Getenv("WSAUTH_REQUIRE_CADDY") == "1" {
			t.Fatal("WSAUTH_REQUIRE_CADDY=1 but caddy is not on PATH")
		}
		t.Skip("caddy not on PATH")
	}
	// The proxy's own port is the one thing rewritten (to a free port, so a
	// host already using 8080 can still run this); the rest of the
	// Caddyfile is the image's, byte for byte.
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyHost := pl.Addr().String()
	_ = pl.Close()
	src, err := os.ReadFile("../Caddyfile")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(src), "\n:8080 {\n") != 1 {
		t.Fatal("the Caddyfile must have exactly one :8080 site")
	}
	caddyfile := filepath.Join(t.TempDir(), "Caddyfile")
	_, port, _ := net.SplitHostPort(proxyHost)
	if err := os.WriteFile(caddyfile, []byte(strings.Replace(string(src), "\n:8080 {\n", "\n:"+port+" {\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"127.0.0.1:5173", mintAddr, proxyAddr} {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			if os.Getenv("WSAUTH_REQUIRE_CADDY") == "1" {
				t.Fatalf("%s busy: %v", addr, err)
			}
			t.Skipf("%s busy: %v", addr, err)
		}
		_ = l.Close()
	}

	// The helper, on its real listeners.
	s := newStore(time.Now)
	serve(t, mintAddr, mintHandler(s))
	serve(t, proxyAddr, proxyHandler(s))

	// The stand-in dev server records every request line it is sent and
	// answers websocket upgrades with 101.
	var mu sync.Mutex
	var seen, cookies []string
	serve(t, "127.0.0.1:5173", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI()+" proto="+r.Header.Get("X-Forwarded-Proto"))
		cookies = append(cookies, r.Header.Values("Cookie")...)
		mu.Unlock()
		if r.Header.Get("Upgrade") == "websocket" {
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nhello")
			_ = rw.Flush()
			_ = conn.Close()
			return
		}
		if r.Method == http.MethodPost {
			_, _ = io.Copy(w, r.Body) // echo: the body must survive the forward_auth check
			return
		}
		_, _ = io.WriteString(w, "dev server")
	}))

	hash, err := exec.Command(caddy, "hash-password", "--plaintext", "deck-pass").Output() //nolint:gosec // test binary
	if err != nil {
		t.Fatalf("hash-password: %v", err)
	}
	var caddyLog lockedBuffer
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, caddy, "run", "--config", caddyfile, "--adapter", "caddyfile") //nolint:gosec // test binary
	cmd.Env = append(os.Environ(), "SLIDES_AUTH_USER=deck", "SLIDES_AUTH_HASH="+strings.TrimSpace(string(hash)), "HOME="+t.TempDir())
	cmd.Stdout, cmd.Stderr = &caddyLog, &caddyLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })

	base := "http://" + proxyHost
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, path string, body io.Reader, hdr map[string]string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, base+path, body)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if resp, err := client.Get(base + "/"); err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("caddy did not come up:\n%s", caddyLog.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	mint := func() string {
		t.Helper()
		resp, err := http.Get("http://" + mintAddr + "/__mint")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var m mintResponse
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			t.Fatal(err)
		}
		return m.Token
	}
	form := func(tok string) (io.Reader, map[string]string) {
		return strings.NewReader(url.Values{"t": {tok}}.Encode()),
			map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"}
	}

	// Unauthenticated: every path is refused, the helper's own routes included.
	for _, p := range []string{"/", "/s/deck", "/__session", "/__mint", "/__ws_login/", "/__agent"} {
		if resp := do(http.MethodGet, p, nil, nil); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without credentials: %d, want 401", p, resp.StatusCode)
		}
	}

	// The bootstrap page is served without credentials, no-store, no-referrer.
	if resp := do(http.MethodGet, "/__ws_login", nil, nil); resp.StatusCode != http.StatusOK ||
		resp.Header.Get("Referrer-Policy") != "no-referrer" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("bootstrap page: %d %v", resp.StatusCode, resp.Header)
	}

	// Redeem once: a session cookie distinct from the token.
	tok := mint()
	body, hdr := form(tok)
	resp := do(http.MethodPost, "/__ws_login", body, hdr)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("redeem: %d", resp.StatusCode)
	}
	var sess *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil || sess.Value == tok || !sess.HttpOnly || !sess.Secure {
		t.Fatalf("session cookie %+v", sess)
	}
	// Replay is refused.
	body, hdr = form(tok)
	if resp := do(http.MethodPost, "/__ws_login", body, hdr); resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
		t.Errorf("replay: %d %v", resp.StatusCode, resp.Header)
	}
	// The login token is not a cookie.
	if resp := do(http.MethodGet, "/", nil, map[string]string{"Cookie": sessionCookie + "=" + tok}); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("login token as cookie: %d, want 401", resp.StatusCode)
	}

	cookie := map[string]string{"Cookie": "other=1; " + sessionCookie + "=" + sess.Value}
	if resp := do(http.MethodGet, "/s/deck", nil, cookie); resp.StatusCode != http.StatusOK {
		t.Errorf("session cookie: %d, want 200", resp.StatusCode)
	}
	// A request body reaches the dev server intact on the cookie path.
	req, _ := http.NewRequest(http.MethodPost, base+"/api/save", strings.NewReader("deck-body"))
	req.Header.Set("Cookie", cookie["Cookie"])
	if resp, err := client.Do(req); err != nil {
		t.Errorf("POST on the cookie path: %v", err)
	} else {
		echoed, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(echoed) != "deck-body" {
			t.Errorf("POST on the cookie path: %d %q, want 200 echoing the body", resp.StatusCode, echoed)
		}
	}
	// A cookie of the right shape the helper does not know: 401 with the
	// basic-auth challenge and the cookie cleared.
	resp = do(http.MethodGet, "/", nil, map[string]string{"Cookie": sessionCookie + "=" + strings.Repeat("A", 43)})
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") == "" ||
		!strings.Contains(resp.Header.Get("Set-Cookie"), sessionCookie+"=;") {
		t.Errorf("unknown session: %d %v", resp.StatusCode, resp.Header)
	}
	// Duplicate session cookies (one planted, one real): accepted in either
	// order, and the real one is not cleared.
	bogus := sessionCookie + "=" + strings.Repeat("B", 43)
	real := sessionCookie + "=" + sess.Value
	for _, hdr := range []string{bogus + "; " + real, real + "; " + bogus} {
		if resp := do(http.MethodGet, "/", nil, map[string]string{"Cookie": hdr}); resp.StatusCode != http.StatusOK || resp.Header.Get("Set-Cookie") != "" {
			t.Errorf("duplicates %q: %d %v, want 200 and no Set-Cookie", hdr, resp.StatusCode, resp.Header)
		}
	}
	if resp := do(http.MethodGet, "/", nil, map[string]string{"Cookie": bogus + "; " + sessionCookie + "=" + strings.Repeat("C", 43)}); resp.StatusCode != http.StatusUnauthorized ||
		!strings.Contains(resp.Header.Get("Set-Cookie"), sessionCookie+"=;") {
		t.Errorf("no valid duplicate: %d %v, want 401 and the cookie cleared", resp.StatusCode, resp.Header)
	}
	// The name without the __Host- prefix is not a session cookie.
	if resp := do(http.MethodGet, "/", nil, map[string]string{"Cookie": "ws_session=" + sess.Value}); resp.StatusCode != http.StatusUnauthorized ||
		resp.Header.Get("Set-Cookie") != "" {
		t.Errorf("plain ws_session: %d %v, want basic auth's 401", resp.StatusCode, resp.Header)
	}

	// A cookie name that only ends in ws_session does not take the cookie
	// path: basic auth's 401, not the helper's (which clears the cookie).
	if resp := do(http.MethodGet, "/", nil, map[string]string{"Cookie": "x" + sessionCookie + "=" + sess.Value}); resp.StatusCode != http.StatusUnauthorized ||
		resp.Header.Get("Set-Cookie") != "" {
		t.Errorf("suffix cookie name: %d %v, want basic auth's 401", resp.StatusCode, resp.Header)
	}

	// Basic auth, unchanged, with or without a cookie.
	basic := map[string]string{"Authorization": "Basic ZGVjazpkZWNrLXBhc3M="} // deck:deck-pass
	if resp := do(http.MethodGet, "/", nil, basic); resp.StatusCode != http.StatusOK {
		t.Errorf("basic auth: %d, want 200", resp.StatusCode)
	}
	basic["Cookie"] = "basicapp=1; " + sessionCookie + "=" + strings.Repeat("A", 43)
	if resp := do(http.MethodGet, "/", nil, basic); resp.StatusCode != http.StatusOK {
		t.Errorf("basic auth with a stale cookie: %d, want 200", resp.StatusCode)
	}
	if resp := do(http.MethodGet, "/", nil, map[string]string{"Authorization": "Basic ZGVjazp3cm9uZw=="}); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password: %d, want 401", resp.StatusCode)
	}

	// A token sent in the query is burned.
	tok2 := mint()
	if resp := do(http.MethodGet, "/__ws_login?t="+tok2, nil, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("query token: %d, want 400", resp.StatusCode)
	}
	body, hdr = form(tok2)
	if resp := do(http.MethodPost, "/__ws_login", body, hdr); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a token seen in a query must not redeem: %d", resp.StatusCode)
	}

	// Websocket upgrade on the cookie path reaches the dev server.
	conn, err := net.Dial("tcp", proxyHost)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "GET /@vite/ws HTTP/1.1\r\nHost: "+proxyHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: %s=%s\r\n\r\n", sessionCookie, sess.Value)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	status, _ := bufio.NewReader(conn).ReadString('\n')
	_ = conn.Close()
	if !strings.Contains(status, "101") {
		t.Errorf("websocket on the cookie path: %q, want 101", status)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, line := range seen {
		if !strings.HasSuffix(line, "proto=https") {
			t.Errorf("dev server request without X-Forwarded-Proto https: %q", line)
		}
		if strings.Contains(line, tok) || strings.Contains(line, "__ws_login") {
			t.Errorf("login traffic reached the dev server: %q", line)
		}
	}
	if len(seen) == 0 {
		t.Error("the dev server saw no request")
	}
	// The session cookie never reaches the dev server; the app's own do.
	sawOther := false
	for _, c := range cookies {
		if strings.Contains(c, sessionCookie) {
			t.Errorf("the session cookie reached the dev server: %q", c)
		}
		sawOther = sawOther || strings.Contains(c, "other=1")
	}
	sawBasic := false
	for _, c := range cookies {
		sawBasic = sawBasic || strings.Contains(c, "basicapp=1")
	}
	if !sawOther || !sawBasic {
		t.Errorf("the app's own cookies were stripped too (cookie path %v, basic path %v): %q", sawOther, sawBasic, cookies)
	}
	if strings.Contains(caddyLog.String(), tok) || strings.Contains(caddyLog.String(), sess.Value) {
		t.Errorf("the proxy's log carries a token or session:\n%s", caddyLog.String())
	}
}

// lockedBuffer collects caddy's output, written by exec's copier goroutine.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func serve(t *testing.T, addr string, h http.Handler) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
}
