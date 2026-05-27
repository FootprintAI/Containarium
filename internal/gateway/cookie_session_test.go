package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// TestCookieSession_SetClear verifies the POST/DELETE
// /v1/auth/session endpoint contract for issue #338:
//   - POST with valid bearer mints a cookie carrying that JWT
//   - The cookie is HttpOnly + SameSite=Lax
//   - The cookie's Max-Age tracks the JWT's remaining lifetime
//   - DELETE clears the cookie (Max-Age=-1)
//   - Missing / junk bearer returns 401 and sets no cookie
//   - Wrong method returns 405 with an Allow header
func TestCookieSession_SetClear(t *testing.T) {
	tm, err := auth.NewTokenManager("test-secret-key-for-cookie-session-handler", "test-issuer")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	mw := auth.NewAuthMiddleware(tm)

	mux := http.NewServeMux()
	registerCookieSession(mux, mw)

	t.Run("POST without bearer → 401, no cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/session", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if c := rec.Result().Cookies(); len(c) != 0 {
			t.Errorf("expected no cookies, got %v", c)
		}
	})

	t.Run("POST with junk bearer → 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/session", nil)
		req.Header.Set("Authorization", "Bearer not.a.real.jwt")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("POST with valid bearer → 200, HttpOnly cookie minted", func(t *testing.T) {
		token, err := tm.GenerateAccessToken("test-user", []string{"admin"}, 10*time.Minute)
		if err != nil {
			t.Fatalf("GenerateAccessToken: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/session", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		cookies := rec.Result().Cookies()
		var c *http.Cookie
		for _, ck := range cookies {
			if ck.Name == auth.SessionCookieName {
				c = ck
				break
			}
		}
		if c == nil {
			t.Fatalf("expected %q cookie to be set, got %v", auth.SessionCookieName, cookies)
		}
		if c.Value != token {
			t.Errorf("cookie value mismatch: cookie is not the bearer JWT")
		}
		if !c.HttpOnly {
			t.Errorf("cookie must be HttpOnly to defend against XSS reading the JWT")
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie SameSite = %v, want Lax (needed for iframe same-origin embeds)", c.SameSite)
		}
		if c.Path != "/" {
			t.Errorf("cookie Path = %q, want /", c.Path)
		}
		// Cookie lifetime must not exceed the JWT's remaining lifetime.
		// Generated 10m token → cookie Max-Age should be ≤600 and > 0.
		if c.MaxAge <= 0 || c.MaxAge > 600 {
			t.Errorf("cookie Max-Age = %d, want (0, 600]", c.MaxAge)
		}
	})

	t.Run("POST behind TLS terminator → Secure cookie", func(t *testing.T) {
		token, err := tm.GenerateAccessToken("test-user", []string{"admin"}, 10*time.Minute)
		if err != nil {
			t.Fatalf("GenerateAccessToken: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/session", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		// Simulates the production deploy: Caddy terminates TLS and
		// forwards plain HTTP to the daemon, setting this header. The
		// cookie must come back Secure=true so the browser refuses to
		// send it back over a hypothetical HTTP downgrade.
		req.Header.Set("X-Forwarded-Proto", "https")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		c := findCookie(rec.Result().Cookies(), auth.SessionCookieName)
		if c == nil {
			t.Fatalf("cookie not set")
		}
		if !c.Secure {
			t.Errorf("X-Forwarded-Proto=https should set Secure on the cookie")
		}
	})

	t.Run("DELETE clears the cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/v1/auth/session", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		c := findCookie(rec.Result().Cookies(), auth.SessionCookieName)
		if c == nil {
			t.Fatalf("DELETE must emit a clearing Set-Cookie")
		}
		if c.MaxAge >= 0 {
			t.Errorf("DELETE cookie Max-Age = %d, want < 0 (so browser drops it)", c.MaxAge)
		}
		if c.Value != "" {
			t.Errorf("DELETE cookie value = %q, want empty", c.Value)
		}
	})

	t.Run("GET → 405 with Allow header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/session", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
		allow := rec.Header().Get("Allow")
		if !strings.Contains(allow, "POST") || !strings.Contains(allow, "DELETE") {
			t.Errorf("Allow header = %q, want both POST and DELETE", allow)
		}
	})
}

func findCookie(cs []*http.Cookie, name string) *http.Cookie {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return nil
}
