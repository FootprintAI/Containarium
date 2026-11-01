package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHTTPMiddleware_CookieMutationOrigin is the regression test for #3338:
// a state-changing request authenticated only by the session cookie must come
// from a trusted origin, while bearer-header and read-only requests are
// unaffected.
func TestHTTPMiddleware_CookieMutationOrigin(t *testing.T) {
	tm, _ := NewTokenManager("test-secret-key-for-cookie-csrf-test", "test-issuer")
	mw := NewAuthMiddleware(tm)
	mw.SetCookieMutationOrigins([]string{"https://ui.example.com"})

	token, err := tm.GenerateToken("test-user", []string{"admin"}, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	cookie := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token}) }
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }

	cases := []struct {
		name   string
		method string
		auth   func(*http.Request)
		header map[string]string
		want   int
	}{
		{"cookie POST same-site sibling", http.MethodPost, cookie, map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://evil.example.com"}, http.StatusForbidden},
		{"cookie POST cross-site", http.MethodPost, cookie, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example.com"}, http.StatusForbidden},
		{"cookie POST opaque origin", http.MethodPost, cookie, map[string]string{"Origin": "null"}, http.StatusForbidden},
		{"cookie DELETE no origin headers", http.MethodDelete, cookie, nil, http.StatusForbidden},
		{"cookie POST same-origin", http.MethodPost, cookie, map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusOK},
		{"cookie POST allow-listed origin", http.MethodPost, cookie, map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://ui.example.com"}, http.StatusOK},
		{"cookie POST old browser, Origin host matches Host", http.MethodPost, cookie, map[string]string{"Origin": "http://daemon.test"}, http.StatusOK},
		{"cookie GET cross-site is read-only", http.MethodGet, cookie, map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusOK},
		{"bearer POST cross-site is unaffected", http.MethodPost, bearer, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example.com"}, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(tc.method, "http://daemon.test/v1/secrets", nil)
			tc.auth(req)
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
			if called != (tc.want == http.StatusOK) {
				t.Fatalf("handler called = %v for status %d", called, rec.Code)
			}
		})
	}
}
