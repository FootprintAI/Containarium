package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// registerCookieSession wires POST/DELETE /v1/auth/session.
//
// Why this exists: the webui authenticates API calls with a JWT in
// localStorage, sent as `Authorization: Bearer <jwt>`. That works for
// fetch() / XHR. It does NOT work for browser-issued requests like
// <iframe src=...>, top-level navigations, or <img>/<link> — the
// browser cannot attach a header from JS to those, so any same-origin
// embed (notably the /grafana/ reverse proxy on the monitoring page)
// hits the auth middleware bare and returns 401. See issue #338.
//
// POST /v1/auth/session promotes the bearer token into a cookie that
// the browser DOES attach to those requests. The auth middleware reads
// either, with the header winning when both are present. The cookie's
// value is the raw JWT, so revocation, expiry, and the Phase 1.6
// refresh-token rejection all work identically — no new credential
// material is minted by this endpoint.
//
// DELETE /v1/auth/session clears the cookie. Called on logout / when
// the webui drops the server entry.
func registerCookieSession(mux *http.ServeMux, authMW *auth.AuthMiddleware) {
	mux.HandleFunc("/v1/auth/session", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handleSessionCookieSet(w, r, authMW)
		case http.MethodDelete:
			handleSessionCookieClear(w, r)
		default:
			w.Header().Set("Allow", "POST, DELETE")
			http.Error(w, `{"error": "method not allowed", "code": 405}`, http.StatusMethodNotAllowed)
		}
	})
}

func handleSessionCookieSet(w http.ResponseWriter, r *http.Request, authMW *auth.AuthMiddleware) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, `{"error": "missing authorization header", "code": 401}`, http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := authMW.ValidateToken(token)
	if err != nil {
		http.Error(w, `{"error": "invalid token", "code": 401}`, http.StatusUnauthorized)
		return
	}

	// Cookie lifetime tracks the JWT's own expiry — never longer.
	// If exp is in the past or missing, we'd have failed ValidateToken
	// already, so this is just translating the time math.
	maxAge := 0
	if claims.ExpiresAt != nil {
		if remaining := time.Until(claims.ExpiresAt.Time); remaining > 0 {
			maxAge = int(remaining.Seconds())
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"expiresAt": claims.ExpiresAt.Time.Unix(),
	})
}

func handleSessionCookieClear(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok": true}`))
}

// requestIsHTTPS reports whether the originating browser connection
// is HTTPS, accounting for the typical deploy where Caddy terminates
// TLS and forwards plain HTTP to the daemon. Without this the cookie
// would be set Secure=false in production behind Caddy, which is
// strictly worse than what Caddy already delivers on the outer leg.
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}
