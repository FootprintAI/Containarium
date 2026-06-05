package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/releases"
	"github.com/footprintai/containarium/pkg/version"
)

// registerVersionEndpoints wires the version-visibility endpoints (#354):
//
//   - GET /v1/releases/latest — this daemon's running version alongside the
//     latest published GitHub release and a "behind" flag, so the webui /
//     `containarium version --check` can show drift in one call. The GitHub
//     lookup is cached (rc) so page loads don't burn the unauthenticated
//     rate limit.
//
// Per-backend versions come from the existing /v1/backends; the sentinel's
// version comes from its own /sentinel/version (internal/sentinel).
//
// Bearer-auth gated like the other /v1 introspection endpoints — the webui
// already sends the session token.
func registerVersionEndpoints(mux *http.ServeMux, rc *releases.Client, authMW *auth.AuthMiddleware) {
	mux.HandleFunc("/v1/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		if !requireBearer(w, r, authMW) {
			return
		}
		rel, cached, err := rc.Latest(r.Context())
		if err != nil {
			http.Error(w, `{"error":"failed to fetch latest release","code":502}`, http.StatusBadGateway)
			return
		}
		cur := version.GetVersion()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(latestReleaseResponse{
			Current:     cur,
			Latest:      rel.TagName,
			Name:        rel.Name,
			HTMLURL:     rel.HTMLURL,
			PublishedAt: rel.PublishedAt.UTC().Format(time.RFC3339),
			Behind:      releases.IsBehind(cur, rel.TagName),
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
			Cached:      cached,
		})
	})
}

// latestReleaseResponse is the JSON for GET /v1/releases/latest. camelCase
// to match the webui's other endpoints (audit, etc.).
type latestReleaseResponse struct {
	Current     string `json:"current"`     // this daemon's running version
	Latest      string `json:"latest"`      // latest published GitHub tag
	Name        string `json:"name"`        // release title
	HTMLURL     string `json:"htmlUrl"`     // release page
	PublishedAt string `json:"publishedAt"` // RFC3339
	Behind      bool   `json:"behind"`      // current < latest
	CheckedAt   string `json:"checkedAt"`   // when the daemon answered
	Cached      bool   `json:"cached"`      // served from the daemon's 1h cache
}

// requireBearer enforces a valid Bearer token, writing a 401 and returning
// false when absent/invalid. Mirrors the audit / security-export endpoints
// (Authorization header only — never a ?token= query param, which leaks
// into proxy logs).
func requireBearer(w http.ResponseWriter, r *http.Request, authMW *auth.AuthMiddleware) bool {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, `{"error":"unauthorized: Bearer token required in Authorization header","code":401}`, http.StatusUnauthorized)
		return false
	}
	if _, err := authMW.ValidateToken(strings.TrimPrefix(authHeader, "Bearer ")); err != nil {
		http.Error(w, `{"error":"unauthorized: invalid token","code":401}`, http.StatusUnauthorized)
		return false
	}
	return true
}
