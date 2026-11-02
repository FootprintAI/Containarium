package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// maxLabelBody caps the request body the guard reads to inspect label keys.
const maxLabelBody = 1 << 20

// guardLabelRoute authenticates a /v1/containers/{username}/labels request with
// the standard HTTP auth middleware, then requires the caller to own the
// {username} tenant (or be admin) and, for scoped tokens, to hold requiredScope.
// Unscoped tokens keep the same behaviour as RequireScope in non-strict mode.
func guardLabelRoute(authMW func(http.Handler) http.Handler, requiredScope string, next http.Handler) http.Handler {
	return authMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, _ := auth.UsernameFromContext(r.Context())
		roles, _ := r.Context().Value(auth.ContextKeyRoles).([]string)
		if err := authorizeTenantWSAccess(&auth.Claims{Username: username, Roles: roles}, labelRouteUsername(r.URL.Path)); err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "forbidden: %s", "code": 403}`, err.Error()), http.StatusForbidden)
			return
		}
		scopes, scoped := r.Context().Value(auth.ContextKeyScopes).([]string)
		// Same decision as RequireScope: an unscoped token is refused when
		// strict-scopes mode is on, otherwise it is unrestricted.
		if !scoped && auth.StrictScopesEnabled() {
			http.Error(w, `{"error": "forbidden: scope required: `+requiredScope+`", "code": 403}`, http.StatusForbidden)
			return
		}
		if scoped && !auth.HasScope(scopes, requiredScope) {
			http.Error(w, `{"error": "forbidden: scope required: `+requiredScope+`", "code": 403}`, http.StatusForbidden)
			return
		}
		// Labels feed tenant resolution (cloud_org_id): only an admin may write
		// or remove that key, even on a box they own.
		if !auth.HasRole(roles, auth.RoleAdmin) {
			keys, err := labelKeysTouched(r)
			if err != nil {
				http.Error(w, `{"error": "invalid request body", "code": 400}`, http.StatusBadRequest)
				return
			}
			for _, k := range keys {
				if k == incus.CloudOrgIDLabel {
					http.Error(w, `{"error": "forbidden: label `+k+` requires administrator authority", "code": 403}`, http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	}))
}

// labelKeysTouched returns the label keys a write request names: the keys of
// the JSON body for PUT/POST, the path key for DELETE, none for reads. The body
// is restored so the handler can still read it.
func labelKeysTouched(r *http.Request) ([]string, error) {
	switch r.Method {
	case http.MethodDelete:
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/containers/"), "/"), "/")
		if len(parts) >= 3 && parts[1] == "labels" {
			return []string{parts[2]}, nil
		}
		return nil, nil
	case http.MethodPut, http.MethodPost:
		if r.Body == nil {
			return nil, nil
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, maxLabelBody+1))
		_ = r.Body.Close()
		if err != nil || len(b) > maxLabelBody {
			return nil, fmt.Errorf("label body unreadable or too large")
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		var req SetLabelsRequest
		if err := json.Unmarshal(b, &req); err != nil {
			// Let the handler produce its own 400 for malformed JSON.
			return nil, nil
		}
		keys := make([]string, 0, len(req.Labels))
		for k := range req.Labels {
			keys = append(keys, k)
		}
		return keys, nil
	}
	return nil, nil
}

// isLabelRoute reports whether path is /v1/containers/{username}/labels or a
// sub-path of it. It matches the path segment exactly, so a container or
// tenant that merely contains "labels" in its name is not captured.
func isLabelRoute(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) >= 4 && parts[0] == "v1" && parts[1] == "containers" && parts[3] == "labels"
}

// labelRouteUsername extracts {username} from /v1/containers/{username}/labels...
func labelRouteUsername(path string) string {
	rest := strings.TrimPrefix(path, "/v1/containers/")
	if i := strings.Index(rest, "/"); i >= 0 {
		return rest[:i]
	}
	return rest
}
