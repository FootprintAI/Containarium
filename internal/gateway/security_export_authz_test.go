package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

func TestAuthorizeClamavExport(t *testing.T) {
	user := &auth.Claims{Username: "alice", Roles: []string{"user"}}
	admin := &auth.Claims{Username: "ops", Roles: []string{auth.RoleAdmin}}
	narrow := &auth.Claims{Username: "alice", Roles: []string{"user"}, Scopes: []string{auth.ScopeContainersRead}}
	sec := &auth.Claims{Username: "alice", Roles: []string{"user"}, Scopes: []string{auth.ScopeSecurityRead}}
	cases := []struct {
		name      string
		claims    *auth.Claims
		container string
		want      int
	}{
		{"nil claims", nil, "alice-container", http.StatusUnauthorized},
		{"tenant, no container (all tenants)", user, "", http.StatusForbidden},
		{"tenant, other tenant's container", user, "bob-container", http.StatusForbidden},
		{"tenant, system container", user, "caddy", http.StatusForbidden},
		{"tenant, own container", user, "alice-container", 0},
		{"admin, no container", admin, "", 0},
		{"wrong scope", narrow, "alice-container", http.StatusForbidden},
		{"security:read scope, own container", sec, "alice-container", 0},
	}
	for _, c := range cases {
		if got, _ := authorizeClamavExport(c.claims, c.container); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{"=1+1": "'=1+1", "+x": "'+x", "-x": "'-x", "@x": "'@x", "ok": "ok", "": ""} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAuthorizeClamavExport_StrictScopes(t *testing.T) {
	auth.SetStrictScopes(true)
	t.Cleanup(func() { auth.SetStrictScopes(false) })
	unscoped := &auth.Claims{Username: "alice", Roles: []string{"user"}}
	if got, _ := authorizeClamavExport(unscoped, "alice-container"); got != http.StatusForbidden {
		t.Fatalf("strict mode, unscoped token: got %d want 403", got)
	}
}

func TestAuthorizeClamavExport_AdminWrongScope(t *testing.T) {
	admin := &auth.Claims{Username: "ops", Roles: []string{auth.RoleAdmin}, Scopes: []string{auth.ScopeContainersRead}}
	if got, _ := authorizeClamavExport(admin, ""); got != http.StatusForbidden {
		t.Fatalf("admin with a non-security scope: got %d want 403", got)
	}
}

// The original exploit, against the registered route: a valid non-admin token
// with no container_name must not reach the store (nil here, so reaching it
// would panic) and must get 403.
func TestClamavExportRoute_TenantWithoutContainerIsForbidden(t *testing.T) {
	tm, err := auth.NewTokenManager("clamav-export-test-secret-at-least-32-bytes", "test")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerSecurityExport(mux, nil, auth.NewAuthMiddleware(tm))
	tok, err := tm.GenerateAccessToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"", "&container_name=bob-container", "&container_name=%20bob-container"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/security/clamav-reports/export?from=2020-01-01&to=2030-01-01"+q, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("query %q: got %d want 403", q, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/security/clamav-reports/export?from=a&to=b", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: got %d want 401", rec.Code)
	}
}
