package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

func labelGuardFixture(t *testing.T) (*auth.TokenManager, http.Handler, *bool) {
	t.Helper()
	tm, err := auth.NewTokenManager("label-guard-test-secret-at-least-32-bytes", "test")
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	h := guardLabelRoute(auth.NewAuthMiddleware(tm).HTTPMiddleware, auth.ScopeContainersWrite,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	return tm, h, &reached
}

func mkRefresh(t *testing.T, tm *auth.TokenManager, user string) string {
	t.Helper()
	tok, err := tm.GenerateRefreshToken(user, []string{"user"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func labelReq(tok string) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/v1/containers/bob/labels", nil)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	return r
}

func TestGuardLabelRoute(t *testing.T) {
	tm, h, reached := labelGuardFixture(t)
	mk := func(user string, roles []string, scopes ...string) string {
		tok, err := tm.GenerateAccessToken(user, roles, time.Hour, scopes...)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	cases := []struct {
		name string
		tok  string
		want int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"other tenant", mk("alice", []string{"user"}), http.StatusForbidden},
		{"owner wrong scope", mk("bob", []string{"user"}, auth.ScopeContainersRead), http.StatusForbidden},
		{"owner unscoped", mk("bob", []string{"user"}), http.StatusOK},
		{"owner right scope", mk("bob", []string{"user"}, auth.ScopeContainersWrite), http.StatusOK},
		{"admin", mk("ops", []string{auth.RoleAdmin}), http.StatusOK},
		{"admin wrong scope", mk("ops", []string{auth.RoleAdmin}, auth.ScopeContainersRead), http.StatusForbidden},
		{"refresh token", mkRefresh(t, tm, "bob"), http.StatusUnauthorized},
	}
	for _, c := range cases {
		*reached = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, labelReq(c.tok))
		if c.want == http.StatusOK && !*reached || c.want != http.StatusOK && (*reached || rec.Code != c.want) {
			t.Errorf("%s: code=%d reached=%v want %d", c.name, rec.Code, *reached, c.want)
		}
	}
}

func TestGuardLabelRoute_StrictScopes(t *testing.T) {
	tm, h, reached := labelGuardFixture(t)
	tok, err := tm.GenerateAccessToken("bob", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	auth.SetStrictScopes(true)
	t.Cleanup(func() { auth.SetStrictScopes(false) })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, labelReq(tok))
	if *reached || rec.Code != http.StatusForbidden {
		t.Fatalf("strict mode, unscoped token: code=%d reached=%v want 403", rec.Code, *reached)
	}
}

func TestIsLabelRoute(t *testing.T) {
	for path, want := range map[string]bool{
		"/v1/containers/bob/labels":       true,
		"/v1/containers/bob/labels/":      true,
		"/v1/containers/bob/labels/k":     true,
		"/v1/containers/labels":           false,
		"/v1/containers/bob":              false,
		"/v1/containers/bob/terminal":     false,
		"/v1/containers/bob/x/labels":     false,
		"/v1/containers/bob/labels-extra": false,
	} {
		if got := isLabelRoute(path); got != want {
			t.Errorf("isLabelRoute(%q)=%v want %v", path, got, want)
		}
	}
}

func TestGuardLabelRoute_CloudOrgIDIsAdminOnly(t *testing.T) {
	tm, h, reached := labelGuardFixture(t)
	mk := func(user string, roles []string) string {
		tok, err := tm.GenerateAccessToken(user, roles, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	do := func(method, path, body, tok string) int {
		*reached = false
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	owner, admin := mk("bob", []string{"user"}), mk("ops", []string{auth.RoleAdmin})
	cases := []struct {
		name, method, path, body, tok string
		wantReached                   bool
	}{
		{"owner sets cloud_org_id", "PUT", "/v1/containers/bob/labels", `{"labels":{"cloud_org_id":"x"}}`, owner, false},
		{"owner sets it among others", "POST", "/v1/containers/bob/labels", `{"labels":{"a":"1","cloud_org_id":"x"}}`, owner, false},
		{"owner removes cloud_org_id", "DELETE", "/v1/containers/bob/labels/cloud_org_id", "", owner, false},
		{"owner sets an ordinary label", "PUT", "/v1/containers/bob/labels", `{"labels":{"team":"x"}}`, owner, true},
		{"owner removes an ordinary label", "DELETE", "/v1/containers/bob/labels/team", "", owner, true},
		{"admin sets cloud_org_id", "PUT", "/v1/containers/bob/labels", `{"labels":{"cloud_org_id":"x"}}`, admin, true},
		{"owner reads", "GET", "/v1/containers/bob/labels", "", owner, true},
	}
	for _, c := range cases {
		code := do(c.method, c.path, c.body, c.tok)
		if *reached != c.wantReached || (!c.wantReached && code != http.StatusForbidden) {
			t.Errorf("%s: reached=%v code=%d want reached=%v", c.name, *reached, code, c.wantReached)
		}
	}
}

// The guard reads the body to see the keys; the handler must still get it.
func TestGuardLabelRoute_BodyIsRestoredForTheHandler(t *testing.T) {
	tm, _, _ := labelGuardFixture(t)
	var seen string
	h := guardLabelRoute(auth.NewAuthMiddleware(tm).HTTPMiddleware, auth.ScopeContainersWrite,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); seen = string(b) }))
	tok, _ := tm.GenerateAccessToken("bob", []string{"user"}, time.Hour)
	r := httptest.NewRequest("PUT", "/v1/containers/bob/labels", strings.NewReader(`{"labels":{"team":"x"}}`))
	r.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen != `{"labels":{"team":"x"}}` {
		t.Fatalf("handler saw %q", seen)
	}
}
