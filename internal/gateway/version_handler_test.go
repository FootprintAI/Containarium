package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/releases"
	"github.com/footprintai/containarium/pkg/version"
)

// fakeGitHubLatest serves a minimal GitHub "latest release" response.
func fakeGitHubLatest(t *testing.T, tag string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"tag_name":%q,"name":"Release %s","html_url":"https://github.com/x/releases/%s","published_at":"2026-06-01T00:00:00Z"}`, tag, tag, tag)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newVersionMux(t *testing.T, tag string) (*http.ServeMux, string) {
	t.Helper()
	tm, err := auth.NewTokenManager("test-secret-key-for-version-handler-test", "test-issuer")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	tok, err := tm.GenerateToken("alice", []string{"admin"}, 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	gh := fakeGitHubLatest(t, tag)
	rc := releases.NewClient(releases.WithURL(gh.URL))
	mux := http.NewServeMux()
	registerVersionEndpoints(mux, rc, auth.NewAuthMiddleware(tm))
	return mux, tok
}

func TestVersionEndpoint_RequiresAuth(t *testing.T) {
	mux, _ := newVersionMux(t, "v99.0.0")
	req := httptest.NewRequest(http.MethodGet, "/v1/releases/latest", nil) // no Bearer
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth status = %d, want 401", rec.Code)
	}
}

func TestVersionEndpoint_ReportsBehind(t *testing.T) {
	// Latest is far ahead of whatever this build's version is, so behind=true.
	mux, tok := newVersionMux(t, "v99.0.0")
	req := httptest.NewRequest(http.MethodGet, "/v1/releases/latest", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp latestReleaseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Current != version.GetVersion() {
		t.Errorf("current = %q, want %q", resp.Current, version.GetVersion())
	}
	if resp.Latest != "v99.0.0" {
		t.Errorf("latest = %q, want v99.0.0", resp.Latest)
	}
	if !resp.Behind {
		t.Errorf("behind = false, want true (current %s < v99.0.0)", resp.Current)
	}
	if resp.CheckedAt == "" {
		t.Error("checkedAt should be populated")
	}
}

func TestVersionEndpoint_UpToDate(t *testing.T) {
	// Latest equals this build's version → behind=false.
	mux, tok := newVersionMux(t, version.GetVersion())
	req := httptest.NewRequest(http.MethodGet, "/v1/releases/latest", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp latestReleaseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Behind {
		t.Errorf("behind = true, want false when current == latest (%s)", resp.Current)
	}
}
