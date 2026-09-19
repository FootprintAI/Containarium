package gitlab

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/tracker"
)

// gitlabFixtureServer wires /api/v4/personal_access_tokens/self and
// /api/v4/user handlers, since DescribeCredential always calls the
// first and best-effort calls the second.
func gitlabFixtureServer(t *testing.T, selfBody string, selfStatus int, userBody string, userStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/personal_access_tokens/self":
			w.WriteHeader(selfStatus)
			_, _ = w.Write([]byte(selfBody))
		case "/api/v4/user":
			w.WriteHeader(userStatus)
			_, _ = w.Write([]byte(userBody))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
}

func TestDescribeCredential_PersonalToken_BroadBreadth(t *testing.T) {
	srv := gitlabFixtureServer(t,
		`{"active":true,"revoked":false,"scopes":["api","read_repository"],"expires_at":"2027-06-15"}`, http.StatusOK,
		`{"username":"alice","bot":false}`, http.StatusOK,
	)
	defer srv.Close()

	a := New(nil)
	info, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "glpat-personal",
	})
	if err != nil {
		t.Fatalf("DescribeCredential: %v", err)
	}
	if len(info.Scopes) != 2 || info.Scopes[0] != "api" || info.Scopes[1] != "read_repository" {
		t.Errorf("Scopes = %v, want [api read_repository]", info.Scopes)
	}
	want := time.Date(2027, 6, 15, 0, 0, 0, 0, time.UTC)
	if !info.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", info.ExpiresAt, want)
	}
	if info.Breadth != tracker.BreadthBroad {
		t.Errorf("Breadth = %v, want BreadthBroad (personal account)", info.Breadth)
	}
}

func TestDescribeCredential_ProjectAccessToken_PreferredBreadth(t *testing.T) {
	srv := gitlabFixtureServer(t,
		`{"active":true,"revoked":false,"scopes":["read_api"],"expires_at":"2027-01-01"}`, http.StatusOK,
		`{"username":"project_123_bot_abc123","bot":true}`, http.StatusOK,
	)
	defer srv.Close()

	a := New(nil)
	info, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "glpat-project",
	})
	if err != nil {
		t.Fatalf("DescribeCredential: %v", err)
	}
	if info.Breadth != tracker.BreadthPreferred {
		t.Errorf("Breadth = %v, want BreadthPreferred (project access token)", info.Breadth)
	}
}

func TestDescribeCredential_GroupAccessToken_BroadBreadth(t *testing.T) {
	srv := gitlabFixtureServer(t,
		`{"active":true,"revoked":false,"scopes":["api"],"expires_at":"2027-01-01"}`, http.StatusOK,
		`{"username":"group_456_bot_xyz789","bot":true}`, http.StatusOK,
	)
	defer srv.Close()

	a := New(nil)
	info, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "glpat-group",
	})
	if err != nil {
		t.Fatalf("DescribeCredential: %v", err)
	}
	if info.Breadth != tracker.BreadthBroad {
		t.Errorf("Breadth = %v, want BreadthBroad (group access token is wider than project)", info.Breadth)
	}
}

func TestDescribeCredential_RevokedToken_ReturnsErrCredentialInvalid(t *testing.T) {
	srv := gitlabFixtureServer(t,
		`{"active":true,"revoked":true,"scopes":["api"]}`, http.StatusOK,
		``, http.StatusOK,
	)
	defer srv.Close()

	a := New(nil)
	_, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "glpat-revoked",
	})
	if !errors.Is(err, tracker.ErrCredentialInvalid) {
		t.Fatalf("err = %v, want ErrCredentialInvalid", err)
	}
}

func TestDescribeCredential_InactiveToken_ReturnsErrCredentialInvalid(t *testing.T) {
	srv := gitlabFixtureServer(t,
		`{"active":false,"revoked":false,"scopes":["api"]}`, http.StatusOK,
		``, http.StatusOK,
	)
	defer srv.Close()

	a := New(nil)
	_, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "glpat-inactive",
	})
	if !errors.Is(err, tracker.ErrCredentialInvalid) {
		t.Fatalf("err = %v, want ErrCredentialInvalid", err)
	}
}

func TestDescribeCredential_Unauthorized_ReturnsErrCredentialInvalid(t *testing.T) {
	srv := gitlabFixtureServer(t,
		`{"message":"401 Unauthorized"}`, http.StatusUnauthorized,
		``, http.StatusOK,
	)
	defer srv.Close()

	a := New(nil)
	_, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "glpat-bad",
	})
	if !errors.Is(err, tracker.ErrCredentialInvalid) {
		t.Fatalf("err = %v, want ErrCredentialInvalid", err)
	}
}

func TestDescribeCredential_UserCallFails_StillSucceedsWithUnspecifiedBreadth(t *testing.T) {
	srv := gitlabFixtureServer(t,
		`{"active":true,"revoked":false,"scopes":["read_api"],"expires_at":"2027-01-01"}`, http.StatusOK,
		`{"message":"insufficient scope"}`, http.StatusForbidden,
	)
	defer srv.Close()

	a := New(nil)
	info, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "glpat-narrowscope",
	})
	if err != nil {
		t.Fatalf("DescribeCredential should succeed even if the breadth probe fails: %v", err)
	}
	if info.Breadth != tracker.BreadthUnspecified {
		t.Errorf("Breadth = %v, want BreadthUnspecified", info.Breadth)
	}
	if len(info.Scopes) != 1 || info.Scopes[0] != "read_api" {
		t.Errorf("Scopes = %v, want [read_api] (should not be discarded by the failed breadth probe)", info.Scopes)
	}
}

func TestDescribeCredential_NoExpiry_LeavesExpiresAtZero(t *testing.T) {
	srv := gitlabFixtureServer(t,
		`{"active":true,"revoked":false,"scopes":["api"],"expires_at":null}`, http.StatusOK,
		`{"username":"alice","bot":false}`, http.StatusOK,
	)
	defer srv.Close()

	a := New(nil)
	info, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "glpat-noexpiry",
	})
	if err != nil {
		t.Fatalf("DescribeCredential: %v", err)
	}
	if !info.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero", info.ExpiresAt)
	}
}

func TestDescribeCredential_Unreachable_ReturnsErrUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	a := New(nil)
	_, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    url,
		Credential: "glpat-sometoken",
	})
	if !errors.Is(err, tracker.ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

func TestDescribeCredential_BaseURLGetsAPIv4Suffix(t *testing.T) {
	var gotPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"active":true,"revoked":false,"scopes":["api"],"username":"alice","bot":false}`))
	}))
	defer srv.Close()

	a := New(nil)
	// BaseURL given WITHOUT /api/v4, as a self-managed instance's site
	// root would be — the adapter must append it, matching how
	// gitlab.com's default (also site-root-shaped) is handled. Checks
	// BOTH calls DescribeCredential makes (self, then the breadth
	// probe's /user), not just the first.
	if _, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "glpat-selfmanaged",
	}); err != nil {
		t.Fatalf("DescribeCredential: %v", err)
	}
	want := []string{"/api/v4/personal_access_tokens/self", "/api/v4/user"}
	if len(gotPaths) != len(want) {
		t.Fatalf("paths hit = %v, want %v", gotPaths, want)
	}
	for i, p := range want {
		if gotPaths[i] != p {
			t.Errorf("call %d path = %q, want %q", i, gotPaths[i], p)
		}
	}
}
