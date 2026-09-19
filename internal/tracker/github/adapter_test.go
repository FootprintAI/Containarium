package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
)

func TestDescribeCredential_ClassicPAT_ReportsScopesAndBroadBreadth(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"alice"}`))
	}))
	defer srv.Close()

	a := New(nil)
	info, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "ghp_classictoken",
	})
	if err != nil {
		t.Fatalf("DescribeCredential: %v", err)
	}
	if gotPath != "/user" {
		t.Errorf("path = %q, want /user", gotPath)
	}
	if gotAuth != "token ghp_classictoken" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "token ghp_classictoken")
	}
	if len(info.Scopes) != 2 || info.Scopes[0] != "repo" || info.Scopes[1] != "read:org" {
		t.Errorf("Scopes = %v, want [repo read:org]", info.Scopes)
	}
	if info.Breadth != tracker.BreadthBroad {
		t.Errorf("Breadth = %v, want BreadthBroad", info.Breadth)
	}
	if !info.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero (GitHub never reports PAT expiry via this endpoint)", info.ExpiresAt)
	}
}

func TestDescribeCredential_FineGrainedPAT_ReportsPreferredBreadth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fine-grained PATs don't set X-OAuth-Scopes.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"alice"}`))
	}))
	defer srv.Close()

	a := New(nil)
	info, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "github_pat_finegrained",
	})
	if err != nil {
		t.Fatalf("DescribeCredential: %v", err)
	}
	if info.Breadth != tracker.BreadthPreferred {
		t.Errorf("Breadth = %v, want BreadthPreferred", info.Breadth)
	}
	if info.Scopes != nil {
		t.Errorf("Scopes = %v, want nil", info.Scopes)
	}
}

func TestDescribeCredential_InstallationToken_ProbesRateLimit(t *testing.T) {
	var hitUser, hitRateLimit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			hitUser = true
			w.WriteHeader(http.StatusForbidden)
		case "/rate_limit":
			hitRateLimit = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"rate":{"limit":5000}}`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	a := New(nil)
	info, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "ghs_installationtoken",
	})
	if err != nil {
		t.Fatalf("DescribeCredential: %v", err)
	}
	if hitUser {
		t.Error("adapter called /user for an installation token, want it to skip straight to /rate_limit")
	}
	if !hitRateLimit {
		t.Error("adapter never called /rate_limit for an installation token")
	}
	if info.Breadth != tracker.BreadthPreferred {
		t.Errorf("Breadth = %v, want BreadthPreferred", info.Breadth)
	}
}

func TestDescribeCredential_InvalidCredential_ReturnsErrCredentialInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()

	a := New(nil)
	_, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "ghp_badtoken",
	})
	if !errors.Is(err, tracker.ErrCredentialInvalid) {
		t.Fatalf("err = %v, want ErrCredentialInvalid", err)
	}
}

func TestDescribeCredential_Unreachable_ReturnsErrUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // now nothing listens on this address

	a := New(nil)
	_, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    url,
		Credential: "ghp_sometoken",
	})
	if !errors.Is(err, tracker.ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

func TestDescribeCredential_UnexpectedStatus_ReturnsPlainError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := New(nil)
	_, err := a.DescribeCredential(context.Background(), tracker.Conn{
		BaseURL:    srv.URL,
		Credential: "ghp_sometoken",
	})
	if err == nil {
		t.Fatal("expected an error for HTTP 500")
	}
	if errors.Is(err, tracker.ErrCredentialInvalid) || errors.Is(err, tracker.ErrUnreachable) {
		t.Errorf("err = %v, want a plain (unclassified) error for a 500, not Invalid or Unreachable", err)
	}
}

func TestBreadthFromTokenPrefix(t *testing.T) {
	tests := []struct {
		token string
		want  tracker.CredentialBreadth
	}{
		{"ghp_classic", tracker.BreadthBroad},
		{"github_pat_finegrained", tracker.BreadthPreferred},
		{"ghs_installation", tracker.BreadthPreferred},
		{"gho_oauth", tracker.BreadthBroad},
		{"ghu_oauth", tracker.BreadthBroad},
		{"some-unrecognized-shape", tracker.BreadthBroad},
	}
	for _, tc := range tests {
		if got := breadthFromTokenPrefix(tc.token); got != tc.want {
			t.Errorf("breadthFromTokenPrefix(%q) = %v, want %v", tc.token, got, tc.want)
		}
	}
}

func TestSplitScopes(t *testing.T) {
	tests := []struct {
		header string
		want   int
	}{
		{"", 0},
		{"   ", 0},
		{"repo", 1},
		{"repo, read:org", 2},
		{"repo,read:org,gist", 3},
	}
	for _, tc := range tests {
		got := splitScopes(tc.header)
		if len(got) != tc.want {
			t.Errorf("splitScopes(%q) = %v, want %d scopes", tc.header, got, tc.want)
		}
	}
	if got := splitScopes(""); got != nil {
		t.Errorf("splitScopes(\"\") = %v, want nil", got)
	}
}
