package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #1217: runner registration was repo-scoped only. A repo-scoped runner
// serves exactly one repository, so an org with N repos wanting shared CI
// capacity had to run N separate pools — N times the boxes for the same
// throughput, each idle whenever its own repo is idle.
//
// The target's SHAPE selects the endpoint family, the way GitHub itself
// disambiguates. These pin that selection, which is the part that silently
// hits the wrong API if it drifts.

func TestParseTarget(t *testing.T) {
	for _, tc := range []struct {
		in        string
		wantScope Scope
		wantPath  string
		wantURL   string
		wantPAT   string
		wantErr   bool
	}{
		{in: "footprintai/containarium", wantScope: ScopeRepo,
			wantPath: "repos/footprintai/containarium",
			wantURL:  "https://github.com/footprintai/containarium", wantPAT: "repo"},
		{in: "footprintai", wantScope: ScopeOrg,
			wantPath: "orgs/footprintai",
			wantURL:  "https://github.com/footprintai", wantPAT: "admin:org"},
		// Names GitHub allows.
		{in: "my-org", wantScope: ScopeOrg, wantPath: "orgs/my-org",
			wantURL: "https://github.com/my-org", wantPAT: "admin:org"},
		{in: "owner/repo.js", wantScope: ScopeRepo, wantPath: "repos/owner/repo.js",
			wantURL: "https://github.com/owner/repo.js", wantPAT: "repo"},

		// Malformed under either scope.
		{in: "", wantErr: true},
		{in: "/repo", wantErr: true},
		{in: "owner/", wantErr: true},
		{in: "owner//repo", wantErr: true},
		{in: "owner/repo/extra", wantErr: true},
		{in: "-leading-dash", wantErr: true},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseTarget(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q) = %+v, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q): %v", tc.in, err)
			}
			if got.Scope != tc.wantScope {
				t.Errorf("scope = %v, want %v", got.Scope, tc.wantScope)
			}
			if got.APIPath() != tc.wantPath {
				t.Errorf("APIPath() = %q, want %q — the wrong endpoint family is a 404 or, worse, "+
					"a successful call against the wrong object", got.APIPath(), tc.wantPath)
			}
			if got.ConfigURL() != tc.wantURL {
				t.Errorf("ConfigURL() = %q, want %q", got.ConfigURL(), tc.wantURL)
			}
			if got.RequiredPATScope() != tc.wantPAT {
				t.Errorf("RequiredPATScope() = %q, want %q", got.RequiredPATScope(), tc.wantPAT)
			}
		})
	}
}

// AC5: endpoint selection for both shapes, asserted on the URL the client
// actually requests rather than on the helper in isolation.
func TestGitHubClient_SelectsEndpointFamilyFromTargetShape(t *testing.T) {
	for _, tc := range []struct {
		target   string
		wantPath string
	}{
		{"footprintai/containarium", "/repos/footprintai/containarium/actions/runners"},
		{"footprintai", "/orgs/footprintai/actions/runners"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			var gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				_, _ = w.Write([]byte(`{"total_count":0,"runners":[]}`))
			}))
			defer srv.Close()

			c := &githubClient{http: srv.Client()}
			// Point the client at the test server by overriding the host via
			// a transport that rewrites the URL.
			c.http = &http.Client{Transport: rewriteHost{to: srv.URL, base: srv.Client().Transport}}

			if _, err := c.ListRunners(context.Background(), tc.target, "ghp_x"); err != nil {
				t.Fatalf("ListRunners: %v", err)
			}
			if gotPath != tc.wantPath {
				t.Errorf("requested %q, want %q", gotPath, tc.wantPath)
			}
		})
	}
}

// rewriteHost sends every request to the test server, preserving the path.
type rewriteHost struct {
	to   string
	base http.RoundTripper
}

func (r rewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	target := strings.TrimPrefix(r.to, "http://")
	u.Scheme, u.Host = "http", target
	clone := req.Clone(req.Context())
	clone.URL = &u
	clone.Host = target
	rt := r.base
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(clone)
}

// AC4: a repo-scoped token against an org target must say so. GitHub returns
// a bare 403 that names no scope, which is the difference between a one-line
// fix and an afternoon of guessing.
func TestGitHubClient_403AgainstAnOrgNamesTheScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Resource not accessible by personal access token"}`))
	}))
	defer srv.Close()

	c := &githubClient{http: &http.Client{Transport: rewriteHost{to: srv.URL}}}

	_, err := c.ListRunners(context.Background(), "footprintai", "ghp_repo_scoped")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "admin:org") {
		t.Errorf("error does not name the scope an org target needs: %v", err)
	}

	// A repo target's 403 must NOT claim admin:org is the fix.
	_, err = c.ListRunners(context.Background(), "footprintai/containarium", "ghp_x")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "admin:org") {
		t.Errorf("a repository target's failure blamed the org scope: %v", err)
	}
}

// Existing repo behaviour must be byte-for-byte unchanged (AC3).
func TestRepoTargetBehaviourUnchanged(t *testing.T) {
	got, err := ParseTarget("footprintai/containarium")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if got.APIPath() != "repos/footprintai/containarium" {
		t.Errorf("APIPath() = %q — the repo endpoint moved", got.APIPath())
	}
	if got.ConfigURL() != "https://github.com/footprintai/containarium" {
		t.Errorf("ConfigURL() = %q — the runner would register against the wrong URL", got.ConfigURL())
	}
	if got.RequiredPATScope() != "repo" {
		t.Errorf("RequiredPATScope() = %q, want repo", got.RequiredPATScope())
	}
}
