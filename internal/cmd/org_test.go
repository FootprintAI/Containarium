package cmd

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/credentials"
)

// cloudSession points serverAddr/authToken at ts and seeds a credentials file
// so isCloudTarget classifies it as cloud and resolveOrgID finds orgID.
// Restores the package globals on test cleanup.
func cloudSession(t *testing.T, ts *httptest.Server, orgID string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	_ = seedCreds(t, home, "", map[string]credentials.ServerCreds{
		ts.URL: {Token: "ctnr_test", OrgID: orgID, AccessModel: credentials.AccessModelToken},
	})
	oldServer, oldToken := serverAddr, authToken
	serverAddr, authToken = ts.URL, "ctnr_test"
	t.Cleanup(func() { serverAddr, authToken = oldServer, oldToken })
}

// TestOrgCommands_RefuseAgainstDaemon is #1607 acceptance 2: the mirror image
// of errUnsupportedOnCloud — a control-plane-only command refusing cleanly
// against a standalone daemon target, not round-tripping to a 404.
func TestOrgCommands_RefuseAgainstDaemon(t *testing.T) {
	oldServer, oldToken := serverAddr, authToken
	serverAddr, authToken = "http://daemon.example", "eyJdaemonjwt"
	t.Cleanup(func() { serverAddr, authToken = oldServer, oldToken })

	for name, run := range map[string]func(*testing.T) error{
		"get-default-region": func(t *testing.T) error { return runOrgGetDefaultRegion(nil, nil) },
		"set-default-region": func(t *testing.T) error { return runOrgSetDefaultRegion(nil, []string{"us-east"}) },
		"regions":            func(t *testing.T) error { return runRegions(nil, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			err := run(t)
			if err == nil || !strings.Contains(err.Error(), "requires a hosted control plane") {
				t.Fatalf("err = %v, want the control-plane-only refusal", err)
			}
		})
	}
}

// TestRunRegions_ListsSortedCodes covers the discovery half (#1607's
// "containarium regions").
func TestRunRegions_ListsSortedCodes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/regions" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"regions": []string{"us-west1", "asia-east1"}})
	}))
	defer ts.Close()
	cloudSession(t, ts, "org-abc")

	regions, err := fetchRegions()
	if err != nil {
		t.Fatalf("fetchRegions: %v", err)
	}
	want := []string{"asia-east1", "us-west1"}
	if len(regions) != 2 || regions[0] != want[0] || regions[1] != want[1] {
		t.Errorf("regions = %v, want sorted %v", regions, want)
	}
}

// TestRunOrgGetDefaultRegion_PrintsCurrentValue covers acceptance 1 (read).
func TestRunOrgGetDefaultRegion_ReadsFromOrgEndpoint(t *testing.T) {
	var gotPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"organization": map[string]any{"id": "org-abc", "defaultRegion": "us-west1"},
		})
	}))
	defer ts.Close()
	cloudSession(t, ts, "org-abc")

	if err := runOrgGetDefaultRegion(nil, nil); err != nil {
		t.Fatalf("runOrgGetDefaultRegion: %v", err)
	}
	if gotPath != "/v1/orgs/org-abc" {
		t.Errorf("path = %q, want /v1/orgs/org-abc", gotPath)
	}
}

// TestRunOrgGetDefaultRegion_NoSessionOrg is the case resolveOrgID has
// nothing for — a caller must get an actionable message, not a bare "" sent
// to the server.
func TestRunOrgGetDefaultRegion_NoSessionOrg(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("must not call the API with no resolved org_id")
	}))
	defer ts.Close()
	cloudSession(t, ts, "") // no OrgID on this session

	if err := runOrgGetDefaultRegion(nil, nil); err == nil {
		t.Fatal("expected an error when no org is resolvable")
	}
}

// TestRunOrgSetDefaultRegion_Success covers acceptance 1 (write).
func TestRunOrgSetDefaultRegion_Success(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"organization": map[string]any{"id": "org-abc", "defaultRegion": "us-west1"},
		})
	}))
	defer ts.Close()
	cloudSession(t, ts, "org-abc")

	if err := runOrgSetDefaultRegion(nil, []string{"us-west1"}); err != nil {
		t.Fatalf("runOrgSetDefaultRegion: %v", err)
	}
	if gotMethod != http.MethodPut || gotPath != "/v1/orgs/org-abc/default-region" {
		t.Errorf("request = %s %s, want PUT /v1/orgs/org-abc/default-region", gotMethod, gotPath)
	}
	if gotBody["region"] != "us-west1" {
		t.Errorf("body region = %v, want us-west1", gotBody["region"])
	}
}

// TestRunOrgSetDefaultRegion_PermissionDenied is acceptance 3: a caller
// without permission sees a permission error, not a generic failure.
func TestRunOrgSetDefaultRegion_PermissionDenied(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 7, "message": "caller is not owner/admin"})
	}))
	defer ts.Close()
	cloudSession(t, ts, "org-abc")

	err := runOrgSetDefaultRegion(nil, []string{"us-west1"})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v, want a permission-denied error", err)
	}
}

// TestRunOrgSetDefaultRegion_UnknownRegionNamesValidCodes is acceptance 4:
// setting an unknown region fails with an error naming the valid ones, not
// just "InvalidArgument".
func TestRunOrgSetDefaultRegion_UnknownRegionNamesValidCodes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/orgs/org-abc/default-region":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": 3, "message": `unknown region "nowhere": not a configured sentinel region`,
			})
		case "/v1/regions":
			_ = json.NewEncoder(w).Encode(map[string]any{"regions": []string{"asia-east1", "us-west1"}})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	defer ts.Close()
	cloudSession(t, ts, "org-abc")

	err := runOrgSetDefaultRegion(nil, []string{"nowhere"})
	if err == nil {
		t.Fatal("expected an error for an unknown region")
	}
	for _, want := range []string{"asia-east1", "us-west1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to name valid region %q", err.Error(), want)
		}
	}
}

// TestApiErrorFromBody pins the grpc-gateway JSON error shape decoding.
func TestApiErrorFromBody(t *testing.T) {
	err := apiErrorFromBody(http.StatusForbidden, []byte(`{"code":7,"message":"nope","details":[]}`))
	var apiErr *cloudAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *cloudAPIError", err)
	}
	if apiErr.Code != 7 {
		t.Errorf("code = %d, want 7", apiErr.Code)
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("Error() = %q, want the permission-denied marker", err.Error())
	}
}
