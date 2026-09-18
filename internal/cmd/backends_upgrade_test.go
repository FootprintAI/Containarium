package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRunBackendsUpgrade_SendsGithubTag proves the --github-tag flag reaches
// the daemon on the wire as the request's github_tag field (#1028) — opt-in,
// alongside the existing backend_id/force fields.
func TestRunBackendsUpgrade_SendsGithubTag(t *testing.T) {
	var gotBody triggerUpgradeReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"upgradeId":"upg-1","status":"in_progress"}`))
	}))
	defer srv.Close()

	origServer, origToken, origForce, origTag := serverAddr, authToken, upgradeForce, upgradeGithubTag
	t.Cleanup(func() {
		serverAddr, authToken, upgradeForce, upgradeGithubTag = origServer, origToken, origForce, origTag
	})
	serverAddr = srv.URL
	authToken = ""
	upgradeForce = false
	upgradeGithubTag = "v0.99.0"

	cmd := backendsUpgradeCmd
	if err := runBackendsUpgrade(cmd, nil); err != nil {
		t.Fatalf("runBackendsUpgrade: %v", err)
	}

	if gotBody.GithubTag != "v0.99.0" {
		t.Errorf("github_tag on the wire = %q, want %q", gotBody.GithubTag, "v0.99.0")
	}
}

// TestRunBackendsUpgrade_OmitsGithubTagWhenUnset proves the default (empty)
// --github-tag doesn't add a stray field, matching backend_id/force's
// omitempty behavior — the daemon's sentinel path stays the unchanged default.
func TestRunBackendsUpgrade_OmitsGithubTagWhenUnset(t *testing.T) {
	var gotRaw map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &gotRaw); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"upgradeId":"upg-2","status":"in_progress"}`))
	}))
	defer srv.Close()

	origServer, origToken, origForce, origTag := serverAddr, authToken, upgradeForce, upgradeGithubTag
	t.Cleanup(func() {
		serverAddr, authToken, upgradeForce, upgradeGithubTag = origServer, origToken, origForce, origTag
	})
	serverAddr = srv.URL
	authToken = ""
	upgradeForce = false
	upgradeGithubTag = ""

	if err := runBackendsUpgrade(backendsUpgradeCmd, nil); err != nil {
		t.Fatalf("runBackendsUpgrade: %v", err)
	}

	if _, present := gotRaw["github_tag"]; present {
		t.Errorf("github_tag should be omitted from the wire when unset, got %v", gotRaw["github_tag"])
	}
}
