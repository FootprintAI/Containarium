package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestRunBackendsUpgrade_PrintsTargetVersion proves the daemon's target_version
// reaches the operator (#2171).
func TestRunBackendsUpgrade_PrintsTargetVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"upgradeId":"upg-3","status":"in_progress","currentVersion":"0.90.1","targetVersion":"0.91.1"}`))
	}))
	defer srv.Close()

	origServer, origToken, origForce, origTag := serverAddr, authToken, upgradeForce, upgradeGithubTag
	t.Cleanup(func() {
		serverAddr, authToken, upgradeForce, upgradeGithubTag = origServer, origToken, origForce, origTag
		backendsUpgradeCmd.SetOut(nil)
	})
	serverAddr, authToken, upgradeForce, upgradeGithubTag = srv.URL, "", false, ""

	var buf bytes.Buffer
	backendsUpgradeCmd.SetOut(&buf)
	if err := runBackendsUpgrade(backendsUpgradeCmd, nil); err != nil {
		t.Fatalf("runBackendsUpgrade: %v", err)
	}
	if !strings.Contains(buf.String(), "to version:   0.91.1") {
		t.Errorf("output missing target version:\n%s", buf.String())
	}
}
