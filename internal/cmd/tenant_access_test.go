package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTenantAccessCLIPreviewApplyAndConflict(t *testing.T) {
	posts := 0
	conflict := false
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing authentication")
		}
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"revision":"` + strings.Repeat("a", 64) + `","policy":{"tenant":"team-b","egressMode":"NETWORK_POLICY_MODE_LOG_ONLY"}}`))
			return
		}
		posts++
		if conflict {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"message":"revision conflict"}`))
			return
		}
		var body accessPlan
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body.Changes) != 2 || body.Changes[0].Destination != "team-b" || body.Changes[1].Destination != "team-a" || len(body.Changes[0].Add) != 1 {
			t.Error("wrong directional patch")
		}
		_, _ = w.Write([]byte(`{"applicationState":"TENANT_ACCESS_APPLICATION_STATE_PENDING","connectivityTested":false}`))
	}))
	defer fixture.Close()
	oldServer, oldHTTP, oldToken, oldBoth, oldRevoke, oldConfirm := serverAddr, httpMode, authToken, accessBoth, accessRevoke, accessConfirm
	t.Cleanup(func() {
		serverAddr, httpMode, authToken, accessBoth, accessRevoke, accessConfirm = oldServer, oldHTTP, oldToken, oldBoth, oldRevoke, oldConfirm
	})
	// The fixture is a plain REST server: the access commands select their
	// transport exactly like every other typed-client command (httpMode).
	serverAddr, httpMode, authToken, accessBoth, accessRevoke, accessConfirm = fixture.URL, true, "fixture-token", true, false, true
	preview, _, err := networkPolicyCmd.Find([]string{"access", "preview"})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	oldOut := preview.OutOrStdout()
	preview.SetOut(&output)
	t.Cleanup(func() { preview.SetOut(oldOut) })
	if err := preview.RunE(preview, []string{"team-a", "team-b"}); err != nil {
		t.Fatal(err)
	}
	if posts != 0 {
		t.Fatal("preview mutated policy")
	}
	plan := filepath.Join(t.TempDir(), "reviewed.json")
	if err := os.WriteFile(plan, output.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	apply, _, err := networkPolicyCmd.Find([]string{"access", "apply"})
	if err != nil {
		t.Fatal(err)
	}
	if err := apply.RunE(apply, []string{plan}); err != nil {
		t.Fatal(err)
	}
	conflict = true
	if err := apply.RunE(apply, []string{plan}); err == nil || posts != 2 {
		t.Fatal("conflict was ignored or replayed")
	}
	if err := os.WriteFile(plan, []byte(`{"changes":[],"egressCidrs":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := apply.RunE(apply, []string{plan}); err == nil || posts != 2 {
		t.Fatal("arbitrary policy input forwarded")
	}
}
