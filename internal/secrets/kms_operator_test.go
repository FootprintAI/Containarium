package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #2403: an operator machine names the key through the backup record's
// kek_id, not through CONTAINARIUM_GCP_KMS_KEY_NAME (which is the daemon's
// shared KEK). Backend + token are all the operator sets.
func TestLoadKMSClientForKey_GCPNeedsNoSharedKeyName(t *testing.T) {
	clearKMSEnv(t)
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte("pt"))})
	}))
	defer srv.Close()
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "gcp")
	t.Setenv("CONTAINARIUM_GCP_KMS_TOKEN", "operator-token")
	t.Setenv("CONTAINARIUM_GCP_KMS_ENDPOINT", srv.URL)

	c, err := LoadKMSClientForKey(factoryTestKeyName)
	if err != nil {
		t.Fatalf("LoadKMSClientForKey: %v", err)
	}
	pt, err := c.Unwrap(context.Background(), []byte("Y2lwaGVy"), "gcp:"+factoryTestKeyName+"/cryptoKeyVersions/1")
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(pt) != "pt" {
		t.Errorf("plaintext = %q", pt)
	}
	if gotPath != "/v1/"+factoryTestKeyName+":decrypt" {
		t.Errorf("decrypt path = %q, want the record's key", gotPath)
	}
	if gotAuth != "Bearer operator-token" {
		t.Errorf("Authorization = %q, want the operator's own token", gotAuth)
	}
}

func TestLoadKMSClientForKey_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"backend not gcp", map[string]string{"CONTAINARIUM_KMS_BACKEND": "inproc"}, "CONTAINARIUM_KMS_BACKEND"},
		{"no token", map[string]string{"CONTAINARIUM_KMS_BACKEND": "gcp"}, "CONTAINARIUM_GCP_KMS_TOKEN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearKMSEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := LoadKMSClientForKey(factoryTestKeyName); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one naming %s", err, tc.wantErr)
			}
		})
	}
}
