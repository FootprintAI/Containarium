package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/footprintai/containarium/pkg/core/secrets"
)

const mcpTestKEKID = "gcp:projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/1"

type mcpFakeKMS struct {
	plaintext  []byte
	err        error
	gotWrapped []byte
	unwraps    int
}

func (f *mcpFakeKMS) Wrap(context.Context, []byte) ([]byte, string, error) {
	return nil, "", errors.New("not used")
}

func (f *mcpFakeKMS) Unwrap(_ context.Context, wrapped []byte, _ string) ([]byte, error) {
	f.unwraps++
	f.gotWrapped = wrapped
	if f.err != nil {
		return nil, f.err
	}
	return f.plaintext, nil
}

// mcpManagedHost serves two managed alice/app records and records every
// restore/verify body it receives.
type mcpManagedHost struct {
	srv    *httptest.Server
	posts  []string
	bodies []map[string]interface{}
}

func newMCPManagedHost(t *testing.T) *mcpManagedHost {
	t.Helper()
	h := &mcpManagedHost{}
	rec := func(id, created, wrapped string) map[string]interface{} {
		return map[string]interface{}{
			"id": id, "username": "alice", "database": "app", "createdAt": created, "encrypted": true,
			"wrappedKey": base64.StdEncoding.EncodeToString([]byte(wrapped)), "kekId": mcpTestKEKID,
			"keyMode": "BACKUP_KEY_MODE_MANAGED",
		}
	}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"records": []interface{}{
				rec("alice-app-20261001T010000Z", "2026-10-01T01:00:00Z", "wrapped-old"),
				rec("alice-app-20261003T010000Z", "2026-10-03T01:00:00Z", "wrapped-new"),
			}})
			return
		}
		h.posts = append(h.posts, r.URL.Path)
		var body map[string]interface{}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		h.bodies = append(h.bodies, body)
		if strings.HasSuffix(r.URL.Path, "/verify") {
			_, _ = w.Write([]byte(`{"message":"verification passed","verification":{"result":"VERIFICATION_RESULT_PASSED"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"message":"restore complete"}`))
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func withMCPFakeKMS(t *testing.T) (*mcpFakeKMS, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	kms := &mcpFakeKMS{plaintext: []byte(id.String())}
	orig := managedKMSLoader
	managedKMSLoader = func(string) (secrets.KMSClient, error) { return kms, nil }
	t.Cleanup(func() { managedKMSLoader = orig })
	return kms, id.String()
}

// #2403: restore_backup's managed/latest/target are thin wrappers over the
// same selection and unwrap the CLI uses, landing on the same REST body.
func TestRestoreBackupTool_ManagedLatestTarget(t *testing.T) {
	h := newMCPManagedHost(t)
	kms, identity := withMCPFakeKMS(t)

	_, err := handleRestoreBackup(NewClient(h.srv.URL, "t"), map[string]interface{}{
		"managed": true, "latest": true, "username": "alice", "database": "app", "target": "scratch-container",
	})
	if err != nil {
		t.Fatalf("handleRestoreBackup: %v", err)
	}
	if len(h.posts) != 1 || h.posts[0] != "/v1/backups/alice-app-20261003T010000Z/restore" {
		t.Fatalf("posts = %v, want one restore of the newest record", h.posts)
	}
	if string(kms.gotWrapped) != "wrapped-new" {
		t.Errorf("unwrapped %q, want the newest record's wrapped key", kms.gotWrapped)
	}
	if h.bodies[0]["age_identity"] != identity || h.bodies[0]["target_container"] != "scratch-container" {
		t.Errorf("restore body did not carry the unwrapped identity and target")
	}
	for _, b := range kms.plaintext {
		if b != 0 {
			t.Fatal("unwrapped identity buffer was not zeroed")
		}
	}
}

func TestRestoreBackupTool_ManagedPermissionDeniedSendsNoRestore(t *testing.T) {
	h := newMCPManagedHost(t)
	kms, _ := withMCPFakeKMS(t)
	kms.err = errors.New("PERMISSION_DENIED")

	_, err := handleRestoreBackup(NewClient(h.srv.URL, "t"), map[string]interface{}{
		"id": "alice-app-20261001T010000Z", "managed": true, "username": "alice",
	})
	if err == nil || !strings.Contains(err.Error(), "PERMISSION_DENIED") {
		t.Fatalf("err = %v, want the KMS denial", err)
	}
	if len(h.posts) != 0 {
		t.Errorf("posts = %v after a denied unwrap, want none", h.posts)
	}
}

func TestVerifyBackupTool_ManagedLatest(t *testing.T) {
	h := newMCPManagedHost(t)
	_, identity := withMCPFakeKMS(t)

	_, err := handleVerifyBackup(NewClient(h.srv.URL, "t"), map[string]interface{}{
		"managed": true, "latest": true, "username": "alice", "database": "app", "target_username": "scratch",
	})
	if err != nil {
		t.Fatalf("handleVerifyBackup: %v", err)
	}
	if len(h.posts) != 1 || h.posts[0] != "/v1/backups/alice-app-20261003T010000Z/verify" {
		t.Fatalf("posts = %v", h.posts)
	}
	if h.bodies[0]["age_identity"] != identity {
		t.Error("verify body did not carry the unwrapped identity")
	}
}

func TestRestoreBackupTool_RefusesAmbiguousSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"id and latest", map[string]interface{}{"id": "x", "latest": true, "username": "alice", "database": "app"}, "latest"},
		{"latest without database", map[string]interface{}{"latest": true, "username": "alice"}, "database"},
		{"managed and age_identity_file", map[string]interface{}{"id": "x", "managed": true, "age_identity_file": "k"}, "managed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMCPManagedHost(t)
			withMCPFakeKMS(t)
			_, err := handleRestoreBackup(NewClient(h.srv.URL, "t"), tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %s", err, tc.want)
			}
			if len(h.posts) != 0 {
				t.Errorf("posts = %v", h.posts)
			}
		})
	}
}

func TestBackupToolSchemas_DeclareManagedLatestTarget(t *testing.T) {
	want := map[string][]string{
		"restore_backup": {"managed", "latest", "username", "database", "target"},
		"verify_backup":  {"managed", "latest", "username", "database"},
	}
	for _, tool := range backupTools() {
		props, _ := tool.InputSchema["properties"].(map[string]interface{})
		for _, p := range want[tool.Name] {
			if _, ok := props[p]; !ok {
				t.Errorf("%s schema lacks %q", tool.Name, p)
			}
		}
	}
}
