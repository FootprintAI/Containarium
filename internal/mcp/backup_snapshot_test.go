package mcp

import (
	"encoding/json"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSnapshotMCPCreate(t *testing.T) {
	var body CreateBackupRequest
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"created"}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "token")
	if _, err := handleCreateBackup(client, map[string]interface{}{"username": "example", "dest": "snapshot"}); err != nil {
		t.Fatal(err)
	}
	if body.Scope != pb.BackupScope_BACKUP_SCOPE_BOX || body.Destination != "BACKUP_DESTINATION_SNAPSHOT" || body.Connection != nil {
		t.Fatalf("request %+v", body)
	}
	for _, option := range []string{"database", "hook", "key_mode", "age_recipient", "gcs_bucket"} {
		value := "invalid"
		if option == "key_mode" {
			value = "managed"
		}
		if _, err := handleCreateBackup(client, map[string]interface{}{"username": "example", "dest": "snapshot", option: value}); err == nil {
			t.Fatalf("accepted %s", option)
		}
	}
	if calls != 1 {
		t.Fatalf("%d requests, want 1", calls)
	}
}
