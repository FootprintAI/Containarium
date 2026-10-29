package mcp

import (
	"encoding/json"
	"testing"
)

// #3214: create_backup's require_encryption is a thin wrapper over the same
// CreateBackupRequest.require_encryption field `backup create
// --require-encryption` sets (#3169). It is passed through unchanged;
// the daemon owns the refusal.
func TestCreateBackup_RequireEncryptionParam(t *testing.T) {
	for _, tc := range []struct {
		name string
		args map[string]interface{}
		want bool
	}{
		{"omitted", map[string]interface{}{}, false},
		{"false", map[string]interface{}{"require_encryption": false}, false},
		{"true", map[string]interface{}{"require_encryption": true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &createBackupOnlyAPI{}
			args := map[string]interface{}{"username": "alice", "database": "app"}
			for k, v := range tc.args {
				args[k] = v
			}
			if _, err := handleCreateBackup(api, args); err != nil {
				t.Fatalf("handleCreateBackup: %v", err)
			}
			if api.got == nil || api.got.RequireEncryption != tc.want {
				t.Fatalf("request = %+v, want RequireEncryption=%v", api.got, tc.want)
			}
		})
	}
}

// The wire name must be the proto field name, and omitted when false so an
// older daemon never sees it.
func TestCreateBackupRequest_RequireEncryptionWire(t *testing.T) {
	b, _ := json.Marshal(CreateBackupRequest{Username: "a", RequireEncryption: true})
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	if m["require_encryption"] != true {
		t.Errorf("wire body = %s, want require_encryption:true", b)
	}
	b, _ = json.Marshal(CreateBackupRequest{Username: "a"})
	m = nil
	_ = json.Unmarshal(b, &m)
	if _, ok := m["require_encryption"]; ok {
		t.Errorf("false must be omitted, got %s", b)
	}
}

func TestCreateBackupSchema_DeclaresRequireEncryption(t *testing.T) {
	for _, tool := range backupTools() {
		if tool.Name != "create_backup" {
			continue
		}
		props, _ := tool.InputSchema["properties"].(map[string]interface{})
		p, ok := props["require_encryption"].(map[string]interface{})
		if !ok || p["type"] != "boolean" {
			t.Fatalf("create_backup schema require_encryption = %v, want a boolean property", props["require_encryption"])
		}
		return
	}
	t.Fatal("create_backup tool not found")
}
