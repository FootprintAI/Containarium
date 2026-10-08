package mcp

import (
	"strings"
	"testing"
)

// createBackupOnlyAPI records the one request the create_backup tool
// builds. It embeds the interface so any other call panics rather than
// silently returning zero values.
type createBackupOnlyAPI struct {
	API
	got *CreateBackupRequest
}

func (f *createBackupOnlyAPI) CreateBackup(req CreateBackupRequest) (*CreateBackupResponse, error) {
	f.got = &req
	return &CreateBackupResponse{Message: "ok", Record: &BackupRecord{
		ID: "alice-app-x", Encrypted: true, AgeRecipient: "age1ephemeral",
		KeyMode: "BACKUP_KEY_MODE_MANAGED", KekID: "gcp:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
	}}, nil
}

// The MCP create_backup tool is a thin wrapper over the same request the
// CLI sends (#2402): key_mode is mapped to the proto enum NAME the
// gateway expects, an unknown value is refused client-side, and the
// response surfaces the key mode and key version so an agent can report
// what it just made.
func TestCreateBackup_KeyModeParam(t *testing.T) {
	for _, tc := range []struct {
		arg     string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"managed", "BACKUP_KEY_MODE_MANAGED", false},
		{"both", "BACKUP_KEY_MODE_BOTH", false},
		{"age_recipient", "BACKUP_KEY_MODE_AGE_RECIPIENT", false},
		{"rot13", "", true},
	} {
		t.Run("key_mode="+tc.arg, func(t *testing.T) {
			api := &createBackupOnlyAPI{}
			args := map[string]interface{}{"username": "alice", "database": "app"}
			if tc.arg != "" {
				args["key_mode"] = tc.arg
			}
			out, err := handleCreateBackup(api, args)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "key_mode") {
					t.Fatalf("err = %v, want a key_mode error", err)
				}
				if api.got != nil {
					t.Error("an invalid key_mode still reached the daemon")
				}
				return
			}
			if err != nil {
				t.Fatalf("handleCreateBackup: %v", err)
			}
			if api.got == nil || api.got.KeyMode != tc.want {
				t.Fatalf("request key_mode = %+v, want %q", api.got, tc.want)
			}
			if !strings.Contains(out, "managed") || !strings.Contains(out, "cryptoKeyVersions/1") {
				t.Errorf("output does not report the key mode and key version:\n%s", out)
			}
		})
	}
}

func TestCreateBackupSchema_DeclaresKeyMode(t *testing.T) {
	var schema map[string]interface{}
	for _, tool := range backupTools() {
		if tool.Name == "create_backup" {
			schema = tool.InputSchema
		}
	}
	props, _ := schema["properties"].(map[string]interface{})
	km, ok := props["key_mode"].(map[string]interface{})
	if !ok {
		t.Fatalf("create_backup schema has no key_mode property: %v", props)
	}
	enum, _ := km["enum"].([]string)
	if strings.Join(enum, ",") != "age_recipient,managed,both" {
		t.Errorf("key_mode enum = %v, want age_recipient,managed,both", enum)
	}
}
