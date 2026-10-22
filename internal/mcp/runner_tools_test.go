package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveMCPSSHKey_PathConstraints exercises the path constraint
// added in response to gosec G304: an authenticated MCP caller must
// not be able to pass an arbitrary `ssh_key_path` and trick the
// daemon into reading files outside ~/.ssh/.
//
// We swap HOME to a tmpdir so the tests are hermetic.
func TestResolveMCPSSHKey_PathConstraints(t *testing.T) {
	tmpHome := t.TempDir()
	sshDir := filepath.Join(tmpHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir ssh: %v", err)
	}
	// Create a fake key file so the existence check passes for the
	// allowed cases.
	keyPath := filepath.Join(sshDir, "id_rsa.pub")
	if err := os.WriteFile(keyPath, []byte("ssh-rsa AAAA fake@host"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	// And a sibling key for the bare-filename test.
	siblingPath := filepath.Join(sshDir, "ci.pub")
	if err := os.WriteFile(siblingPath, []byte("ssh-rsa AAAA ci@host"), 0o600); err != nil {
		t.Fatalf("write sibling: %v", err)
	}
	// A file outside ~/.ssh that an attacker might try to target.
	outsidePath := filepath.Join(tmpHome, "outside.pub")
	if err := os.WriteFile(outsidePath, []byte("attacker target"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	// A sibling .ssh-evil dir to test the prefix-with-separator
	// guard (so "/home/x/.ssh-evil" doesn't match "/home/x/.ssh").
	evilDir := filepath.Join(tmpHome, ".ssh-evil")
	if err := os.MkdirAll(evilDir, 0o700); err != nil {
		t.Fatalf("mkdir evil: %v", err)
	}
	evilPath := filepath.Join(evilDir, "id_rsa.pub")
	if err := os.WriteFile(evilPath, []byte("attacker dir"), 0o600); err != nil {
		t.Fatalf("write evil: %v", err)
	}

	t.Setenv("HOME", tmpHome)

	cases := []struct {
		name        string
		input       string
		wantPubPath string // empty = don't check
		wantErr     string // substring; empty = expect success
	}{
		{
			name:        "empty defaults to ~/.ssh/id_rsa.pub",
			input:       "",
			wantPubPath: keyPath,
		},
		{
			name:        "bare filename resolves under ~/.ssh",
			input:       "ci.pub",
			wantPubPath: siblingPath,
		},
		{
			name:        "tilde prefix expands to home",
			input:       "~/.ssh/id_rsa.pub",
			wantPubPath: keyPath,
		},
		{
			name:    "absolute path outside ~/.ssh rejected",
			input:   "/etc/shadow",
			wantErr: "must resolve under",
		},
		{
			name:    "path outside ~/.ssh in same home rejected",
			input:   outsidePath,
			wantErr: "must resolve under",
		},
		{
			name:    "dot-dot escape after clean rejected",
			input:   filepath.Join(sshDir, "..", "outside.pub"),
			wantErr: "must resolve under",
		},
		{
			name:    "sibling .ssh-evil dir rejected (prefix-with-separator guard)",
			input:   evilPath,
			wantErr: "must resolve under",
		},
		{
			name:    "missing file under ~/.ssh surfaces NotFound, not path-rejection",
			input:   filepath.Join(sshDir, "nope.pub"),
			wantErr: "not found",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, err := resolveMCPSSHKey(tc.input)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (pub=%q priv=%q)", tc.wantErr, pub, priv)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantPubPath != "" && pub != tc.wantPubPath {
				t.Errorf("pub path = %q, want %q", pub, tc.wantPubPath)
			}
			// privPath should be pubPath without the .pub suffix; if
			// no .pub suffix, equal to pubPath. Sanity check.
			expectedPriv := strings.TrimSuffix(pub, ".pub")
			if priv != expectedPriv {
				t.Errorf("priv path = %q, want %q", priv, expectedPriv)
			}
		})
	}
}

// TestProvisionRunners_RunnerGroup checks the MCP tool exposes runner_group
// and hands it to the same runner.ValidateOptions the CLI uses: a group on a
// repository target is refused before any box or SSH work starts, which is
// why a nil client is enough here.
func TestProvisionRunners_RunnerGroup(t *testing.T) {
	var schema map[string]interface{}
	for _, tool := range runnerTools() {
		if tool.Name == "provision_runners" {
			schema = tool.InputSchema
		}
	}
	props, _ := schema["properties"].(map[string]interface{})
	if _, ok := props["runner_group"]; !ok {
		t.Fatal("provision_runners schema has no runner_group property")
	}

	_, err := handleProvisionRunners(nil, map[string]interface{}{
		"repo":         "owner/repo",
		"github_pat":   "ghp_x",
		"runner_group": "gpu",
	})
	if err == nil || !strings.Contains(err.Error(), "runner group requires an organization target") {
		t.Fatalf("want the organization-target refusal, got %v", err)
	}
}
