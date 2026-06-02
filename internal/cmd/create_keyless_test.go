package cmd

import (
	"strings"
	"testing"
)

// TestValidateSSHKeyMode covers the "exactly one of --ssh-key / --no-ssh-key"
// rule for `containarium create` (#388): human dev boxes still require a key,
// service tenants opt out with --no-ssh-key, and neither/both are rejected.
func TestValidateSSHKeyMode(t *testing.T) {
	cases := []struct {
		name       string
		noSSHKey   bool
		sshKeyPath string
		wantErr    string // substring; "" means expect success
	}{
		{"key provided (human dev box)", false, "~/.ssh/id_rsa.pub", ""},
		{"keyless service tenant", true, "", ""},
		{"neither → required error", false, "", "--ssh-key is required"},
		{"both → mutually exclusive", true, "/tmp/k.pub", "mutually exclusive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSSHKeyMode(tc.noSSHKey, tc.sshKeyPath)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateSSHKeyMode(%v, %q) unexpected error: %v", tc.noSSHKey, tc.sshKeyPath, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateSSHKeyMode(%v, %q) = %v, want error containing %q", tc.noSSHKey, tc.sshKeyPath, err, tc.wantErr)
			}
		})
	}
}
