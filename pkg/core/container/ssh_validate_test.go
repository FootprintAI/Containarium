package container

import "testing"

func TestValidateSSHPublicKey(t *testing.T) {
	// Valid ED25519 key (real-looking, properly base64-encoded 32-byte payload)
	validEd25519 := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOG7qdS54tiPQYW4ONfZiLVDy5j31epqxRT8sv4gj4gA user@host"

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"empty", "", true},
		{"whitespace", "   ", true},
		{"placeholder YOUR_KEY", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG...YOUR_KEY", true},
		{"placeholder text", "ssh-ed25519 placeholder foo@bar", true},
		{"placeholder TODO", "TODO: add key here", true},
		{"ellipsis truncated", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... user@host", true},
		{"invalid type", "ssh-unknown AAAA user@host", true},
		{"garbage", "not a key at all", true},
		{"valid ed25519", validEd25519, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSSHPublicKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSSHPublicKey(%q) error = %v, wantErr %v", tt.key, err, tt.wantErr)
			}
		})
	}
}
