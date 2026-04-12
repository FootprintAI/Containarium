package container

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ValidateSSHPublicKey verifies that the given string is a well-formed SSH
// public key (in OpenSSH authorized_keys format). Rejects obvious placeholder
// strings and keys with malformed base64 payloads.
func ValidateSSHPublicKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("key is empty")
	}

	// Reject obvious placeholder markers that have bitten us before.
	lowered := strings.ToLower(key)
	for _, marker := range []string{
		"your_key", "your-key", "yourkey",
		"placeholder",
		"replace_me", "replace-me",
		"todo",
		"...",
	} {
		if strings.Contains(lowered, marker) {
			return fmt.Errorf("key contains placeholder text %q", marker)
		}
	}

	// Use the ssh package to parse — this validates the key type, base64
	// payload, and overall structure. Any parse failure is rejected.
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return fmt.Errorf("not a valid SSH public key: %w", err)
	}

	return nil
}
