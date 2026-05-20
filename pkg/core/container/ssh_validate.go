package container

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ValidateSSHPublicKey verifies that the given string is a well-formed SSH
// public key (in OpenSSH authorized_keys format). Rejects obvious placeholder
// strings, keys with embedded newlines (an injection vector into the
// authorized_keys file), and keys with malformed base64 payloads.
//
// Audit B-MED-3: ssh.ParseAuthorizedKey happens to reject embedded
// `\n` / `\r` today because the base64 layer doesn't tolerate them,
// but that's incidental — a future loosening (or a parser that
// runs `strings.TrimSpace` upstream and feeds us multi-line input)
// would re-open the door. The explicit check makes the intent
// load-bearing rather than implicit.
func ValidateSSHPublicKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("key is empty")
	}

	// Reject any embedded CR/LF. An authorized_keys file is line-
	// based, and a key with a `\n` in the middle would silently
	// inject a second "line" the sshd parser interprets as
	// additional authorized credentials. Done before placeholder
	// matching so the more specific error wins.
	if strings.ContainsAny(key, "\r\n") {
		return fmt.Errorf("key contains embedded newline (CR or LF)")
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
