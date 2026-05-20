package container

import (
	"strings"
	"testing"
)

// Phase 3.5 — explicit CR/LF rejection in ValidateSSHPublicKey
// (audit B-MED-3). The pre-3.5 behavior happened to reject these
// keys because ssh.ParseAuthorizedKey's base64 decoder couldn't
// stomach embedded newlines, but the rejection was incidental.
// Make it explicit so a future parser change can't silently
// re-open the injection vector.

func TestValidateSSHPublicKey_RejectsEmbeddedLF(t *testing.T) {
	// Synthesize a key with a sneaky LF in the middle. The exact
	// bytes don't matter — the validator should reject before
	// it ever tries to parse.
	key := "ssh-ed25519 AAAA\ncommand=\"rm -rf /\" ssh-ed25519 BBBB user@host"
	err := ValidateSSHPublicKey(key)
	if err == nil {
		t.Fatal("embedded LF must be rejected")
	}
	if !strings.Contains(err.Error(), "newline") {
		t.Fatalf("error should name newline: %v", err)
	}
}

func TestValidateSSHPublicKey_RejectsEmbeddedCR(t *testing.T) {
	key := "ssh-ed25519 AAAA\rsomething ssh-ed25519 BBBB user@host"
	err := ValidateSSHPublicKey(key)
	if err == nil {
		t.Fatal("embedded CR must be rejected")
	}
}

func TestValidateSSHPublicKey_RejectsEmbeddedCRLF(t *testing.T) {
	key := "ssh-ed25519 AAAA\r\nfoo user@host"
	err := ValidateSSHPublicKey(key)
	if err == nil {
		t.Fatal("embedded CRLF must be rejected")
	}
}

func TestValidateSSHPublicKey_AcceptsRealKey(t *testing.T) {
	// Real ed25519 public key (throwaway, never used as auth).
	// The TrimSpace in the validator means leading/trailing
	// whitespace is fine; embedded newlines aren't.
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK8gYz2sUYIvKVoB1aZmJC1hY4yYR8nM8GxTk8nL7sWP user@test"
	if err := ValidateSSHPublicKey(key); err != nil {
		t.Fatalf("real key should be accepted: %v", err)
	}
}

func TestValidateSSHPublicKey_NewlineCheckBeatsPlaceholderCheck(t *testing.T) {
	// A key that's BOTH placeholder-shaped AND has a newline —
	// the more-specific newline error should fire first because
	// the injection vector is more dangerous than a placeholder.
	key := "ssh-rsa your_key\nssh-rsa real_payload user@host"
	err := ValidateSSHPublicKey(key)
	if err == nil {
		t.Fatal("must reject")
	}
	if !strings.Contains(err.Error(), "newline") {
		t.Fatalf("newline check should fire before placeholder check: %v", err)
	}
}
