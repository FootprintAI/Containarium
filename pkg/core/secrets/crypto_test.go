package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	cases := []struct {
		name    string
		wantErr bool
		descr   string
	}{
		{"OPENAI_API_KEY", false, "canonical env-var name"},
		{"DB_URL", false, "short uppercase"},
		{"_LEADING_UNDERSCORE", false, "leading underscore ok per regex"},
		{"A", false, "single char"},
		{"openai_api_key", true, "lowercase rejected"},
		{"OpenAI", true, "mixed case rejected"},
		{"1FOO", true, "leading digit rejected"},
		{"FOO-BAR", true, "dash rejected"},
		{"FOO.BAR", true, "dot rejected"},
		{"", true, "empty rejected"},
		{strings.Repeat("A", 129), true, "129 chars exceeds max"},
		{strings.Repeat("A", 128), false, "128 chars is exactly the limit"},
	}
	for _, c := range cases {
		got := ValidateName(c.name)
		if (got != nil) != c.wantErr {
			t.Errorf("ValidateName(%q) error=%v, wantErr=%v (%s)", c.name, got, c.wantErr, c.descr)
		}
	}
}

func TestValidateValue(t *testing.T) {
	if err := ValidateValue(""); err != nil {
		t.Errorf("empty value should be valid (soft-delete pattern), got %v", err)
	}
	if err := ValidateValue("sk-abc..."); err != nil {
		t.Errorf("typical value should be valid, got %v", err)
	}
	if err := ValidateValue(strings.Repeat("x", 64*1024)); err != nil {
		t.Errorf("64 KiB exactly should be valid, got %v", err)
	}
	if err := ValidateValue(strings.Repeat("x", 64*1024+1)); err == nil {
		t.Errorf("64 KiB + 1 should reject")
	}
}

func TestLoadOrCreateMasterKey_GeneratesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.key")

	key1, created, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if !created {
		t.Errorf("first call should report created=true")
	}
	if len(key1) != MasterKeySize {
		t.Errorf("got %d bytes, want %d", len(key1), MasterKeySize)
	}

	// Check mode is 0400
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat keyfile: %v", err)
	}
	if mode := info.Mode().Perm(); mode != MasterKeyFileMode {
		t.Errorf("keyfile mode = %o, want %o", mode, MasterKeyFileMode)
	}

	// Second call should re-read, not regenerate
	key2, created2, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if created2 {
		t.Errorf("second call should report created=false")
	}
	if !bytes.Equal(key1, key2) {
		t.Errorf("keys differ across calls (regenerated when shouldn't have)")
	}
}

func TestLoadOrCreateMasterKey_RejectsWrongSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.key")
	if err := os.WriteFile(path, []byte("too-short"), 0o400); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, _, err := LoadOrCreateMasterKey(path)
	if err == nil {
		t.Fatal("expected error on wrong-size key file")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("error should mention 32 bytes, got %v", err)
	}
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, MasterKeySize)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	plaintext := []byte("sk-test-1234567890")
	nonce, ct, err := c.Encrypt("alice", "OPENAI_API_KEY", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(nonce) != NonceSize {
		t.Errorf("nonce wrong size: %d", len(nonce))
	}
	// Ciphertext = plaintext + 16-byte tag in GCM
	if len(ct) != len(plaintext)+16 {
		t.Errorf("ciphertext wrong size: %d (want %d)", len(ct), len(plaintext)+16)
	}

	got, err := c.Decrypt("alice", "OPENAI_API_KEY", nonce, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncryptDecrypt_AADBindingRejectsWrongName(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, MasterKeySize)
	c, _ := NewCipher(key)

	nonce, ct, _ := c.Encrypt("alice", "OPENAI_API_KEY", []byte("sk-secret"))

	// Same user, different name — should fail authentication.
	_, err := c.Decrypt("alice", "GITHUB_TOKEN", nonce, ct)
	if err != ErrAuthentication {
		t.Errorf("expected ErrAuthentication for wrong name, got %v", err)
	}

	// Different user, same name — should fail authentication.
	_, err = c.Decrypt("bob", "OPENAI_API_KEY", nonce, ct)
	if err != ErrAuthentication {
		t.Errorf("expected ErrAuthentication for wrong username, got %v", err)
	}

	// AAD-trick avoidance: ("alice", "X_KEY") and ("aliceX", "_KEY")
	// must not collide. Encrypt under the first, decrypt under the
	// second.
	nonce2, ct2, _ := c.Encrypt("alice", "X_KEY", []byte("v1"))
	_, err = c.Decrypt("aliceX", "_KEY", nonce2, ct2)
	if err != ErrAuthentication {
		t.Errorf("expected ErrAuthentication for split-AAD collision attempt, got %v", err)
	}
}

func TestEncryptDecrypt_TamperedCiphertextFails(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, MasterKeySize)
	c, _ := NewCipher(key)
	nonce, ct, _ := c.Encrypt("alice", "KEY", []byte("plaintext"))

	// Flip a single byte in the ciphertext.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 0xff

	_, err := c.Decrypt("alice", "KEY", nonce, tampered)
	if err != ErrAuthentication {
		t.Errorf("tampered ciphertext should fail auth, got %v", err)
	}
}

func TestNewCipher_RejectsWrongKeySize(t *testing.T) {
	_, err := NewCipher([]byte("too-short"))
	if err != ErrKeyWrongSize {
		t.Errorf("expected ErrKeyWrongSize, got %v", err)
	}
}

func TestEncryptDecrypt_FreshNonceEveryTime(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, MasterKeySize)
	c, _ := NewCipher(key)

	nonce1, _, _ := c.Encrypt("alice", "KEY", []byte("plaintext"))
	nonce2, _, _ := c.Encrypt("alice", "KEY", []byte("plaintext"))
	if bytes.Equal(nonce1, nonce2) {
		t.Errorf("nonces should be random, got identical %x", nonce1)
	}
}
