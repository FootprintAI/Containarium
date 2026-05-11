package mcp

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateEphemeralSSHKey_ProducesUsablePair(t *testing.T) {
	pubOpenSSH, privPEM, err := generateEphemeralSSHKey("test-label")
	if err != nil {
		t.Fatalf("generateEphemeralSSHKey: %v", err)
	}

	// Public key should look like an authorized_keys line: "ssh-ed25519 BASE64 [comment]\n"
	if !strings.HasPrefix(pubOpenSSH, "ssh-ed25519 ") {
		t.Errorf("public key doesn't start with ssh-ed25519: %q", pubOpenSSH)
	}
	if !strings.HasSuffix(pubOpenSSH, "\n") {
		t.Errorf("public key should end with a newline so it appends cleanly to authorized_keys")
	}

	// Private key should be OpenSSH PEM-encoded.
	if !strings.Contains(string(privPEM), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Errorf("private key isn't OpenSSH PEM:\n%s", string(privPEM))
	}

	// Round-trip: the generated public key should parse back via ssh.ParseAuthorizedKey.
	parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubOpenSSH))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey on our own output: %v", err)
	}
	if parsedPub.Type() != ssh.KeyAlgoED25519 {
		t.Errorf("expected ed25519 key, got %s", parsedPub.Type())
	}

	// And the private key should parse via ssh.ParseRawPrivateKey.
	if _, err := ssh.ParseRawPrivateKey(privPEM); err != nil {
		t.Fatalf("ParseRawPrivateKey on our own output: %v", err)
	}
}

func TestGenerateEphemeralSSHKey_UniqueEachCall(t *testing.T) {
	a, _, err := generateEphemeralSSHKey("a")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := generateEphemeralSSHKey("b")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Errorf("two separate calls produced identical keys — entropy issue?")
	}
}
