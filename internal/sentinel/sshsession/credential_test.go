package sshsession

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/ssh"
)

// newTestCA returns an ssh.Signer usable as a certificate authority.
func newTestCA(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("build CA signer: %v", err)
	}
	return signer
}

// newTestUserCert signs a fresh ed25519 key as a user certificate with the
// given key_id/serial, using ca as the signing authority.
func newTestUserCert(t *testing.T, ca ssh.Signer, keyID string, serial uint64) (*ssh.Certificate, ssh.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("build user public key: %v", err)
	}

	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		Serial:          serial,
		ValidPrincipals: []string{"boxuser"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("sign certificate: %v", err)
	}
	return cert, pub
}

func TestExtractCredential_Certificate(t *testing.T) {
	// Acceptance criterion 2: the record names the certificate's key_id
	// AND serial, not only the login name.
	ca := newTestCA(t)
	cert, innerPub := newTestUserCert(t, ca, "alice", 42)

	authMethod, cred, err := ExtractCredential(cert.Marshal())
	if err != nil {
		t.Fatalf("ExtractCredential: %v", err)
	}

	if authMethod != AuthMethodCertificate {
		t.Errorf("auth method = %q, want %q", authMethod, AuthMethodCertificate)
	}
	if cred.KeyID != "alice" {
		t.Errorf("key id = %q, want %q", cred.KeyID, "alice")
	}
	if cred.Serial != 42 {
		t.Errorf("serial = %d, want 42", cred.Serial)
	}
	wantCAFingerprint := ssh.FingerprintSHA256(ca.PublicKey())
	if cred.CAFingerprint != wantCAFingerprint {
		t.Errorf("ca fingerprint = %q, want %q", cred.CAFingerprint, wantCAFingerprint)
	}
	wantKeyFingerprint := ssh.FingerprintSHA256(innerPub)
	if cred.KeyFingerprint != wantKeyFingerprint {
		t.Errorf("key fingerprint = %q, want %q", cred.KeyFingerprint, wantKeyFingerprint)
	}
}

func TestExtractCredential_RawPublicKey(t *testing.T) {
	// Acceptance criterion 3: a raw-public-key connection records the key
	// fingerprint.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("build public key: %v", err)
	}

	authMethod, cred, err := ExtractCredential(pub.Marshal())
	if err != nil {
		t.Fatalf("ExtractCredential: %v", err)
	}

	if authMethod != AuthMethodPublicKey {
		t.Errorf("auth method = %q, want %q", authMethod, AuthMethodPublicKey)
	}
	want := ssh.FingerprintSHA256(pub)
	if cred.KeyFingerprint != want {
		t.Errorf("key fingerprint = %q, want %q", cred.KeyFingerprint, want)
	}
	if cred.KeyID != "" || cred.Serial != 0 || cred.CAFingerprint != "" {
		t.Errorf("raw key credential should carry no cert fields, got %+v", cred)
	}
}

func TestExtractCredential_MalformedKey(t *testing.T) {
	authMethod, cred, err := ExtractCredential([]byte("not a valid ssh public key"))
	if err == nil {
		t.Fatal("expected an error for malformed key bytes")
	}
	if authMethod != AuthMethodUnknown {
		t.Errorf("auth method = %q, want %q", authMethod, AuthMethodUnknown)
	}
	if cred != (Credential{}) {
		t.Errorf("expected empty credential on parse failure, got %+v", cred)
	}
}

// TestExtractCredential_NeverExposesSecretMaterial guards acceptance
// criterion 8: no private key, token, or session content in any record.
// ExtractCredential only ever sees a PUBLIC key/certificate to begin
// with, but this pins that its output never regresses to embedding the
// raw offered bytes (e.g. via a future field addition).
func TestExtractCredential_NeverExposesSecretMaterial(t *testing.T) {
	ca := newTestCA(t)
	cert, _ := newTestUserCert(t, ca, "alice", 42)
	raw := cert.Marshal()

	_, cred, err := ExtractCredential(raw)
	if err != nil {
		t.Fatalf("ExtractCredential: %v", err)
	}

	rec := Record{Credential: cred}
	blob, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}

	if bytes.Contains(blob, raw) {
		t.Fatal("credential JSON contains the raw offered key/certificate bytes")
	}
}
