package catalogsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// writeKeyFile writes a trusted-keys file with the given public keys, base64 one
// per line, plus a comment and a blank line to exercise the parser.
func writeKeyFile(t *testing.T, dir string, pubs ...ed25519.PublicKey) string {
	t.Helper()
	path := filepath.Join(dir, "trusted.keys")
	body := "# trusted catalog keys\n\n"
	for _, p := range pubs {
		body += base64.StdEncoding.EncodeToString(p) + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

func TestVerifyAcceptsGoodSignature(t *testing.T) {
	pub, priv := genKey(t)
	v := &Verifier{keys: []ed25519.PublicKey{pub}}
	data := []byte("skills:\n  - id: x\n")
	if err := v.Verify(data, ed25519.Sign(priv, data)); err != nil {
		t.Fatalf("Verify good sig: %v", err)
	}
}

func TestVerifyRejectsTamperedDataAndWrongKey(t *testing.T) {
	pub, priv := genKey(t)
	_, otherPriv := genKey(t)
	v := &Verifier{keys: []ed25519.PublicKey{pub}}
	data := []byte("skills:\n  - id: x\n")

	// Tampered payload, valid-shape signature over the original.
	if err := v.Verify([]byte("skills:\n  - id: evil\n"), ed25519.Sign(priv, data)); err == nil {
		t.Fatal("expected tampered data to fail verification")
	}
	// Right data, signed by an untrusted key.
	if err := v.Verify(data, ed25519.Sign(otherPriv, data)); err == nil {
		t.Fatal("expected untrusted-key signature to fail verification")
	}
	// Wrong-size signature.
	if err := v.Verify(data, []byte("short")); err == nil {
		t.Fatal("expected wrong-size signature to fail verification")
	}
}

func TestVerifyMultipleTrustedKeysAllowsRotation(t *testing.T) {
	oldPub, _ := genKey(t)
	newPub, newPriv := genKey(t)
	v := &Verifier{keys: []ed25519.PublicKey{oldPub, newPub}}
	data := []byte("crews:\n  - id: c\n")
	if err := v.Verify(data, ed25519.Sign(newPriv, data)); err != nil {
		t.Fatalf("rotation: signature under one trusted key should verify: %v", err)
	}
}

func TestLoadVerifierRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	keyPath := writeKeyFile(t, dir, pub)

	v, err := LoadVerifier(keyPath)
	if err != nil {
		t.Fatalf("LoadVerifier: %v", err)
	}
	data := []byte("hello")
	if err := v.Verify(data, ed25519.Sign(priv, data)); err != nil {
		t.Fatalf("Verify after LoadVerifier: %v", err)
	}
}

func TestLoadVerifierRejectsBadKeyFile(t *testing.T) {
	dir := t.TempDir()

	// No usable keys.
	empty := filepath.Join(dir, "empty.keys")
	if err := os.WriteFile(empty, []byte("# only comments\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifier(empty); err == nil {
		t.Fatal("expected error for key file with no usable keys")
	}

	// Malformed key.
	bad := filepath.Join(dir, "bad.keys")
	if err := os.WriteFile(bad, []byte("not-base64-!!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifier(bad); err == nil {
		t.Fatal("expected error for malformed key")
	}

	// Missing file.
	if _, err := LoadVerifier(filepath.Join(dir, "nope.keys")); err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestFromEnv(t *testing.T) {
	dir := t.TempDir()
	pub, _ := genKey(t)
	keyPath := writeKeyFile(t, dir, pub)

	// Off by default -> nil verifier, no error.
	t.Setenv(EnvRequireSigned, "")
	t.Setenv(EnvTrustedKeys, "")
	v, err := FromEnv()
	if err != nil || v != nil {
		t.Fatalf("FromEnv off: want (nil,nil), got (%v,%v)", v, err)
	}

	// On but no key file -> fail closed.
	t.Setenv(EnvRequireSigned, "1")
	t.Setenv(EnvTrustedKeys, "")
	if _, err := FromEnv(); err == nil {
		t.Fatal("FromEnv on without trusted keys should error (fail closed)")
	}

	// On with a key file -> usable verifier.
	t.Setenv(EnvTrustedKeys, keyPath)
	v, err = FromEnv()
	if err != nil {
		t.Fatalf("FromEnv on: %v", err)
	}
	if v == nil {
		t.Fatal("FromEnv on: expected a verifier")
	}
}

func TestReadDetachedSig(t *testing.T) {
	dir := t.TempDir()
	_, priv := genKey(t)
	catalog := filepath.Join(dir, "skills.yaml")
	data := []byte("skills: []\n")
	if err := os.WriteFile(catalog, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Missing sig is a hard error.
	if _, err := ReadDetachedSig(catalog); err == nil {
		t.Fatal("expected error for missing detached signature")
	}

	// Present, well-formed sig decodes to the raw signature bytes.
	sig := ed25519.Sign(priv, data)
	if err := os.WriteFile(catalog+SigSuffix, []byte(base64.StdEncoding.EncodeToString(sig)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDetachedSig(catalog)
	if err != nil {
		t.Fatalf("ReadDetachedSig: %v", err)
	}
	if string(got) != string(sig) {
		t.Fatal("decoded signature does not match")
	}

	// Malformed base64 is a hard error.
	if err := os.WriteFile(catalog+SigSuffix, []byte("not base64 !!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDetachedSig(catalog); err == nil {
		t.Fatal("expected error for malformed signature encoding")
	}
}
