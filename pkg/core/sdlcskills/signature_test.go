package sdlcskills

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

type testKey struct {
	priv *ecdsa.PrivateKey
	pem  []byte
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{priv: priv, pem: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}
}

// sign makes the line cosign sign-blob --key writes: base64 of the ASN.1 DER
// ECDSA signature over the SHA-256 of msg.
func (k testKey) sign(t *testing.T, msg []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(msg)
	der, err := ecdsa.SignASN1(rand.Reader, k.priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(der) + "\n")
}

func keyring(t *testing.T, pems ...[]byte) Keyring {
	t.Helper()
	var all []byte
	for _, p := range pems {
		all = append(all, p...)
	}
	k, err := ParseKeyring(all)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyring_VerifiesOnlyWhatATrustedKeySigned(t *testing.T) {
	trusted, other := newTestKey(t), newTestKey(t)
	keys := keyring(t, trusted.pem)
	msg := []byte(validManifest())

	if err := keys.Verify(msg, trusted.sign(t, msg)); err != nil {
		t.Errorf("good signature refused: %v", err)
	}
	if err := keys.Verify(msg, other.sign(t, msg)); err == nil {
		t.Error("signature by an untrusted key accepted")
	}
	if err := keys.Verify(append([]byte("x"), msg...), trusted.sign(t, msg)); err == nil {
		t.Error("signature over other bytes accepted")
	}
	for name, sig := range map[string][]byte{
		"empty":      nil,
		"blank":      []byte("\n\n"),
		"not base64": []byte("!!!!\n"),
		"not DER":    []byte(base64.StdEncoding.EncodeToString([]byte("not a signature")) + "\n"),
	} {
		if err := keys.Verify(msg, sig); err == nil {
			t.Errorf("%s signature accepted", name)
		}
	}
}

// Rotation: the file holds old and new keys, and the .sig may hold one line
// per signing key. Any trusted key verifying any line is enough.
func TestKeyring_AnyKeyAnyLine(t *testing.T) {
	old, next, stranger := newTestKey(t), newTestKey(t), newTestKey(t)
	msg := []byte(validManifest())
	both := append(stranger.sign(t, msg), next.sign(t, msg)...)

	if err := keyring(t, old.pem, next.pem).Verify(msg, both); err != nil {
		t.Errorf("second line by the second key refused: %v", err)
	}
	if err := keyring(t, old.pem).Verify(msg, both); err == nil {
		t.Error("accepted with no line by a trusted key")
	}
}

func TestKeyring_EmptyNeverVerifies(t *testing.T) {
	k := newTestKey(t)
	msg := []byte("m")
	empty, err := ParseKeyring([]byte("# no keys yet\n"))
	if err != nil {
		t.Fatalf("a file with no keys is valid (nothing is trusted): %v", err)
	}
	err = empty.Verify(msg, k.sign(t, msg))
	if err == nil || !strings.Contains(err.Error(), "no trusted signing key") {
		t.Errorf("err = %v, want a refusal naming the missing key", err)
	}
}

func TestParseKeyring_RejectsWhatItCannotUse(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKIXPublicKey(edPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{
		"ed25519":     {Type: "PUBLIC KEY", Bytes: edDER},
		"P-384":       {Type: "PUBLIC KEY", Bytes: p384DER},
		"garbage":     {Type: "PUBLIC KEY", Bytes: []byte("nope")},
		"private key": {Type: "EC PRIVATE KEY", Bytes: []byte("nope")},
	} {
		if _, err := ParseKeyring(pem.EncodeToMemory(block)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The embedded file must parse; a key committed there is trusted by every
// daemon and CLI built from this tree.
func TestTrustedKeys_EmbeddedFileParses(t *testing.T) {
	if _, err := TrustedKeys(); err != nil {
		t.Fatalf("embedded trusted-keys.pem: %v", err)
	}
}

// Interop: a signature written by `cosign sign-blob --key` (testdata/cosign,
// made with a throwaway key whose private half was discarded) verifies here.
func TestKeyring_VerifiesACosignSignBlobSignature(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/cosign/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	keys := keyring(t, read("throwaway.pub"))
	msg, sig := read("sdlc-skills.manifest"), read("sdlc-skills.manifest.sig")
	if err := keys.Verify(msg, sig); err != nil {
		t.Fatalf("cosign signature refused: %v", err)
	}
	if err := keys.Verify(append(msg, '\n'), sig); err == nil {
		t.Error("cosign signature accepted over changed bytes")
	}
	if _, err := ParseManifest(msg); err != nil {
		t.Errorf("fixture manifest does not parse: %v", err)
	}
}
