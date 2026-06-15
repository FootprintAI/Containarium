package integrity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestCompute_Unsigned(t *testing.T) {
	bin := writeTemp(t, "daemon", []byte("daemon-bytes"))
	prog := writeTemp(t, "policy.o", []byte("ebpf-object-bytes"))

	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	m, err := Compute(Inputs{
		BinaryPath:    bin,
		Programs:      []ProgramObject{{Name: "policy.o", Path: prog}},
		ConfigState:   map[string]string{"enforce": "1", "base_domain": "example.com"},
		DaemonVersion: "v0.28.0",
		Now:           now,
	})
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}

	// No signer → unsigned but still a complete measurement.
	if m.Signed {
		t.Errorf("expected unsigned measurement, got Signed=true")
	}
	if m.Signature != "" {
		t.Errorf("expected empty signature, got %q", m.Signature)
	}

	// Binary digest matches a direct sha256 of the file bytes.
	wantBin := sha256.Sum256([]byte("daemon-bytes"))
	if m.BinaryDigest != hex.EncodeToString(wantBin[:]) {
		t.Errorf("binary digest mismatch: got %s", m.BinaryDigest)
	}
	if len(m.ProgramDigests) != 1 || m.ProgramDigests[0].Name != "policy.o" {
		t.Fatalf("expected 1 program digest named policy.o, got %+v", m.ProgramDigests)
	}
	wantProg := sha256.Sum256([]byte("ebpf-object-bytes"))
	if m.ProgramDigests[0].Digest != hex.EncodeToString(wantProg[:]) {
		t.Errorf("program digest mismatch: got %s", m.ProgramDigests[0].Digest)
	}
	if m.MeasurementDigest == "" || m.ConfigDigest == "" {
		t.Errorf("expected non-empty measurement/config digests")
	}
	if m.HashAlgorithm != HashAlgorithm {
		t.Errorf("hash algorithm: got %s want %s", m.HashAlgorithm, HashAlgorithm)
	}
}

func TestCompute_Deterministic(t *testing.T) {
	bin := writeTemp(t, "daemon", []byte("x"))
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	in := Inputs{
		BinaryPath:    bin,
		ConfigState:   map[string]string{"a": "1", "b": "2"},
		DaemonVersion: "v1",
		Now:           now,
	}
	m1, err := Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	if m1.MeasurementDigest != m2.MeasurementDigest {
		t.Errorf("measurement digest not deterministic: %s vs %s", m1.MeasurementDigest, m2.MeasurementDigest)
	}

	// Config map ordering must not affect the config digest.
	in.ConfigState = map[string]string{"b": "2", "a": "1"}
	m3, err := Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	if m3.ConfigDigest != m1.ConfigDigest {
		t.Errorf("config digest depends on map ordering: %s vs %s", m3.ConfigDigest, m1.ConfigDigest)
	}
}

func TestCompute_ProgramDigestsSorted(t *testing.T) {
	bin := writeTemp(t, "daemon", []byte("x"))
	p1 := writeTemp(t, "zeta.o", []byte("z"))
	p2 := writeTemp(t, "alpha.o", []byte("a"))
	m, err := Compute(Inputs{
		BinaryPath: bin,
		Programs: []ProgramObject{
			{Name: "zeta.o", Path: p1},
			{Name: "alpha.o", Path: p2},
		},
		Now: time.Unix(0, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.ProgramDigests) != 2 {
		t.Fatalf("expected 2 program digests, got %d", len(m.ProgramDigests))
	}
	if m.ProgramDigests[0].Name != "alpha.o" || m.ProgramDigests[1].Name != "zeta.o" {
		t.Errorf("program digests not sorted by name: %+v", m.ProgramDigests)
	}
}

func TestCompute_Signed_VerifiesECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bin := writeTemp(t, "daemon", []byte("signed-daemon"))

	m, err := Compute(Inputs{
		BinaryPath:    bin,
		DaemonVersion: "v1",
		Signer:        key,
		Now:           time.Unix(0, 0),
	})
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !m.Signed {
		t.Fatalf("expected Signed=true")
	}
	if m.SignatureAlgorithm != SignatureAlgorithmECDSAP256SHA256 {
		t.Errorf("signature algorithm: got %q", m.SignatureAlgorithm)
	}

	// The signature must verify over the SHA-256 of the canonical bytes, which
	// equals the bytes the measurement_digest covers. A verifier reconstructs
	// the canonical bytes from the component fields.
	canonical := canonicalBytes(m)
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) != m.MeasurementDigest {
		t.Fatalf("measurement digest does not match canonical bytes")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, sum[:], sig) {
		t.Errorf("ECDSA signature did not verify")
	}
}

func TestCompute_TamperBreaksSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bin := writeTemp(t, "daemon", []byte("orig"))
	m, err := Compute(Inputs{BinaryPath: bin, Signer: key, Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a verifier that recomputes the canonical bytes after the binary
	// digest is tampered: the signature must no longer verify.
	tampered := m
	tampered.BinaryDigest = "deadbeef"
	sum := sha256.Sum256(canonicalBytes(tampered))
	sig, _ := base64.StdEncoding.DecodeString(m.Signature)
	if ecdsa.VerifyASN1(&key.PublicKey, sum[:], sig) {
		t.Errorf("signature verified over tampered measurement — integrity check is broken")
	}
}

func TestCompute_MissingBinaryErrors(t *testing.T) {
	_, err := Compute(Inputs{BinaryPath: filepath.Join(t.TempDir(), "nope")})
	if err == nil {
		t.Errorf("expected error for missing binary path")
	}
}

// ensure x509 import is exercised (cert parsing not strictly needed here but
// documents that signing_cert_pem is opaque to Compute).
var _ = x509.ParseCertificate
var _ = big.NewInt
