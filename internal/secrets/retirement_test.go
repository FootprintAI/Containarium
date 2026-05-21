package secrets

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// Phase 4.1 Phase-E — master-key retirement gate.

func TestWithRequireEnvelope_DefaultIsOff(t *testing.T) {
	s := &Store{cipher: newCipher(t)}
	if s.requireEnvelope {
		t.Fatal("default requireEnvelope should be false")
	}
}

func TestWithRequireEnvelope_TogglesField(t *testing.T) {
	s := &Store{cipher: newCipher(t)}
	WithRequireEnvelope(true)(s)
	if !s.requireEnvelope {
		t.Fatal("WithRequireEnvelope(true) didn't set the flag")
	}
	WithRequireEnvelope(false)(s)
	if s.requireEnvelope {
		t.Fatal("WithRequireEnvelope(false) didn't clear the flag")
	}
}

func TestRetirement_LegacyRowRejected(t *testing.T) {
	// Build a legacy row, then read it through a Store
	// with requireEnvelope=true. Must fail with a clear
	// "migrate before retiring" message — the operator
	// flipped the gate too early.
	cipher := newCipher(t)
	plaintext := []byte("legacy-secret")
	legacyNonce, legacyCT, err := cipher.Encrypt("alice", "FOO", plaintext)
	if err != nil {
		t.Fatalf("legacy encrypt: %v", err)
	}

	s := &Store{
		cipher:          cipher,
		kms:             newKMS(t),
		requireEnvelope: true,
	}
	_, err = s.decryptFromStorage(context.Background(), "alice", "FOO",
		legacyNonce, legacyCT, nil, "")
	if err == nil {
		t.Fatal("require_envelope=true must reject legacy rows")
	}
	if !strings.Contains(err.Error(), "migrate-to-envelope") {
		t.Fatalf("error should name the recovery procedure; got %v", err)
	}
}

func TestRetirement_EnvelopeRowStillWorks(t *testing.T) {
	// Confirm requireEnvelope doesn't accidentally break
	// the envelope path. Envelope rows must continue to
	// decrypt cleanly.
	s := &Store{
		cipher:          newCipher(t),
		kms:             newKMS(t),
		requireEnvelope: true,
	}
	plaintext := []byte("envelope-secret")
	nonce, ct, wrapped, kekID, err := s.encryptForStorage(
		context.Background(), "alice", "FOO", plaintext,
	)
	if err != nil {
		t.Fatalf("encryptForStorage: %v", err)
	}
	out, err := s.decryptFromStorage(context.Background(), "alice", "FOO",
		nonce, ct, wrapped, kekID)
	if err != nil {
		t.Fatalf("envelope row should still decrypt with require_envelope=true; got %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatal("envelope roundtrip altered plaintext")
	}
}

func TestRetirement_OffAllowsLegacy(t *testing.T) {
	// Sanity check: with the gate OFF, legacy rows still
	// decrypt — the pre-retirement compat behavior is
	// preserved.
	cipher := newCipher(t)
	plaintext := []byte("legacy-secret")
	legacyNonce, legacyCT, _ := cipher.Encrypt("alice", "FOO", plaintext)

	s := &Store{
		cipher:          cipher,
		kms:             newKMS(t),
		requireEnvelope: false, // default
	}
	out, err := s.decryptFromStorage(context.Background(), "alice", "FOO",
		legacyNonce, legacyCT, nil, "")
	if err != nil {
		t.Fatalf("with gate off, legacy decrypts fine; got %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatal("legacy roundtrip altered plaintext")
	}
}
