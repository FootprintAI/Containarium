package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
)

// Phase 4.1 Phase-B — unit tests for the per-row dispatch
// logic in encryptForStorage / decryptFromStorage. These
// avoid the Postgres dependency so they run in CI; the
// SQL-roundtrip integration test stays skip-by-default.

func newCipher(t *testing.T) *corecrypto.Cipher {
	t.Helper()
	mk := make([]byte, corecrypto.MasterKeySize)
	if _, err := io.ReadFull(rand.Reader, mk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	c, err := corecrypto.NewCipher(mk)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func newKMS(t *testing.T) corecrypto.KMSClient {
	t.Helper()
	mk := make([]byte, corecrypto.MasterKeySize)
	if _, err := io.ReadFull(rand.Reader, mk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	k, err := corecrypto.NewInProcKMS(mk)
	if err != nil {
		t.Fatalf("NewInProcKMS: %v", err)
	}
	return k
}

// --- Legacy mode (no KMS) ---

func TestEncryptForStorage_LegacyOmitsEnvelopeColumns(t *testing.T) {
	s := &Store{cipher: newCipher(t)}
	nonce, ct, wrapped, kekID, err := s.encryptForStorage(
		context.Background(), "alice", "FOO", []byte("plaintext"),
	)
	if err != nil {
		t.Fatalf("encryptForStorage: %v", err)
	}
	if len(nonce) == 0 || len(ct) == 0 {
		t.Fatal("legacy mode should produce nonce+ciphertext")
	}
	if wrapped != nil {
		t.Fatalf("legacy mode should leave wrapped_dek nil; got %d bytes", len(wrapped))
	}
	if kekID != "" {
		t.Fatalf("legacy mode should leave kek_id empty; got %q", kekID)
	}
}

func TestDecryptFromStorage_LegacyRoundtrip(t *testing.T) {
	s := &Store{cipher: newCipher(t)}
	plaintext := []byte("hello-legacy")

	nonce, ct, wrapped, kekID, err := s.encryptForStorage(
		context.Background(), "alice", "FOO", plaintext,
	)
	if err != nil {
		t.Fatalf("encryptForStorage: %v", err)
	}

	out, err := s.decryptFromStorage(context.Background(), "alice", "FOO", nonce, ct, wrapped, kekID)
	if err != nil {
		t.Fatalf("decryptFromStorage: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("roundtrip altered plaintext: got %q want %q", out, plaintext)
	}
}

// --- Envelope mode (with KMS) ---

func TestEncryptForStorage_EnvelopeProducesAllColumns(t *testing.T) {
	s := &Store{cipher: newCipher(t), kms: newKMS(t)}
	nonce, ct, wrapped, kekID, err := s.encryptForStorage(
		context.Background(), "alice", "FOO", []byte("plaintext"),
	)
	if err != nil {
		t.Fatalf("encryptForStorage: %v", err)
	}
	if len(nonce) == 0 || len(ct) == 0 {
		t.Fatal("envelope mode should still produce nonce+ciphertext (DEK-encrypted)")
	}
	if len(wrapped) == 0 {
		t.Fatal("envelope mode should populate wrapped_dek")
	}
	if kekID == "" {
		t.Fatal("envelope mode should populate kek_id")
	}
}

func TestDecryptFromStorage_EnvelopeRoundtrip(t *testing.T) {
	s := &Store{cipher: newCipher(t), kms: newKMS(t)}
	plaintext := []byte("hello-envelope")

	nonce, ct, wrapped, kekID, err := s.encryptForStorage(
		context.Background(), "alice", "FOO", plaintext,
	)
	if err != nil {
		t.Fatalf("encryptForStorage: %v", err)
	}

	out, err := s.decryptFromStorage(context.Background(), "alice", "FOO", nonce, ct, wrapped, kekID)
	if err != nil {
		t.Fatalf("decryptFromStorage: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("envelope roundtrip altered plaintext: got %q want %q", out, plaintext)
	}
}

// --- Mixed-state DB: legacy rows decrypt without KMS ---

func TestDecryptFromStorage_LegacyRowOnEnvelopeStore(t *testing.T) {
	// Write a legacy row (no KMS); then read it through a
	// Store that DOES have a KMS configured. This is the
	// mixed-state case after a deployment enables KMS but
	// before migration runs.
	legacy := &Store{cipher: newCipher(t)}
	plaintext := []byte("mixed-state-legacy")
	nonce, ct, wrapped, kekID, _ := legacy.encryptForStorage(
		context.Background(), "alice", "FOO", plaintext,
	)
	if wrapped != nil {
		t.Fatal("setup: legacy write should not produce wrapped_dek")
	}

	withKMS := &Store{cipher: legacy.cipher, kms: newKMS(t)}
	out, err := withKMS.decryptFromStorage(context.Background(), "alice", "FOO", nonce, ct, wrapped, kekID)
	if err != nil {
		t.Fatalf("legacy row on envelope-enabled Store should still decrypt; got %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatal("roundtrip altered plaintext")
	}
}

// --- Failure: envelope row read by KMS-less Store ---

func TestDecryptFromStorage_EnvelopeRowOnLegacyStoreRejected(t *testing.T) {
	// Write an envelope row with KMS, then try to read it
	// with a Store that has no KMS configured. The expected
	// failure mode is "KMS missing" rather than silent
	// decrypt-as-legacy garbage.
	withKMS := &Store{cipher: newCipher(t), kms: newKMS(t)}
	nonce, ct, wrapped, kekID, _ := withKMS.encryptForStorage(
		context.Background(), "alice", "FOO", []byte("x"),
	)

	noKMS := &Store{cipher: withKMS.cipher} // no kms
	_, err := noKMS.decryptFromStorage(context.Background(), "alice", "FOO", nonce, ct, wrapped, kekID)
	if err == nil {
		t.Fatal("envelope row on no-KMS Store must fail, not silently mis-decrypt")
	}
}

// --- WithKMS option behavior ---

func TestWithKMS_NilIsNoOp(t *testing.T) {
	s := &Store{cipher: newCipher(t)}
	WithKMS(nil)(s)
	if s.kms != nil {
		t.Fatal("WithKMS(nil) should leave kms unset")
	}
}

func TestWithKMS_NonNilSets(t *testing.T) {
	s := &Store{cipher: newCipher(t)}
	k := newKMS(t)
	WithKMS(k)(s)
	if s.kms == nil {
		t.Fatal("WithKMS(non-nil) should populate kms")
	}
}

// --- AAD binding: envelope cipher is DEK-encrypted, must
// still bind (username, name) so swapping the row to a
// different name fails. ---

func TestEnvelope_AADBindingPreserved(t *testing.T) {
	s := &Store{cipher: newCipher(t), kms: newKMS(t)}
	plaintext := []byte("aad-test")
	nonce, ct, wrapped, kekID, _ := s.encryptForStorage(
		context.Background(), "alice", "FOO", plaintext,
	)

	// Try to decrypt the SAME ciphertext under a different
	// (username, name). The DEK is valid, but the GCM AAD
	// won't match — must fail.
	_, err := s.decryptFromStorage(context.Background(), "bob", "FOO", nonce, ct, wrapped, kekID)
	if err == nil {
		t.Fatal("swapping the row to a different username must fail AAD check")
	}
	_, err = s.decryptFromStorage(context.Background(), "alice", "BAR", nonce, ct, wrapped, kekID)
	if err == nil {
		t.Fatal("swapping the row to a different name must fail AAD check")
	}
}
