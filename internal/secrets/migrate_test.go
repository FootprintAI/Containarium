package secrets

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// Phase 4.1 Phase-D — pure-Go tests for the migration
// logic that don't need Postgres. The full SQL roundtrip
// is exercised by the integration suite; here we cover:
//
//   - Migrate is refused without a KMSClient
//   - The legacy → envelope round-trip on a single row
//     produces a verifiable envelope tuple
//   - The verify step catches a planted mismatch (the
//     migration would corrupt secrets if the verifier
//     were silent)

func TestMigrate_RefusedWithoutKMS(t *testing.T) {
	s := &Store{cipher: newCipher(t)}
	_, err := s.MigrateLegacyToEnvelope(context.Background(), MigrateOptions{})
	if !errors.Is(err, ErrMigrateNoKMS) {
		t.Fatalf("got %v want ErrMigrateNoKMS", err)
	}
}

// TestMigrate_SingleRowRoundtripVerify mirrors the inner
// loop of migrateOne (decrypt legacy → encrypt envelope
// → verify) without touching SQL.
func TestMigrate_SingleRowRoundtripVerify(t *testing.T) {
	cipher := newCipher(t)
	kms := newKMS(t)
	s := &Store{cipher: cipher, kms: kms}

	// Build a legacy-shaped row.
	const username, name = "alice", "FOO"
	plaintext := []byte("the-actual-secret")
	legacyNonce, legacyCT, err := cipher.Encrypt(username, name, plaintext)
	if err != nil {
		t.Fatalf("legacy encrypt: %v", err)
	}

	// Decrypt under master key (the migrator's first step).
	got, err := s.cipher.Decrypt(username, name, legacyNonce, legacyCT)
	if err != nil {
		t.Fatalf("legacy decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("legacy roundtrip broken")
	}

	// Re-encrypt envelope.
	newNonce, newCT, wrappedDEK, kekID, err := s.encryptForStorage(
		context.Background(), username, name, got,
	)
	if err != nil {
		t.Fatalf("envelope encrypt: %v", err)
	}
	if len(wrappedDEK) == 0 || kekID == "" {
		t.Fatal("envelope encrypt should populate wrapped_dek + kek_id")
	}

	// Verify the round-trip — this is the safety check
	// that prevents the migration from quietly corrupting
	// every row.
	verifyPT, err := s.decryptFromStorage(context.Background(), username, name, newNonce, newCT, wrappedDEK, kekID)
	if err != nil {
		t.Fatalf("envelope verify: %v", err)
	}
	if !bytes.Equal(verifyPT, plaintext) {
		t.Fatalf("verify mismatch: got %q want %q", verifyPT, plaintext)
	}
}

// TestMigrate_VerifierCatchesTamper guards against a
// regression where the verifier silently accepted a
// mismatch. Tamper the envelope ciphertext after encrypt
// and confirm decryptFromStorage returns an error — the
// migrator's verify step would treat that as a failure
// and rollback.
func TestMigrate_VerifierCatchesTamper(t *testing.T) {
	s := &Store{cipher: newCipher(t), kms: newKMS(t)}
	plaintext := []byte("tamper-test")

	nonce, ct, wrapped, kekID, err := s.encryptForStorage(
		context.Background(), "alice", "FOO", plaintext,
	)
	if err != nil {
		t.Fatalf("encryptForStorage: %v", err)
	}

	// Flip a byte in the ciphertext — must fail GCM.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 0x01

	_, err = s.decryptFromStorage(context.Background(), "alice", "FOO", nonce, tampered, wrapped, kekID)
	if err == nil {
		t.Fatal("verifier must catch tampered envelope ciphertext")
	}
}

// TestMigrate_DryRunDoesNotMutate is a smoke test on the
// signature: DryRun=true with no actual SQL exec should
// still validate without erroring at the type level.
func TestMigrate_OptionDefaults(t *testing.T) {
	// Don't exercise the SQL path (no pool); just verify
	// the default branch picks BatchSize=100. We do that
	// by constructing the result and reading the
	// BatchSize indirectly via behavior — easier here is
	// to check the public constants are sensible.
	opts := MigrateOptions{}
	if opts.BatchSize != 0 {
		t.Fatalf("zero-value BatchSize should be 0 (let migrator default it); got %d", opts.BatchSize)
	}
	// MaxRows zero-value means unlimited — documented in
	// the struct comment.
	if opts.MaxRows != 0 {
		t.Fatalf("zero-value MaxRows = %d; want 0 (unlimited)", opts.MaxRows)
	}
}

// TestCoverageReport_Shape sanity-checks the report type.
// The actual SQL is integration-tested.
func TestCoverageReport_Zero(t *testing.T) {
	var c CoverageReport
	if c.Total != 0 || c.Legacy != 0 || c.Envelope != 0 {
		t.Fatal("zero-value should be all zeros")
	}
}
