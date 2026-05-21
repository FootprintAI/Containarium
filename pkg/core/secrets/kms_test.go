package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// Phase 4.1 Phase-A — InProcKMS wrap/unwrap symmetry +
// edge-case rejections.

func makeMasterKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, MasterKeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestInProcKMS_WrapUnwrapSymmetry(t *testing.T) {
	mk := makeMasterKey(t)
	kms, err := NewInProcKMS(mk)
	if err != nil {
		t.Fatalf("NewInProcKMS: %v", err)
	}

	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	if len(dek) != DEKSize {
		t.Fatalf("DEK size = %d; want %d", len(dek), DEKSize)
	}

	wrapped, kekID, err := kms.Wrap(context.Background(), dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if kekID != inprocKEKID {
		t.Fatalf("kekID = %q; want %q", kekID, inprocKEKID)
	}

	unwrapped, err := kms.Unwrap(context.Background(), wrapped, kekID)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatal("round-trip altered the DEK")
	}
}

func TestInProcKMS_RejectsWrongKEKID(t *testing.T) {
	kms, _ := NewInProcKMS(makeMasterKey(t))
	dek, _ := NewDEK()
	wrapped, _, _ := kms.Wrap(context.Background(), dek)

	_, err := kms.Unwrap(context.Background(), wrapped, "gcp-kms:projects/x/keys/y")
	if err == nil {
		t.Fatal("InProcKMS must refuse to unwrap a row addressed to a different KMS")
	}
}

func TestInProcKMS_RejectsWrongDEKSize(t *testing.T) {
	kms, _ := NewInProcKMS(makeMasterKey(t))
	cases := [][]byte{
		nil,
		make([]byte, 16), // half size
		make([]byte, 64), // double size
	}
	for _, c := range cases {
		_, _, err := kms.Wrap(context.Background(), c)
		if err == nil {
			t.Fatalf("Wrap should reject DEK of size %d", len(c))
		}
	}
}

func TestInProcKMS_RejectsTamperedCiphertext(t *testing.T) {
	kms, _ := NewInProcKMS(makeMasterKey(t))
	dek, _ := NewDEK()
	wrapped, kekID, _ := kms.Wrap(context.Background(), dek)

	// Flip a byte in the ciphertext portion (after the
	// 12-byte nonce prefix).
	tampered := make([]byte, len(wrapped))
	copy(tampered, wrapped)
	tampered[NonceSize+1] ^= 0x01

	_, err := kms.Unwrap(context.Background(), tampered, kekID)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered ciphertext: got %v want ErrAuthentication", err)
	}
}

func TestInProcKMS_DifferentDeploymentsCannotCrossDecrypt(t *testing.T) {
	// Two different master keys (two daemon deployments).
	// A row wrapped under one cannot be unwrapped under
	// the other.
	a, _ := NewInProcKMS(makeMasterKey(t))
	b, _ := NewInProcKMS(makeMasterKey(t))

	dek, _ := NewDEK()
	wrapped, kekID, _ := a.Wrap(context.Background(), dek)
	if _, err := b.Unwrap(context.Background(), wrapped, kekID); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("cross-deployment unwrap should fail; got %v", err)
	}
}

func TestInProcKMS_RejectsShortWrappedDEK(t *testing.T) {
	kms, _ := NewInProcKMS(makeMasterKey(t))
	_, err := kms.Unwrap(context.Background(), []byte("too-short"), inprocKEKID)
	if err == nil {
		t.Fatal("short wrapped DEK should be rejected")
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %d; want 0", i, v)
		}
	}
	// nil-safe (don't panic).
	ZeroBytes(nil)
}

func TestNewDEK_FreshEachCall(t *testing.T) {
	a, _ := NewDEK()
	b, _ := NewDEK()
	if bytes.Equal(a, b) {
		t.Fatal("two NewDEK calls produced the same key — crypto/rand isn't")
	}
}

// KMSClient interface conformance: InProcKMS satisfies the
// contract. Compile-time check via a typed nil — if the
// interface method set drifts, this won't compile.
var _ KMSClient = (*InProcKMS)(nil)
