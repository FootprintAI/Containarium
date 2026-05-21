package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Phase 4.1 Phase-A — KMS envelope-encryption interface +
// in-process no-op impl. Audit C-HIGH-6. See
// docs/security/KMS-ENVELOPE-DESIGN.md for the threat
// model and the multi-phase rollout plan.
//
// THIS PR INTRODUCES THE INTERFACE ONLY. No callers wire
// it yet — the existing Cipher path remains the canonical
// encrypt/decrypt route. Subsequent phases wire envelope
// rows alongside the legacy ciphertext (Phase B), add
// real KMS backends (Phase C), and eventually retire the
// master key (Phase E).
//
// Wire shape: every secret carries a per-row Data
// Encryption Key (DEK). The DEK encrypts the plaintext via
// AES-GCM the same way the master key does today. The
// KMSClient.Wrap call encrypts the DEK under the
// KMS-resident Key Encryption Key (KEK). Storage holds
// (ciphertext, wrapped_dek, kek_id). On read, KMSClient.Unwrap
// turns the wrapped DEK back into a plaintext DEK in
// daemon memory; the daemon decrypts the value and zeroes
// the DEK before returning.

// KMSClient is the narrow envelope-encryption interface
// the Store talks to. Implementations:
//
//   - kms_inproc.go (this file): no-op shim using the
//     existing master key. Default for backwards compat;
//     gets the schema migration in place without changing
//     the cryptographic protection.
//   - kms_gcp.go (future): GCP KMS via cloudkms.v1.
//   - kms_vault.go (future): Vault Transit secret engine.
//   - kms_aws.go (future): AWS KMS.
//
// The interface is intentionally tight: just Wrap and
// Unwrap. Backends that need more state (versioning,
// rotation hints) carry it inside the implementation, not
// the contract.
type KMSClient interface {
	// Wrap encrypts a plaintext Data Encryption Key (DEK)
	// under the KMS-resident Key Encryption Key (KEK).
	// Returns the wrapped DEK and the KEK identifier
	// (provider-specific — for GCP KMS it's the full
	// resource name; for the inproc impl it's a sentinel).
	// The wrapped DEK lands in the secrets row alongside
	// the ciphertext.
	Wrap(ctx context.Context, plaintextDEK []byte) (wrappedDEK []byte, kekID string, err error)

	// Unwrap reverses Wrap. The kekID is the value returned
	// by the original Wrap call — implementations use it to
	// pick the right key version on the backend. Returns
	// the plaintext DEK; callers MUST zero it after use.
	Unwrap(ctx context.Context, wrappedDEK []byte, kekID string) (plaintextDEK []byte, err error)
}

// DEKSize is the size of a Data Encryption Key. AES-256
// matches the existing master-key path.
const DEKSize = 32

// inprocKEKID is the sentinel kek_id stored by the in-
// process KMS. Future per-row reads use this to route to
// the inproc Unwrap; real KMS rows carry a real resource
// path.
const inprocKEKID = "inproc:master"

// InProcKMS is the no-op envelope backend. It wraps DEKs
// using the daemon's existing master key with AES-GCM.
// Cryptographically equivalent to the legacy single-key
// path — the protection level is the same, the storage
// shape is just one indirection longer. The point is to
// land the schema and the Store-side plumbing without
// changing the threat model; switching to a real KMS later
// is then a configuration change, not a code change at
// every callsite.
type InProcKMS struct {
	aead cipher.AEAD
}

// NewInProcKMS builds an InProcKMS from the daemon's
// master key (the same 32-byte key Cipher uses). The KMS
// uses a different AEAD instance than Cipher so that even
// a future bug in one path can't pollute the other.
func NewInProcKMS(masterKey []byte) (*InProcKMS, error) {
	if len(masterKey) != MasterKeySize {
		return nil, ErrKeyWrongSize
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return &InProcKMS{aead: aead}, nil
}

// Wrap encrypts the DEK under the master key with a fresh
// nonce. The output bytes are nonce || ciphertext-with-
// tag, so Unwrap doesn't need to know the nonce
// separately. Phase-A simplicity; Phase-B+ may attach
// versioning bytes via a TLV envelope.
func (k *InProcKMS) Wrap(_ context.Context, plaintextDEK []byte) ([]byte, string, error) {
	if len(plaintextDEK) != DEKSize {
		return nil, "", fmt.Errorf("DEK must be %d bytes; got %d", DEKSize, len(plaintextDEK))
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", fmt.Errorf("generate wrap nonce: %w", err)
	}
	// Use the literal kek-id as AAD so a wrapped DEK can't
	// be replayed under a different KMS backend's row.
	wrapped := k.aead.Seal(nil, nonce, plaintextDEK, []byte(inprocKEKID))
	// Prepend the nonce so Unwrap doesn't need it
	// separately. Layout: [12-byte nonce][ciphertext+tag].
	out := make([]byte, 0, NonceSize+len(wrapped))
	out = append(out, nonce...)
	out = append(out, wrapped...)
	return out, inprocKEKID, nil
}

// Unwrap reverses Wrap. The kekID must match the sentinel
// or we refuse — that's how Phase-B+ readers know not to
// route a real-KMS row through the inproc backend by
// mistake.
func (k *InProcKMS) Unwrap(_ context.Context, wrappedDEK []byte, kekID string) ([]byte, error) {
	if kekID != inprocKEKID {
		return nil, fmt.Errorf("InProcKMS: refusing to unwrap row whose kek_id=%q (not %q)", kekID, inprocKEKID)
	}
	if len(wrappedDEK) < NonceSize+1 {
		return nil, errors.New("InProcKMS: wrapped DEK too short")
	}
	nonce := wrappedDEK[:NonceSize]
	ct := wrappedDEK[NonceSize:]
	pt, err := k.aead.Open(nil, nonce, ct, []byte(inprocKEKID))
	if err != nil {
		return nil, ErrAuthentication
	}
	if len(pt) != DEKSize {
		// Shouldn't happen — every Wrap input is DEKSize —
		// but a malformed row from a future bug shouldn't
		// quietly truncate.
		return nil, fmt.Errorf("InProcKMS: unwrapped DEK has %d bytes; want %d", len(pt), DEKSize)
	}
	return pt, nil
}

// NewDEK generates a 32-byte Data Encryption Key from
// crypto/rand. Used at every Set call before the KMS Wrap.
// Caller MUST zero the returned slice after use.
func NewDEK() ([]byte, error) {
	dek := make([]byte, DEKSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}
	return dek, nil
}

// ZeroBytes overwrites the slice in place. Defense-in-
// depth — the Go garbage collector may relocate the
// backing array, but explicit zero closes the easy
// memory-inspection paths.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
