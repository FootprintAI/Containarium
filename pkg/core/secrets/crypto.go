// Package secrets implements the daemon-side cryptographic primitives
// for storing and retrieving tenant secrets per the design in
// docs/SECRETS-MANAGEMENT-DESIGN.md.
//
// The encryption scheme is AES-256-GCM. Each secret is encrypted
// under the daemon's master key with a fresh 12-byte random nonce.
// The tuple (username, name) is bound to the ciphertext as
// Additional Authenticated Data (AAD), so a row exfiltrated from
// Postgres and replayed under a different name fails the GCM
// authentication tag at decrypt time.
//
// This package contains pure crypto and keyfile loading — no
// network, no database, no daemon coupling. It's importable from
// tests and from the future server implementation without dragging
// either layer's deps in.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
)

const (
	// MasterKeySize is the required size of the master key file.
	// AES-256 keys are 32 bytes.
	MasterKeySize = 32

	// NonceSize is the AES-GCM standard 12-byte nonce.
	NonceSize = 12

	// MaxValueSize is the hard cap on the plaintext value per
	// design doc decision #2 (64 KiB).
	MaxValueSize = 64 * 1024

	// MaxNameLength is the hard cap on secret names per design
	// doc decision #1.
	MaxNameLength = 128

	// MasterKeyFileMode is the on-disk mode the keyfile is
	// created with (root-only read).
	MasterKeyFileMode = 0o400
)

// nameRE matches the env-var-compatible name pattern from design
// doc decision #1. Compiled once at package init.
var nameRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// Errors callers can match on.
var (
	ErrInvalidName     = errors.New("secrets: name must match ^[A-Z_][A-Z0-9_]*$ and be at most 128 chars")
	ErrValueTooLarge   = errors.New("secrets: value exceeds 64 KiB limit")
	ErrKeyWrongSize    = errors.New("secrets: master key must be exactly 32 bytes")
	ErrAuthentication  = errors.New("secrets: ciphertext authentication failed (tampered or wrong key?)")
)

// ValidateName returns nil if the name matches the env-var-compatible
// pattern and length cap. Used at the API boundary before any storage
// touches.
func ValidateName(name string) error {
	if len(name) == 0 || len(name) > MaxNameLength {
		return ErrInvalidName
	}
	if !nameRE.MatchString(name) {
		return ErrInvalidName
	}
	return nil
}

// ValidateValue returns nil if the value is within the 64 KiB cap.
// Empty values are valid — operators sometimes "set to empty" as a
// soft-delete that keeps the env var present but blank.
func ValidateValue(value string) error {
	if len(value) > MaxValueSize {
		return ErrValueTooLarge
	}
	return nil
}

// LoadOrCreateMasterKey reads the 32-byte master key from the given
// path. If the file doesn't exist, it generates a fresh key from
// crypto/rand, writes it at mode 0400, and returns the new key.
//
// The "fresh on first start" behavior implements design-doc decision
// #5; callers must log a loud back-it-up warning when the file is
// newly created so operators know to copy it off-host.
//
// Audit C-HIGH-6: before returning the key, stat the file and refuse
// if any non-owner permission bit is set. The key was originally
// written with mode 0400, but umask drift, ownership change, or
// backup-tool side effects can widen permissions silently — leaving
// the master key readable by anyone who can land on the host.
// Fail-closed at startup is the only way operators see the
// regression.
//
// Returns (key, created, err) — created=true means the file did not
// exist and a new key was written.
func LoadOrCreateMasterKey(path string) (key []byte, created bool, err error) {
	if info, statErr := os.Stat(path); statErr == nil {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, false, fmt.Errorf("master key %s has insecure permissions %#o (any non-owner read/write/exec bit set); chmod 0400 it and ensure root ownership", path, perm)
		}
		data, readErr := os.ReadFile(path) // #nosec G304 -- operator-controlled config path
		if readErr != nil {
			return nil, false, fmt.Errorf("read master key at %s: %w", path, readErr)
		}
		if len(data) != MasterKeySize {
			return nil, false, fmt.Errorf("%w (file %s has %d bytes)", ErrKeyWrongSize, path, len(data))
		}
		return data, false, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, false, fmt.Errorf("stat master key at %s: %w", path, statErr)
	}

	newKey := make([]byte, MasterKeySize)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, false, fmt.Errorf("generate master key: %w", err)
	}
	if err := os.WriteFile(path, newKey, MasterKeyFileMode); err != nil {
		return nil, false, fmt.Errorf("write master key at %s: %w", path, err)
	}
	return newKey, true, nil
}

// Cipher wraps the AES-GCM AEAD for repeated use. Construct once
// per daemon startup and reuse for every Encrypt / Decrypt call.
//
// The Go cipher.AEAD interface is safe for concurrent use, so a
// single Cipher is fine across goroutines.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher builds a Cipher from a 32-byte master key.
func NewCipher(masterKey []byte) (*Cipher, error) {
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
	return &Cipher{aead: aead}, nil
}

// Encrypt seals plaintext under the master key with a fresh random
// nonce, binding (username, name) as Additional Authenticated Data.
//
// Returns (nonce, ciphertext_with_tag, err). Both bytes are stored
// in the secrets row; decrypt reads them back and re-derives the
// AAD from the same (username, name).
func (c *Cipher) Encrypt(username, name string, plaintext []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}
	aad := buildAAD(username, name)
	ciphertext = c.aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// Decrypt verifies and opens the ciphertext under the master key
// with (username, name) as AAD. Returns ErrAuthentication if the
// GCM tag fails to verify — that's the signal that either the
// master key is wrong, the ciphertext was tampered with, or the
// (username, name) doesn't match what was encrypted.
func (c *Cipher) Decrypt(username, name string, nonce, ciphertext []byte) (plaintext []byte, err error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}
	aad := buildAAD(username, name)
	pt, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// crypto/cipher returns a generic error for any auth
		// failure; normalize to our sentinel so callers can
		// match.
		return nil, ErrAuthentication
	}
	return pt, nil
}

// buildAAD concatenates username + 0x00 + name as the AAD. The
// null separator prevents the trick where ("alice", "X_KEY") and
// ("aliceX", "_KEY") would otherwise produce the same concatenation.
func buildAAD(username, name string) []byte {
	out := make([]byte, 0, len(username)+1+len(name))
	out = append(out, username...)
	out = append(out, 0x00)
	out = append(out, name...)
	return out
}
