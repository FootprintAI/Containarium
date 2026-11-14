package sdlcskills

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

//go:embed trusted-keys.pem
var trustedKeysPEM []byte

// Keyring is the set of public keys trusted to sign a skills release.
type Keyring []*ecdsa.PublicKey

// ParseKeyring reads PEM "PUBLIC KEY" blocks (ECDSA P-256, the form `cosign
// public-key` prints). Text outside the blocks is ignored, so the file can
// carry comments. Any other block type, key type or curve is an error: a file
// that was meant to add trust and cannot is not silently dropped. A file with
// no block is valid and trusts nothing.
func ParseKeyring(data []byte) (Keyring, error) {
	var keys Keyring
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("sdlcskills: trusted keys hold a %q block; only PUBLIC KEY is accepted", block.Type)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("sdlcskills: trusted key %d: %w", len(keys)+1, err)
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("sdlcskills: trusted key %d is not an ECDSA P-256 key", len(keys)+1)
		}
		keys = append(keys, key)
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		return nil, errors.New("sdlcskills: trusted keys hold a PEM block that does not decode")
	}
	return keys, nil
}

// TrustedKeys returns the keys this binary was built with.
func TrustedKeys() (Keyring, error) { return ParseKeyring(trustedKeysPEM) }

// TrustedKeysPEM returns the embedded key file as it was built in.
func TrustedKeysPEM() []byte { return append([]byte(nil), trustedKeysPEM...) }

// Verify checks a detached signature over msg: sig holds one signature per
// line, each the base64 of an ASN.1 DER ECDSA signature over SHA-256(msg),
// which is what `cosign sign-blob --key` writes and `openssl dgst -sha256
// -verify` checks. It succeeds when any key verifies any line.
func (k Keyring) Verify(msg, sig []byte) error {
	if len(k) == 0 {
		return errors.New("sdlcskills: no trusted signing key; a skills release cannot be verified")
	}
	sum := sha256.Sum256(msg)
	lines := 0
	for _, line := range strings.Split(string(sig), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines++
		der, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			continue
		}
		for _, key := range k {
			if ecdsa.VerifyASN1(key, sum[:], der) {
				return nil
			}
		}
	}
	if lines == 0 {
		return errors.New("sdlcskills: the signature file is empty")
	}
	return errors.New("sdlcskills: no trusted key verifies the signature")
}
