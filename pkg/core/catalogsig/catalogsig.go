// Package catalogsig provides an optional, offline provenance check for
// external skill/crew catalogs loaded from disk (#648). It verifies a detached
// ed25519 signature of each catalog file against a set of operator-configured
// trusted public keys before the file is parsed and merged.
//
// The check is opt-in. When require-signed mode is off (the default), callers
// load catalogs unsigned exactly as before — this is correct for the
// self-authored / BYOA path where the operator points the env var at a
// directory they wrote themselves. The check only matters once a catalog is
// distributed from outside the operator's own tree, where "did this manifest
// come from a source I trust, intact" is a real question.
//
// Verification performs no network I/O: the trusted keys are configured
// locally, so it works for air-gapped installs.
package catalogsig

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Environment variables that configure the provenance check.
const (
	// EnvRequireSigned, when truthy ("1"/"true"/"yes"), turns on require-signed
	// mode: every external catalog file must carry a valid detached signature.
	EnvRequireSigned = "CONTAINARIUM_CATALOG_REQUIRE_SIGNED"
	// EnvTrustedKeys names a file holding the trusted public keys: one
	// base64-encoded ed25519 public key per line, with blank lines and
	// '#'-prefixed comments ignored. At least one key is required when
	// require-signed mode is on.
	EnvTrustedKeys = "CONTAINARIUM_CATALOG_TRUSTED_PUBKEYS"
)

// SigSuffix is appended to a catalog file's name to find its detached
// signature: foo.yaml -> foo.yaml.sig. The .sig file holds the base64-encoded
// raw ed25519 signature (64 bytes) over the exact bytes of the catalog file.
const SigSuffix = ".sig"

// Verifier checks detached ed25519 signatures against a set of trusted public
// keys. The zero value is not usable; build one with FromEnv or LoadVerifier.
type Verifier struct {
	keys []ed25519.PublicKey
}

// NewVerifier builds a Verifier over the given trusted ed25519 public keys.
// It is the programmatic counterpart to LoadVerifier (which reads keys from a
// file); a caller embedding its own trusted keys can use this directly.
func NewVerifier(keys ...ed25519.PublicKey) *Verifier {
	return &Verifier{keys: keys}
}

// FromEnv builds a Verifier from operator configuration.
//
// It returns (nil, nil) when require-signed mode is off — the caller then loads
// catalogs unsigned, exactly as before. When the mode is on, it requires
// EnvTrustedKeys to name a file with at least one valid key, otherwise it
// returns an error so the caller fails closed rather than loading unsigned.
func FromEnv() (*Verifier, error) {
	if !truthy(os.Getenv(EnvRequireSigned)) {
		return nil, nil
	}
	path := os.Getenv(EnvTrustedKeys)
	if path == "" {
		return nil, fmt.Errorf("%s is on but %s names no trusted public-key file", EnvRequireSigned, EnvTrustedKeys)
	}
	return LoadVerifier(path)
}

// LoadVerifier reads trusted ed25519 public keys from path (one base64 key per
// line; blanks and '#' comments ignored) and returns a Verifier over them.
func LoadVerifier(path string) (*Verifier, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trusted catalog keys %q: %w", path, err)
	}
	var keys []ed25519.PublicKey
	sc := bufio.NewScanner(bytes.NewReader(data))
	for line := 1; sc.Scan(); line++ {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		key, err := DecodePublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, line, err)
		}
		keys = append(keys, key)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read trusted catalog keys %q: %w", path, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("trusted catalog keys file %q has no usable keys", path)
	}
	return &Verifier{keys: keys}, nil
}

// Verify reports whether sig is a valid ed25519 signature of data under any of
// the trusted keys. It returns nil on success and a descriptive error otherwise.
func (v *Verifier) Verify(data, sig []byte) error {
	if v == nil {
		return fmt.Errorf("no verifier configured")
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	for _, k := range v.keys {
		if ed25519.Verify(k, data, sig) {
			return nil
		}
	}
	return fmt.Errorf("no trusted key verifies this signature")
}

// ReadDetachedSig reads and base64-decodes the detached signature sitting next
// to a catalog file (catalogPath + SigSuffix). A missing or malformed signature
// is a hard error — the load must not silently skip it.
func ReadDetachedSig(catalogPath string) ([]byte, error) {
	sigPath := catalogPath + SigSuffix
	raw, err := os.ReadFile(sigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("missing detached signature %q (require-signed mode is on)", sigPath)
		}
		return nil, fmt.Errorf("read signature %q: %w", sigPath, err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode signature %q: %w", sigPath, err)
	}
	return sig, nil
}

// DecodePublicKey decodes a base64-encoded ed25519 public key.
func DecodePublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
