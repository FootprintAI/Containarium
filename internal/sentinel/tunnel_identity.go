package sentinel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TunnelPinPrefix is the algorithm tag every TunnelPin starts with.
const TunnelPinPrefix = "sha256:"

// tunnelIdentityCommonName is the fixed subject of every tunnel identity
// certificate. The subject carries no trust: peers are authenticated by the
// SPKI pin alone.
const tunnelIdentityCommonName = "containarium-sentinel-tunnel"

// tunnelIdentityValidity is the validity window written into the
// self-signed certificate. Pin verification ignores it; it only needs to be
// a well-formed range for TLS stacks that parse the certificate.
const tunnelIdentityValidity = 100 * 365 * 24 * time.Hour

// TunnelPin is a public-key pin of the form "sha256:<64 lowercase hex>",
// the SHA-256 digest of a certificate's DER-encoded SubjectPublicKeyInfo.
// Values are produced by TunnelIdentity.Pin or ParsePins; both normalise to
// lowercase so pins compare with ==.
type TunnelPin string

// TunnelIdentity is a long-lived ECDSA P-256 key and a self-signed
// certificate over it, presented by the sentinel's tunnel endpoint and
// pinned by clients via its TunnelPin.
type TunnelIdentity struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// GenerateTunnelIdentity creates a fresh ECDSA P-256 key and a self-signed
// certificate for it.
func GenerateTunnelIdentity() (*TunnelIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate tunnel identity key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate tunnel identity serial: %w", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: tunnelIdentityCommonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(tunnelIdentityValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create tunnel identity certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse tunnel identity certificate: %w", err)
	}
	return &TunnelIdentity{key: key, cert: cert}, nil
}

// LoadTunnelIdentity reads an identity written by Save. The file must hold
// exactly one CERTIFICATE block and one PKCS#8 PRIVATE KEY block whose
// public key matches the certificate. A missing file yields an error for
// which os.IsNotExist reports true.
func LoadTunnelIdentity(path string) (*TunnelIdentity, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured identity file path, read by the service that owns it
	if err != nil {
		return nil, err
	}
	var certDER, keyDER []byte
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if certDER != nil {
				return nil, fmt.Errorf("tunnel identity %s: more than one certificate", path)
			}
			certDER = block.Bytes
		case "PRIVATE KEY":
			if keyDER != nil {
				return nil, fmt.Errorf("tunnel identity %s: more than one private key", path)
			}
			keyDER = block.Bytes
		default:
			return nil, fmt.Errorf("tunnel identity %s: unexpected PEM block %q", path, block.Type)
		}
	}
	if certDER == nil || keyDER == nil {
		return nil, fmt.Errorf("tunnel identity %s: need one CERTIFICATE and one PRIVATE KEY block", path)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("tunnel identity %s: parse certificate: %w", path, err)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("tunnel identity %s: parse private key: %w", path, err)
	}
	key, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("tunnel identity %s: private key is not ECDSA P-256", path)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("tunnel identity %s: private key does not match certificate", path)
	}
	return &TunnelIdentity{key: key, cert: cert}, nil
}

// LoadOrGenerateTunnelIdentity loads the identity at path, or generates and
// saves a new one when the file does not exist. generated reports which
// happened. A file that exists but cannot be loaded is an error and is left
// untouched: replacing it would silently invalidate every client's pin.
func LoadOrGenerateTunnelIdentity(path string) (id *TunnelIdentity, generated bool, err error) {
	id, err = LoadTunnelIdentity(path)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	id, err = GenerateTunnelIdentity()
	if err != nil {
		return nil, false, err
	}
	if err := id.Save(path); err != nil {
		return nil, false, err
	}
	return id, true, nil
}

// marshalPEM encodes the certificate followed by the PKCS#8 private key.
func (id *TunnelIdentity) marshalPEM() ([]byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(id.key)
	if err != nil {
		return nil, fmt.Errorf("marshal tunnel identity key: %w", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: id.cert.Raw}); err != nil {
		return nil, err
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Save writes the identity to path with mode 0600, creating the parent
// directory (0700) if needed. The write goes through a temporary file in the
// same directory and a rename, so a crash never leaves a truncated identity
// and an existing file with looser permissions is replaced, not reused.
func (id *TunnelIdentity) Save(path string) error {
	data, err := id.marshalPEM()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create tunnel identity directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tunnel-identity-*.tmp")
	if err != nil {
		return fmt.Errorf("create tunnel identity temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod tunnel identity temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write tunnel identity: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync tunnel identity: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tunnel identity temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install tunnel identity: %w", err)
	}
	return nil
}

// Pin returns the identity's public-key pin.
func (id *TunnelIdentity) Pin() TunnelPin {
	return pinForSPKI(id.cert.RawSubjectPublicKeyInfo)
}

// TLSCertificate returns the identity in the form tls.Config.Certificates
// expects.
func (id *TunnelIdentity) TLSCertificate() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{id.cert.Raw},
		PrivateKey:  id.key,
		Leaf:        id.cert,
	}
}

func pinForSPKI(spki []byte) TunnelPin {
	sum := sha256.Sum256(spki)
	return TunnelPin(TunnelPinPrefix + hex.EncodeToString(sum[:]))
}

// parsePin validates and normalises a single pin.
func parsePin(s string) (TunnelPin, error) {
	digest, ok := strings.CutPrefix(s, TunnelPinPrefix)
	if !ok {
		return "", fmt.Errorf("tunnel pin %q: must start with %q", s, TunnelPinPrefix)
	}
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("tunnel pin %q: digest must be %d hex characters", s, 2*sha256.Size)
	}
	return TunnelPin(TunnelPinPrefix + hex.EncodeToString(raw)), nil
}

// ParsePins parses a comma-separated list of pins, as accepted by a tunnel
// client during key rotation (old and new pin both trusted). Surrounding
// whitespace is ignored, hex is normalised to lowercase and duplicates are
// dropped. An empty list, an empty entry, or any malformed entry is an
// error.
func ParsePins(s string) ([]TunnelPin, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("tunnel pin list is empty")
	}
	parts := strings.Split(s, ",")
	pins := make([]TunnelPin, 0, len(parts))
	seen := make(map[TunnelPin]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("tunnel pin list %q has an empty entry", s)
		}
		pin, err := parsePin(part)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[pin]; dup {
			continue
		}
		seen[pin] = struct{}{}
		pins = append(pins, pin)
	}
	return pins, nil
}

// VerifyPinned returns a tls.Config.VerifyPeerCertificate callback that
// accepts the peer only if the SubjectPublicKeyInfo of its leaf certificate
// matches one of pins. Certificate validity dates, subject, issuer and any
// further chain entries are ignored: the pin authenticates a key, not a
// WebPKI certificate. An empty pin set rejects every peer.
func VerifyPinned(pins []TunnelPin) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	want := append([]TunnelPin(nil), pins...)
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(want) == 0 {
			return errors.New("tunnel pin verification: no pins configured")
		}
		if len(rawCerts) == 0 {
			return errors.New("tunnel pin verification: peer presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("tunnel pin verification: parse peer certificate: %w", err)
		}
		got := pinForSPKI(leaf.RawSubjectPublicKeyInfo)
		for _, p := range want {
			if subtle.ConstantTimeCompare([]byte(got), []byte(p)) == 1 {
				return nil
			}
		}
		return fmt.Errorf("tunnel pin verification: peer key %s matches no configured pin", got)
	}
}
