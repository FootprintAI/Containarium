// Package integrity turns a backend's own runtime state into a signed
// self-measurement that the control plane verifies out of band of the
// backend's normal reporting, to detect tampering of a backend's control
// plane.
//
// The measurement hashes three things:
//   - the running daemon binary on disk,
//   - the loaded in-kernel network-policy program object(s), and
//   - the canonical policy/config state (the integrity-relevant daemon
//     configuration + active network-policy posture).
//
// Those component digests are folded into one canonical byte string, hashed
// once more to a measurement digest, and signed with the node's identity key.
// The signer is supplied by the caller: the daemon reuses the sentinel-issued
// peer leaf private key from the peer-PKI plumbing (TPM-backed when a TPM is
// present, software-signed via the peer key otherwise). When no identity key
// is available the measurement is still produced, just unsigned — the control
// plane treats an unsigned measurement as unverifiable, not as tamper.
//
// The compute here is pure (no proto, no Incus, no filesystem assumptions
// beyond reading the paths the caller hands it) so it is unit-testable in
// isolation; the server gathers the inputs (binary path, program-object
// paths, config snapshot, signer) and maps the result onto the wire type.
// This is the node-side half only; the control plane's verification and
// quarantine logic lives elsewhere. See #683.
package integrity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// HashAlgorithm is the digest algorithm name recorded in the measurement. Only
// sha256 is produced today; the field makes the choice explicit on the wire so
// a future change is unambiguous to the verifier.
const HashAlgorithm = "sha256"

// SignatureAlgorithmECDSAP256SHA256 is the scheme recorded when an ECDSA P-256
// identity key (the sentinel-issued peer leaf) signs the measurement.
const SignatureAlgorithmECDSAP256SHA256 = "ecdsa-p256-sha256"

// ProgramObject identifies one in-kernel program object to digest: a stable
// name (the configured object path) and the path to read its bytes from.
type ProgramObject struct {
	// Name is the stable identifier recorded in the measurement (typically the
	// configured object path itself).
	Name string
	// Path is where to read the object bytes from. When empty, Name is used as
	// the path.
	Path string
}

// Inputs is the snapshot the measurement compute consumes. The caller (the
// daemon) gathers it: the running binary path, the loaded program objects, a
// canonicalizable config-state snapshot, the daemon version, and a signer.
type Inputs struct {
	// BinaryPath is the path to the running daemon binary on disk. Empty skips
	// the binary digest (recorded as empty).
	BinaryPath string

	// Programs are the loaded in-kernel program object(s) to digest. Empty when
	// no program object is configured on this backend.
	Programs []ProgramObject

	// ConfigState is the integrity-relevant policy/config snapshot. It is
	// serialized canonically (sorted keys) before hashing so two daemons with
	// the same posture produce the same digest regardless of map ordering. Nil
	// is treated as an empty object.
	ConfigState map[string]string

	// DaemonVersion is recorded into the measurement.
	DaemonVersion string

	// Signer is the node identity key. When nil the measurement is produced
	// unsigned. Today the daemon passes its sentinel-issued peer leaf key
	// (an *ecdsa.PrivateKey via tls.Certificate.PrivateKey).
	Signer crypto.Signer

	// SigningCertPEM is the PEM of the signing certificate (the peer leaf), so
	// the verifier can check the signature against the sentinel CA without a
	// side lookup. Empty when unsigned or unavailable.
	SigningCertPEM string

	// TPMBacked records whether Signer is a TPM-backed key. The daemon sets this
	// when a TPM provided the key; false means the software peer key signed.
	TPMBacked bool

	// Now is injected so callers/tests can pin the recorded timestamp.
	Now time.Time
}

// ProgramDigest is one program object's identity + digest.
type ProgramDigest struct {
	Name   string
	Digest string
}

// Measurement is the computed, possibly-signed self-measurement. It mirrors
// pb.SelfMeasurement but carries no proto dependency; the server maps it onto
// the wire type.
type Measurement struct {
	HashAlgorithm      string
	BinaryDigest       string
	ProgramDigests     []ProgramDigest
	ConfigDigest       string
	MeasurementDigest  string
	Signature          string
	SignatureAlgorithm string
	TPMBacked          bool
	Signed             bool
	SigningCertPEM     string
	MeasuredAt         time.Time
	DaemonVersion      string
}

// Compute reads the inputs, builds the component digests, folds them into a
// canonical measurement, and signs it when a signer is supplied. Read errors
// on the binary or a program object are returned (a measurement we cannot
// build from real bytes would be misleading); a nil/absent signer is not an
// error — it yields an unsigned measurement.
func Compute(in Inputs) (Measurement, error) {
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	m := Measurement{
		HashAlgorithm: HashAlgorithm,
		DaemonVersion: in.DaemonVersion,
		MeasuredAt:    now.UTC(),
	}

	if in.BinaryPath != "" {
		d, err := digestFile(in.BinaryPath)
		if err != nil {
			return Measurement{}, fmt.Errorf("digest daemon binary %q: %w", in.BinaryPath, err)
		}
		m.BinaryDigest = d
	}

	// Digest each program object, then sort by name for a stable order so the
	// measurement (and its signature) is deterministic regardless of the
	// caller's slice ordering.
	for _, p := range in.Programs {
		path := p.Path
		if path == "" {
			path = p.Name
		}
		d, err := digestFile(path)
		if err != nil {
			return Measurement{}, fmt.Errorf("digest program object %q: %w", p.Name, err)
		}
		m.ProgramDigests = append(m.ProgramDigests, ProgramDigest{Name: p.Name, Digest: d})
	}
	sort.Slice(m.ProgramDigests, func(i, j int) bool {
		return m.ProgramDigests[i].Name < m.ProgramDigests[j].Name
	})

	m.ConfigDigest = digestConfigState(in.ConfigState)

	// Fold the components into the canonical measurement bytes. This is exactly
	// what gets signed and what measurement_digest covers, so the verifier
	// reconstructs the same bytes from the component fields.
	canonical := canonicalBytes(m)
	sum := sha256.Sum256(canonical)
	m.MeasurementDigest = hex.EncodeToString(sum[:])

	if in.Signer == nil {
		// Unsigned but valid measurement.
		return m, nil
	}

	sig, alg, err := sign(in.Signer, sum[:])
	if err != nil {
		return Measurement{}, fmt.Errorf("sign measurement: %w", err)
	}
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	m.SignatureAlgorithm = alg
	m.Signed = true
	m.TPMBacked = in.TPMBacked
	m.SigningCertPEM = in.SigningCertPEM
	return m, nil
}

// canonicalBytes builds the deterministic byte string that is hashed +
// signed. A line-oriented, field-tagged encoding keeps it human-auditable and
// trivially reproducible by a verifier in any language, and avoids JSON map
// ordering surprises. The measurement_digest / signature fields are excluded —
// they are derived from these bytes.
func canonicalBytes(m Measurement) []byte {
	var b strings.Builder
	b.WriteString("containarium.self-measurement.v1\n")
	b.WriteString("hash=" + m.HashAlgorithm + "\n")
	b.WriteString("daemon_version=" + m.DaemonVersion + "\n")
	b.WriteString("measured_at=" + m.MeasuredAt.UTC().Format(time.RFC3339Nano) + "\n")
	b.WriteString("binary=" + m.BinaryDigest + "\n")
	for _, p := range m.ProgramDigests {
		b.WriteString("program=" + p.Name + ":" + p.Digest + "\n")
	}
	b.WriteString("config=" + m.ConfigDigest + "\n")
	return []byte(b.String())
}

// digestConfigState canonicalizes the config snapshot (sorted keys) and hashes
// it. A nil/empty map hashes the empty object so the field is always present
// and stable.
func digestConfigState(state map[string]string) string {
	keys := make([]string, 0, len(state))
	for k := range state {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, k := range keys {
		// Encode each key/value pair via json so embedded separators in values
		// can't forge a different pairing.
		_ = enc.Encode([2]string{k, state[k]})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// digestFile streams a file through SHA-256 and returns the hex digest.
func digestFile(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path is operator/daemon-controlled (binary + configured program object), not user input
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sign signs the measurement digest with the node identity key. ECDSA keys
// (the sentinel-issued peer leaf) sign the digest directly; any other
// crypto.Signer is signed with SHA-256 as the opts hash. The returned
// algorithm string records the scheme for the verifier.
func sign(signer crypto.Signer, digest []byte) (sig []byte, alg string, err error) {
	switch signer.(type) {
	case *ecdsa.PrivateKey:
		s, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			return nil, "", err
		}
		return s, SignatureAlgorithmECDSAP256SHA256, nil
	default:
		s, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			return nil, "", err
		}
		return s, "sha256", nil
	}
}
