package guardrail

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SubjectDigest is the canonical SHA-256 of a directory: one line per
// regular file, "<slash-separated relative path>\n<sha256 of content>\n",
// in sorted path order, hashed together. Symlinks are not followed — they
// are skipped, like every non-regular file — so a tree cannot pull bytes
// from outside itself into its own digest. It depends on content and
// names only, never on mtimes or modes, so the same tree produced on two
// machines digests the same.
//
// Walks and opens go through os.Root (as internal/transfer does), so every
// open is kernel-enforced to stay inside dir even if the tree changes
// under us between the walk and the open.
func SubjectDigest(dir string) (string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()

	paths, err := regularFiles(root)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, rel := range paths {
		f, err := root.Open(filepath.FromSlash(rel))
		if err != nil {
			return "", err
		}
		fh := sha256.New()
		_, cerr := io.Copy(fh, f)
		_ = f.Close()
		if cerr != nil {
			return "", cerr
		}
		fmt.Fprintf(h, "%s\n%s\n", rel, hex.EncodeToString(fh.Sum(nil)))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// regularFiles lists the regular files under root as sorted slash paths.
func regularFiles(root *os.Root) ([]string, error) {
	var paths []string
	err := fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

// PolicyHash is the SHA-256 of the policy's deterministic proto encoding.
func PolicyHash(policy *pb.GuardrailPolicy) (string, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(policy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// KeyID identifies a public key in an attestation: SHA-256 of its bytes.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// signingBytes is what the signature covers: the attestation with the
// signature cleared, deterministically encoded.
func signingBytes(att *pb.GuardrailAttestation) ([]byte, error) {
	clone := proto.Clone(att).(*pb.GuardrailAttestation)
	clone.Signature = nil
	return proto.MarshalOptions{Deterministic: true}.Marshal(clone)
}

// Sign fills key_id and signature in place.
func Sign(att *pb.GuardrailAttestation, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("guardrail: signing key is not an ed25519 private key")
	}
	att.KeyId = KeyID(priv.Public().(ed25519.PublicKey))
	b, err := signingBytes(att)
	if err != nil {
		return err
	}
	att.Signature = ed25519.Sign(priv, b)
	return nil
}

// ErrBadSignature is returned by Verify when the signature does not match.
var ErrBadSignature = errors.New("guardrail: attestation signature does not verify")

// Verify checks the signature against pub and that key_id names pub. It
// does not look at the verdict or the subject — VerifySubject does.
func Verify(att *pb.GuardrailAttestation, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("guardrail: public key is not an ed25519 public key")
	}
	if att.GetKeyId() != KeyID(pub) {
		return fmt.Errorf("guardrail: attestation was signed by key %s, not by the key supplied (%s)", short(att.GetKeyId()), short(KeyID(pub)))
	}
	b, err := signingBytes(att)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, att.GetSignature()) {
		return ErrBadSignature
	}
	return nil
}

// VerifySubject is what a consumer runs before using data: the signature
// verifies, the directory's digest is the attested one, and the verdict is
// PASS. Each failure is its own error so a log says which.
func VerifySubject(att *pb.GuardrailAttestation, pub ed25519.PublicKey, dir string) error {
	if err := Verify(att, pub); err != nil {
		return err
	}
	got, err := SubjectDigest(dir)
	if err != nil {
		return err
	}
	if got != att.GetSubjectSha256() {
		return fmt.Errorf("guardrail: subject digest %s does not match attested %s — the bytes changed after attestation", short(got), short(att.GetSubjectSha256()))
	}
	if att.GetVerdict() != pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS {
		return fmt.Errorf("guardrail: attestation verdict is %s, not PASS", strings.TrimPrefix(att.GetVerdict().String(), "GUARDRAIL_VERDICT_"))
	}
	return nil
}

// Key files hold one base64 (standard encoding) line: the 64-byte ed25519
// private key, or the 32-byte public key — the same shape the sentinel's
// ed25519 keys use (internal/auth). The private file is written 0600.

// GenerateKeyFiles writes <prefix>.key and <prefix>.pub.
func GenerateKeyFiles(prefix string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(prefix+".key", []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return nil, err
	}
	// #nosec G306 -- the public half is meant to be handed to verifiers; no secret in it
	if err := os.WriteFile(prefix+".pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return nil, err
	}
	return pub, nil
}

// LoadSigningKey reads a <prefix>.key file.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("guardrail: %s: want %d-byte ed25519 private key, got %d bytes", path, ed25519.PrivateKeySize, len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// LoadPublicKey reads a <prefix>.pub file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("guardrail: %s: want %d-byte ed25519 public key, got %d bytes", path, ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func readKeyFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-named key file, read on the operator's own machine
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
}

func short(hexstr string) string {
	if len(hexstr) > 12 {
		return hexstr[:12] + "…"
	}
	return hexstr
}
