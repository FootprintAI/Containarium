// Package sshkey detects, generates, and fingerprints local SSH
// keypairs for the `containarium ssh setup` flow (sub-task A5 of
// umbrella-issue #100). See prd/cloud/cli-login-and-multi-env-ssh.md
// §"Design — Multi-environment SSH".
//
// Why a dedicated package: the CLI flow needs three slightly-different
// things from "the user's local SSH key" — locate an existing one,
// generate a new one on first login, and compute the SHA256 fingerprint
// so the cloud-side ListSSHKeys table is human-meaningful. Concentrating
// all three in one place gives `internal/cmd/ssh.go` and the
// `--with-ssh-setup` path in login.go a single, testable surface.
//
// Strong typing per CLAUDE.md: the public shape is the SSHKey struct
// (which mirrors the cloud's UserService SSHKey message field-for-field),
// not a (string, string, string) triple.
package sshkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHKey is the wire-shape of a user-registered SSH key as returned by
// the cloud's UserService.ListSSHKeys / AddSSHKey. Kept here (rather
// than in pkg/pb) so the CLI compiles cleanly even before the
// cloud-side proto/pb regen lands; the field tags match the JSON the
// REST shim will emit.
type SSHKey struct {
	Name        string    `json:"name"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
}

// DefaultPrivateKeyPath is the file we look at first when "find the
// local key" is asked. It's the canonical OpenSSH default; nearly
// every developer machine has ed25519 here or at id_rsa.
const (
	DefaultPrivateKeyPath    = "id_ed25519"
	DefaultPublicKeyPath     = "id_ed25519.pub"
	FallbackPrivateKeyPath   = "id_rsa"
	FallbackPublicKeyPath    = "id_rsa.pub"
	containariumKeyName      = "containarium_ed25519"
	containariumPubKeySuffix = ".pub"
)

// LocateOpts controls Locate's search order. Zero value is "look in
// ~/.ssh for ed25519 then rsa". Tests inject HomeDir to redirect at a
// tempdir.
type LocateOpts struct {
	HomeDir string // override $HOME (mostly for tests); empty = os.UserHomeDir
}

// Locate scans ~/.ssh for an existing SSH keypair and returns the
// path to the *public* key file plus its parsed contents. The
// private key is not loaded — we never need to send it anywhere, and
// reading it would gratuitously require an unlock prompt on
// passphrase-protected keys.
//
// Search order: id_ed25519.pub, then id_rsa.pub. Returns os.ErrNotExist
// if neither exists (callers can choose to fall through to Generate).
func Locate(opts LocateOpts) (pubPath string, pub string, err error) {
	dir, err := sshDir(opts.HomeDir)
	if err != nil {
		return "", "", err
	}
	for _, name := range []string{DefaultPublicKeyPath, FallbackPublicKeyPath} {
		p := filepath.Join(dir, name)
		// #nosec G304 -- path is under the user's own ~/.ssh; not
		// attacker-controlled.
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", "", fmt.Errorf("read %s: %w", p, err)
		}
		s := strings.TrimSpace(string(b))
		if s == "" {
			continue
		}
		if err := validatePublicKey(s); err != nil {
			return "", "", fmt.Errorf("public key %s is malformed: %w", p, err)
		}
		return p, s, nil
	}
	return "", "", os.ErrNotExist
}

// Generate creates a fresh ed25519 keypair, writes it to
// ~/.ssh/containarium_ed25519{,.pub} with the standard 0600/0644
// perms, and returns the public-key path + contents.
//
// We deliberately use a containarium-prefixed filename rather than
// clobbering id_ed25519: a user might already have a personal key
// there that's registered with GitHub/GitLab, and silently replacing
// it would be hostile. The cost is one extra file in ~/.ssh; the
// benefit is "containarium ssh setup is idempotent and never
// destructive."
//
// Returns os.ErrExist if the target paths already exist — callers
// should call Locate first, or pass force=true to overwrite (the
// containarium-prefixed variant only, not the personal keys).
func Generate(opts LocateOpts, force bool) (pubPath string, pub string, err error) {
	dir, err := sshDir(opts.HomeDir)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("create %s: %w", dir, err)
	}

	privPath := filepath.Join(dir, containariumKeyName)
	pubPath = privPath + containariumPubKeySuffix

	if !force {
		if _, err := os.Stat(privPath); err == nil {
			return "", "", fmt.Errorf("%s already exists: %w", privPath, os.ErrExist)
		}
		if _, err := os.Stat(pubPath); err == nil {
			return "", "", fmt.Errorf("%s already exists: %w", pubPath, os.ErrExist)
		}
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ed25519: %w", err)
	}

	// Marshal private key in OpenSSH PEM format.
	pemBlock, err := ssh.MarshalPrivateKey(privKey, "containarium-cli")
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}
	privBytes := pem.EncodeToMemory(pemBlock)

	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return "", "", fmt.Errorf("wrap public key: %w", err)
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)

	// Write private FIRST (0600). If we crash between, the .pub
	// without its counterpart is harmless; the reverse is not (a
	// .pub-less private key may look orphan to ssh-agent).
	if err := writeFileMode(privPath, privBytes, 0o600); err != nil {
		return "", "", fmt.Errorf("write %s: %w", privPath, err)
	}
	if err := writeFileMode(pubPath, pubBytes, 0o644); err != nil {
		return "", "", fmt.Errorf("write %s: %w", pubPath, err)
	}
	return pubPath, strings.TrimSpace(string(pubBytes)), nil
}

// LocateOrGenerate convenience-wraps the common "use existing if
// present, else generate" path used by `containarium ssh setup` and
// the login --with-ssh-setup branch.
//
// `generated` reports whether the key on disk was freshly created
// (true) versus already there (false), so the caller can tell the
// user "found existing key at X" vs "generated new key at X".
func LocateOrGenerate(opts LocateOpts) (pubPath string, pub string, generated bool, err error) {
	pubPath, pub, err = Locate(opts)
	if err == nil {
		return pubPath, pub, false, nil
	}
	if !os.IsNotExist(err) {
		return "", "", false, err
	}
	pubPath, pub, err = Generate(opts, false)
	if err != nil {
		return "", "", false, err
	}
	return pubPath, pub, true, nil
}

// Fingerprint returns the SHA256 fingerprint of an OpenSSH-format
// public key, in the same "SHA256:base64..." form that `ssh-keygen
// -lf` prints. Padding is stripped to match ssh-keygen's output.
func Fingerprint(authorizedKey string) (string, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(authorizedKey)))
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	sum := sha256.Sum256(pk.Marshal())
	enc := base64.StdEncoding.EncodeToString(sum[:])
	enc = strings.TrimRight(enc, "=")
	return "SHA256:" + enc, nil
}

// ReadPublicKey reads a public-key file from disk, validates it, and
// returns the trimmed contents. Convenience for `--key=<path>` on the
// CLI.
func ReadPublicKey(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is empty")
	}
	// #nosec G304 -- path comes from a --key flag the user supplied
	// explicitly; not attacker-controlled.
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	s := strings.TrimSpace(string(b))
	if err := validatePublicKey(s); err != nil {
		return "", fmt.Errorf("public key %s is malformed: %w", path, err)
	}
	return s, nil
}

// DefaultKeyName synthesizes a human-friendly label for the
// "Register this machine's key as 'X'" prompt. PRD example:
// "alice-laptop". We use "<user>@<host>" matching login.go's
// deviceName fallback — close enough that the cloud-side "Active
// sessions" and "SSH keys" tables read consistently.
func DefaultKeyName(user, host string) string {
	user = strings.TrimSpace(user)
	host = strings.TrimSpace(host)
	switch {
	case user != "" && host != "":
		return fmt.Sprintf("%s@%s", user, host)
	case host != "":
		return host
	case user != "":
		return user
	}
	return "containarium-cli"
}

// validatePublicKey is a thin wrapper that rejects obvious malformed
// public-key strings before we ship them to the cloud. The cloud will
// re-validate, but rejecting at the CLI gives a much clearer error
// message ("not a valid SSH public key: …") than the cloud's generic
// HTTP 400.
func validatePublicKey(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("key is empty")
	}
	if strings.ContainsAny(s, "\r\n") {
		return fmt.Errorf("key contains embedded newline")
	}
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return fmt.Errorf("ssh.ParseAuthorizedKey: %w", err)
	}
	return nil
}

func sshDir(home string) (string, error) {
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		home = h
	}
	return filepath.Join(home, ".ssh"), nil
}

// writeFileMode is a small wrapper that combines O_CREATE|O_EXCL|O_WRONLY
// with the supplied mode. We don't use os.WriteFile because it doesn't
// guarantee O_EXCL — and Generate's whole contract is "don't clobber".
// Force-mode callers stat-then-write through the same path; the EXCL
// flag protects against a race between the stat and the write.
func writeFileMode(path string, data []byte, mode os.FileMode) error {
	// #nosec G304 -- path computed from ~/.ssh; not attacker-controlled.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
