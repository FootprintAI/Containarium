package zfskey

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultKeysDir is where FileKeyProvider looks for per-tenant key files
// unless the daemon is pointed elsewhere with --zfs-keys-dir.
const DefaultKeysDir = "/etc/containarium/keys"

// keyFileSuffix is appended to a tenant id to form its key file name.
const keyFileSuffix = ".key"

// FileKeyProvider is the OSS reference KeyProvider: one raw key file per
// tenant under a single directory. It is the same trade-off operators
// already accept for the pool-level --zfs-encryption-keyfile, scoped per
// tenant instead of per pool.
//
// Cloud deployments swap this for a KMS- or Vault-backed provider; the
// daemon only ever sees the KeyProvider interface.
type FileKeyProvider struct {
	dir string
}

// NewFileKeyProvider constructs a provider over dir. The directory is
// created if absent, with permissions that exclude group and other —
// a keys directory readable by anyone but the daemon user is not a
// custody boundary.
func NewFileKeyProvider(dir string) (*FileKeyProvider, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("keys directory is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve keys directory: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create keys directory: %w", err)
	}
	// An existing directory may have been created with looser
	// permissions; tighten rather than trust.
	//
	// #nosec G302 -- 0700 is the tightest usable mode for a *directory*:
	// the owner execute bit is what allows traversing into it to open the
	// key files. The 0600 the rule wants would make the directory
	// unopenable. Group and other are already excluded, which is the
	// property that matters for key custody.
	if err := os.Chmod(abs, 0o700); err != nil {
		return nil, fmt.Errorf("secure keys directory: %w", err)
	}
	return &FileKeyProvider{dir: abs}, nil
}

// Wrap resolves the tenant's key, generating one on first use.
//
// Generate-if-absent rather than require-preprovisioned: an operator who
// has not dropped a key file in place should get a working encrypted
// container with a fresh random key, not a failed create. Operators who
// manage custody themselves simply place the file first, and Wrap adopts
// it.
func (p *FileKeyProvider) Wrap(ctx context.Context, tenantID string) (Key, KeyRef, error) {
	if err := ctx.Err(); err != nil {
		return Key{}, KeyRef{}, err
	}
	path, err := p.keyPath(tenantID)
	if err != nil {
		return Key{}, KeyRef{}, err
	}
	ref := KeyRef{Scheme: SchemeFile, URI: path}

	// Adopt an existing key so a tenant's containers all land on one
	// encryptionroot, and so an operator-provisioned key is never
	// silently replaced.
	switch key, err := p.readKeyFile(path); {
	case err == nil:
		return key, ref, nil
	case !os.IsNotExist(err):
		return Key{}, KeyRef{}, err
	}

	material := make([]byte, KeyLen)
	if _, err := rand.Read(material); err != nil {
		return Key{}, KeyRef{}, fmt.Errorf("generate key for tenant %q: %w", tenantID, err)
	}
	key, err := NewKey(material)
	if err != nil {
		return Key{}, KeyRef{}, err
	}

	// O_EXCL so two concurrent creates for the same tenant cannot race
	// into two different keys, one of which would silently win and leave
	// the other's dataset unopenable.
	// #nosec G304 -- path comes from p.keyPath(tenantID), which rejects
	// separators and ".." and joins onto p.dir, so it cannot escape the
	// keys directory. It is never caller-supplied.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			// Lost the race — adopt the winner's key.
			existing, rerr := p.readKeyFile(path)
			if rerr != nil {
				return Key{}, KeyRef{}, rerr
			}
			return existing, ref, nil
		}
		return Key{}, KeyRef{}, fmt.Errorf("create key file for tenant %q: %w", tenantID, err)
	}
	if _, err := f.Write(material); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return Key{}, KeyRef{}, fmt.Errorf("write key file for tenant %q: %w", tenantID, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return Key{}, KeyRef{}, fmt.Errorf("close key file for tenant %q: %w", tenantID, err)
	}
	return key, ref, nil
}

// Load re-reads key material for a ref this provider issued.
func (p *FileKeyProvider) Load(ctx context.Context, ref KeyRef) (Key, error) {
	if err := ctx.Err(); err != nil {
		return Key{}, err
	}
	if ref.Scheme != SchemeFile {
		return Key{}, fmt.Errorf("unsupported key ref scheme %q (this provider serves %q)", ref.Scheme, SchemeFile)
	}
	if ref.URI == "" {
		return Key{}, fmt.Errorf("key ref has no URI")
	}
	// A KeyRef is stored on container metadata, so treat it as
	// attacker-influenced: confine it to the keys directory rather than
	// following it wherever it points.
	if err := p.confine(ref.URI); err != nil {
		return Key{}, err
	}
	return p.readKeyFile(ref.URI)
}

// keyPath maps a tenant id to its key file, rejecting ids that would
// escape the keys directory once joined into a path.
func (p *FileKeyProvider) keyPath(tenantID string) (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("tenant id is required")
	}
	if strings.ContainsAny(tenantID, `/\`) || strings.Contains(tenantID, "..") || tenantID != filepath.Base(tenantID) {
		return "", fmt.Errorf("invalid tenant id %q", tenantID)
	}
	if tenantID == "." {
		return "", fmt.Errorf("invalid tenant id %q", tenantID)
	}
	return filepath.Join(p.dir, tenantID+keyFileSuffix), nil
}

// confine rejects any path that does not resolve to a direct child of the
// keys directory.
func (p *FileKeyProvider) confine(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve key path: %w", err)
	}
	if filepath.Dir(abs) != p.dir {
		return fmt.Errorf("key ref %q points outside the keys directory", path)
	}
	return nil
}

// readKeyFile reads and validates one key file. Permissions are checked
// before the contents are trusted: a key readable by other local users is
// not a secret, and proceeding would launder that into an encryption
// guarantee the operator does not actually have.
func (p *FileKeyProvider) readKeyFile(path string) (Key, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Key{}, err // callers distinguish os.IsNotExist
	}
	if fi.IsDir() {
		return Key{}, fmt.Errorf("key path %q is a directory", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return Key{}, fmt.Errorf(
			"key file %q has unsafe permission %#o: it is readable by group or other; chmod 600 it", path, perm)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- path is confined to p.dir by keyPath/confine
	if err != nil {
		return Key{}, fmt.Errorf("read key file: %w", err)
	}
	key, err := NewKey(b)
	if err != nil {
		return Key{}, fmt.Errorf("key file %q: %w", path, err)
	}
	return key, nil
}
