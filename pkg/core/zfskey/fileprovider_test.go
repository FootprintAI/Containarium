package zfskey

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestProvider(t *testing.T) (*FileKeyProvider, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	p, err := NewFileKeyProvider(dir)
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}
	return p, dir
}

// AC: a tenant ID resolves to distinct key material; two tenants never
// share a key.
func TestWrapGivesEachTenantADistinctKey(t *testing.T) {
	p, _ := newTestProvider(t)
	ctx := context.Background()

	alice, aliceRef, err := p.Wrap(ctx, "alice")
	if err != nil {
		t.Fatalf("Wrap(alice): %v", err)
	}
	bob, bobRef, err := p.Wrap(ctx, "bob")
	if err != nil {
		t.Fatalf("Wrap(bob): %v", err)
	}

	if bytes.Equal(alice.Bytes(), bob.Bytes()) {
		t.Fatal("two tenants were given the same key — the whole point is per-tenant isolation")
	}
	if aliceRef.URI == bobRef.URI {
		t.Errorf("refs collide: %q", aliceRef.URI)
	}
	if alice.Len() != KeyLen || bob.Len() != KeyLen {
		t.Errorf("key lengths = %d/%d, want %d", alice.Len(), bob.Len(), KeyLen)
	}
	if aliceRef.Scheme != SchemeFile {
		t.Errorf("scheme = %q, want %q", aliceRef.Scheme, SchemeFile)
	}
}

// A tenant's containers share one ZFS encryptionroot, so Wrap must be
// idempotent — a second container for the same tenant gets the same key.
func TestWrapIsIdempotentPerTenant(t *testing.T) {
	p, _ := newTestProvider(t)
	ctx := context.Background()

	first, firstRef, err := p.Wrap(ctx, "alice")
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	second, secondRef, err := p.Wrap(ctx, "alice")
	if err != nil {
		t.Fatalf("Wrap (again): %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Error("Wrap generated a new key for an existing tenant — its containers would land on different encryptionroots")
	}
	if firstRef.URI != secondRef.URI {
		t.Errorf("refs differ: %q vs %q", firstRef.URI, secondRef.URI)
	}
}

// AC: Load after Wrap returns the same key bytes for the same KeyRef.
func TestLoadReturnsTheWrappedKey(t *testing.T) {
	p, _ := newTestProvider(t)
	ctx := context.Background()

	want, ref, err := p.Wrap(ctx, "alice")
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := p.Load(ctx, ref)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Error("Load returned different material than Wrap issued")
	}
}

// A ref this provider never issued, or one pointing outside the keys
// directory, must be refused — a KeyRef is stored on container metadata
// and is therefore attacker-influenced input in a compromised control
// plane.
func TestLoadRejectsRefsOutsideTheKeysDir(t *testing.T) {
	p, dir := newTestProvider(t)
	ctx := context.Background()

	outside := filepath.Join(t.TempDir(), "elsewhere.key")
	if err := os.WriteFile(outside, bytes.Repeat([]byte{9}, KeyLen), 0o600); err != nil {
		t.Fatalf("write outside key: %v", err)
	}

	for _, tc := range []struct {
		name string
		ref  KeyRef
	}{
		{"absolute path outside dir", KeyRef{Scheme: SchemeFile, URI: outside}},
		{"traversal out of dir", KeyRef{Scheme: SchemeFile, URI: filepath.Join(dir, "..", "escape.key")}},
		{"unknown scheme", KeyRef{Scheme: "kms", URI: filepath.Join(dir, "alice.key")}},
		{"empty uri", KeyRef{Scheme: SchemeFile}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := p.Load(ctx, tc.ref); err == nil {
				t.Errorf("Load accepted %+v", tc.ref)
			}
		})
	}
}

// AC: path traversal via tenant ID cannot escape the keys dir.
func TestWrapRejectsUnsafeTenantIDs(t *testing.T) {
	p, dir := newTestProvider(t)
	ctx := context.Background()

	for _, id := range []string{
		"", "..", "../escape", "a/b", `a\b`, "../../etc/shadow", ".", "alice/../bob",
	} {
		t.Run("id="+id, func(t *testing.T) {
			if _, _, err := p.Wrap(ctx, id); err == nil {
				t.Errorf("Wrap accepted unsafe tenant id %q", id)
			}
		})
	}

	// Nothing should have been created outside the keys dir.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("rejected ids still created files: %v", entries)
	}
}

// AC: FileKeyProvider rejects a key file with unsafe permissions and a
// key of the wrong length, rather than proceeding.
func TestLoadRejectsUnsafeKeyFiles(t *testing.T) {
	ctx := context.Background()

	t.Run("group or world readable", func(t *testing.T) {
		p, dir := newTestProvider(t)
		_, ref, err := p.Wrap(ctx, "alice")
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		if err := os.Chmod(filepath.Join(dir, "alice.key"), 0o644); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		_, err = p.Load(ctx, ref)
		if err == nil {
			t.Fatal("Load accepted a world-readable key file")
		}
		if !strings.Contains(err.Error(), "permission") {
			t.Errorf("error should name the permission problem, got %q", err)
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		p, dir := newTestProvider(t)
		_, ref, err := p.Wrap(ctx, "alice")
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "alice.key"), []byte("too short"), 0o600); err != nil {
			t.Fatalf("truncate key: %v", err)
		}
		if _, err := p.Load(ctx, ref); err == nil {
			t.Error("Load accepted a key of the wrong length")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		p, dir := newTestProvider(t)
		_, ref, err := p.Wrap(ctx, "alice")
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		if err := os.Remove(filepath.Join(dir, "alice.key")); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if _, err := p.Load(ctx, ref); err == nil {
			t.Error("Load succeeded with no key file")
		}
	})
}

// An operator who pre-places a key file keeps custody: Wrap adopts it
// rather than overwriting it.
func TestWrapAdoptsAPreProvisionedKey(t *testing.T) {
	p, dir := newTestProvider(t)
	ctx := context.Background()

	preplaced := bytes.Repeat([]byte{0x5A}, KeyLen)
	if err := os.WriteFile(filepath.Join(dir, "alice.key"), preplaced, 0o600); err != nil {
		t.Fatalf("pre-place key: %v", err)
	}

	got, _, err := p.Wrap(ctx, "alice")
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if !bytes.Equal(got.Bytes(), preplaced) {
		t.Error("Wrap overwrote an operator-provided key")
	}
}

// Generated key files must not be readable by anyone but the daemon user.
func TestGeneratedKeyFilesAreNotGroupOrWorldReadable(t *testing.T) {
	p, dir := newTestProvider(t)
	if _, _, err := p.Wrap(context.Background(), "alice"); err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	fi, err := os.Stat(filepath.Join(dir, "alice.key"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("key file mode = %#o, want no group/other bits", perm)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("keys dir mode = %#o, want no group/other bits", perm)
	}
}

// FileKeyProvider must satisfy the interface the daemon depends on.
func TestFileKeyProviderImplementsKeyProvider(t *testing.T) {
	var _ KeyProvider = (*FileKeyProvider)(nil)
}
