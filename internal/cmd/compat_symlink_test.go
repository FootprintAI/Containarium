//go:build !windows && !containarium_client

package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEnsureCompatSymlink_NoOpWhenNewBinaryAbsent pins the safety property:
// service install / pool join must not touch /usr/local/bin/containarium at
// all until containariumd actually exists — replacing a still-in-use binary
// with a symlink to nothing would brick the host instead of converging it.
func TestEnsureCompatSymlink_NoOpWhenNewBinaryAbsent(t *testing.T) {
	root := t.TempDir()
	if err := ensureCompatSymlink(root); err != nil {
		t.Fatalf("ensureCompatSymlink: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, compatSymlinkOldPath)); !os.IsNotExist(err) {
		t.Errorf("expected no file at the old path, got err=%v", err)
	}
}

// TestEnsureCompatSymlink_ReplacesOldRealBinary is the Phase 1 rollout case:
// a host still has the real (pre-#1780) binary at the old path; once
// containariumd is deployed there, the old path must become a symlink to it.
func TestEnsureCompatSymlink_ReplacesOldRealBinary(t *testing.T) {
	root := t.TempDir()
	newPath := filepath.Join(root, compatSymlinkNewPath)
	oldPath := filepath.Join(root, compatSymlinkOldPath)
	if err := os.MkdirAll(filepath.Dir(newPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("fake binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldPath, []byte("old real binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := ensureCompatSymlink(root); err != nil {
		t.Fatalf("ensureCompatSymlink: %v", err)
	}

	fi, err := os.Lstat(oldPath)
	if err != nil {
		t.Fatalf("Lstat old path: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("old path is not a symlink: mode=%v", fi.Mode())
	}
	target, err := os.Readlink(oldPath)
	if err != nil || target != newPath {
		t.Errorf("symlink target = %q, err=%v, want %q", target, err, newPath)
	}
}

// TestEnsureCompatSymlink_Idempotent mirrors pool join's documented
// idempotency: re-running must not error, and must leave the symlink intact.
func TestEnsureCompatSymlink_Idempotent(t *testing.T) {
	root := t.TempDir()
	newPath := filepath.Join(root, compatSymlinkNewPath)
	if err := os.MkdirAll(filepath.Dir(newPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("fake binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := ensureCompatSymlink(root); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := ensureCompatSymlink(root); err != nil {
		t.Fatalf("second call should be idempotent, got: %v", err)
	}

	target, err := os.Readlink(filepath.Join(root, compatSymlinkOldPath))
	if err != nil || target != newPath {
		t.Errorf("symlink target = %q, err=%v, want %q", target, err, newPath)
	}
}

// TestRemoveCompatSymlink_OnlyRemovesOurSymlink pins the uninstall-safety
// property: a real file at the old path (some other mechanism's binary, or a
// host that never converged) must never be deleted by uninstall — only a
// symlink this package itself created is fair game.
func TestRemoveCompatSymlink_OnlyRemovesOurSymlink(t *testing.T) {
	t.Run("real file is left alone", func(t *testing.T) {
		root := t.TempDir()
		oldPath := filepath.Join(root, compatSymlinkOldPath)
		if err := os.MkdirAll(filepath.Dir(oldPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(oldPath, []byte("a real binary"), 0o755); err != nil {
			t.Fatal(err)
		}

		removeCompatSymlink(root)

		if _, err := os.Stat(oldPath); err != nil {
			t.Errorf("real file was removed: %v", err)
		}
	})

	t.Run("our symlink is removed", func(t *testing.T) {
		root := t.TempDir()
		newPath := filepath.Join(root, compatSymlinkNewPath)
		oldPath := filepath.Join(root, compatSymlinkOldPath)
		if err := os.MkdirAll(filepath.Dir(newPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(newPath, []byte("fake binary"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(newPath, oldPath); err != nil {
			t.Fatal(err)
		}

		removeCompatSymlink(root)

		if _, err := os.Lstat(oldPath); !os.IsNotExist(err) {
			t.Errorf("expected the symlink to be removed, got err=%v", err)
		}
	})

	t.Run("absent old path is a no-op", func(t *testing.T) {
		root := t.TempDir()
		removeCompatSymlink(root) // must not panic or error
	})
}
