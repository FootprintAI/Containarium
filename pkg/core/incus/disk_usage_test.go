package incus

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBuildContainerRootfsPath nails down the path-resolution
// convention for the dir-backend disk-usage fallback. If incus
// ever moves where it puts pool sources we want this test to fail
// before the fallback silently starts looking at the wrong tree.
func TestBuildContainerRootfsPath(t *testing.T) {
	tests := []struct {
		name          string
		pool          string
		poolSource    string
		containerName string
		want          string
	}{
		{
			name:          "explicit absolute source (zfs pool source path)",
			pool:          "default",
			poolSource:    "/srv/containarium/storage",
			containerName: "alice",
			want:          "/srv/containarium/storage/containers/alice/rootfs",
		},
		{
			name:          "empty source falls through to incus default",
			pool:          "default",
			poolSource:    "",
			containerName: "alice",
			want:          "/var/lib/incus/storage-pools/default/containers/alice/rootfs",
		},
		{
			name:          "non-path source (e.g. zfs dataset name) falls through to default",
			pool:          "fast",
			poolSource:    "tank/incus",
			containerName: "bob",
			want:          "/var/lib/incus/storage-pools/fast/containers/bob/rootfs",
		},
		{
			name:          "non-default pool name with explicit source",
			pool:          "fast",
			poolSource:    "/mnt/fast-pool",
			containerName: "carol",
			want:          "/mnt/fast-pool/containers/carol/rootfs",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := buildContainerRootfsPath(tc.pool, tc.poolSource, tc.containerName)
			if got != tc.want {
				t.Errorf("buildContainerRootfsPath(%q, %q, %q) = %q, want %q",
					tc.pool, tc.poolSource, tc.containerName, got, tc.want)
			}
		})
	}
}

// TestDirSize covers the cases the dir-backend fallback actually
// hits: regular files at the top level, files inside subdirs,
// symlinks (skipped), and a vanished path (we want a real error
// surfaced so GetContainerMetrics knows to skip the field).
func TestDirSize(t *testing.T) {
	t.Run("sums regular file sizes recursively", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "a.txt"), 100)
		writeFile(t, filepath.Join(root, "sub", "b.txt"), 250)
		writeFile(t, filepath.Join(root, "sub", "deep", "c.txt"), 17)

		got, err := dirSize(root)
		if err != nil {
			t.Fatalf("dirSize: %v", err)
		}
		const want = 100 + 250 + 17
		if got != want {
			t.Errorf("dirSize = %d, want %d", got, want)
		}
	})

	t.Run("ignores symlinks so we don't double-count the target", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "real.txt"), 50)
		// Symlink to the file — its own size should NOT be added.
		if err := os.Symlink("real.txt", filepath.Join(root, "link.txt")); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		// Symlink to a directory — its own size should also NOT be added.
		if err := os.Symlink("..", filepath.Join(root, "loop")); err != nil {
			t.Fatalf("symlink dir: %v", err)
		}

		got, err := dirSize(root)
		if err != nil {
			t.Fatalf("dirSize: %v", err)
		}
		if got != 50 {
			t.Errorf("dirSize = %d, want 50 (only the regular file)", got)
		}
	})

	t.Run("missing root yields zero, no error (best-effort metric)", func(t *testing.T) {
		// containerRootfsPath() stats the path before calling
		// dirSize, so dirSize on a non-existent root shouldn't
		// happen in practice. But the contract callers depend on
		// is "errors during the walk don't abort, they just leave
		// the partial sum" — pin that here so a future refactor
		// to WalkDir's error handling doesn't silently change
		// the field to abort-on-error.
		got, err := dirSize("/nonexistent/path/we/dont/expect")
		if err != nil {
			t.Errorf("expected no error on missing root, got %v", err)
		}
		if got != 0 {
			t.Errorf("expected 0 bytes on missing root, got %d", got)
		}
	})

	t.Run("empty directory is zero, not an error", func(t *testing.T) {
		got, err := dirSize(t.TempDir())
		if err != nil {
			t.Fatalf("dirSize: %v", err)
		}
		if got != 0 {
			t.Errorf("empty dir size = %d, want 0", got)
		}
	})
}

func writeFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
