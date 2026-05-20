package secrets

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Phase 4.2 — master key file must be 0400 (or stricter) at load
// time. Audit finding C-HIGH-6: the file is created at 0400 but
// umask drift, ownership change, or backup-tool side effects can
// widen the permissions silently. LoadOrCreateMasterKey must
// fail-closed if any non-owner bit is set.

func TestLoadOrCreateMasterKey_RejectsWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	tmp := t.TempDir()
	path := filepath.Join(tmp, "master.key")
	if err := os.WriteFile(path, make([]byte, MasterKeySize), 0o444); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, _, err := LoadOrCreateMasterKey(path)
	if err == nil {
		t.Fatal("world-readable master key must be rejected")
	}
	if !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("error should mention permissions: %v", err)
	}
}

func TestLoadOrCreateMasterKey_RejectsGroupReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	tmp := t.TempDir()
	path := filepath.Join(tmp, "master.key")
	if err := os.WriteFile(path, make([]byte, MasterKeySize), 0o440); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, _, err := LoadOrCreateMasterKey(path)
	if err == nil {
		t.Fatal("group-readable master key must be rejected")
	}
}

func TestLoadOrCreateMasterKey_AcceptsMode0400(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	tmp := t.TempDir()
	path := filepath.Join(tmp, "master.key")
	wantKey := make([]byte, MasterKeySize)
	for i := range wantKey {
		wantKey[i] = byte(i)
	}
	if err := os.WriteFile(path, wantKey, 0o400); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, created, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatalf("0400 master key must be accepted: %v", err)
	}
	if created {
		t.Fatal("file existed; created should be false")
	}
	if len(got) != MasterKeySize {
		t.Fatalf("got %d bytes, want %d", len(got), MasterKeySize)
	}
}

func TestLoadOrCreateMasterKey_NewFileCreated0400(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	tmp := t.TempDir()
	path := filepath.Join(tmp, "master.key")

	_, created, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateMasterKey: %v", err)
	}
	if !created {
		t.Fatal("expected created=true on fresh path")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != MasterKeyFileMode {
		t.Fatalf("newly created key has mode %#o, want %#o", perm, MasterKeyFileMode)
	}

	// And subsequent loads should succeed — covers the
	// create→load round trip.
	_, created2, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatalf("re-load after creation failed: %v", err)
	}
	if created2 {
		t.Fatal("created flag should be false on re-load")
	}
}
