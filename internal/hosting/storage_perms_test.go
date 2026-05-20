package hosting

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Phase 4.8 — CheckStorageDirPerms (audit C-MED-7). TLS private
// keys live under the Caddy storage path; world-readable bits
// have no business there.

func TestCheckStorageDirPerms_Accepts0750(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	dir := filepath.Join(t.TempDir(), "caddy")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := CheckStorageDirPerms(dir); err != nil {
		t.Fatalf("0750 should pass: %v", err)
	}
}

func TestCheckStorageDirPerms_Accepts0700(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	dir := filepath.Join(t.TempDir(), "caddy")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := CheckStorageDirPerms(dir); err != nil {
		t.Fatalf("0700 should pass: %v", err)
	}
}

func TestCheckStorageDirPerms_RejectsWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	dir := filepath.Join(t.TempDir(), "caddy")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err := CheckStorageDirPerms(dir)
	if err == nil {
		t.Fatal("0755 must be rejected")
	}
	if !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("error should call out permissions: %v", err)
	}
}

func TestCheckStorageDirPerms_RejectsWorldWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	dir := filepath.Join(t.TempDir(), "caddy")
	if err := os.MkdirAll(dir, 0o757); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := CheckStorageDirPerms(dir); err == nil {
		t.Fatal("0757 must be rejected")
	}
}

func TestCheckStorageDirPerms_RejectsMissingDir(t *testing.T) {
	err := CheckStorageDirPerms("/this/path/does/not/exist")
	if err == nil {
		t.Fatal("missing dir must error")
	}
}

func TestCheckStorageDirPerms_RejectsFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "actually-a-file")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := CheckStorageDirPerms(tmp); err == nil {
		t.Fatal("non-directory path must error")
	}
}
