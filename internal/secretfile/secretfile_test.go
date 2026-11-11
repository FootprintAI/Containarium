package secretfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWrite_PreExisting0644BecomesMode0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil { // defeat umask
		t.Fatal(err)
	}
	if err := Write(p, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 0600", got)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "secret" {
		t.Fatalf("content = %q", b)
	}
}

func TestWrite_NewFileIs0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "new")
	if err := Write(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", fi.Mode().Perm())
	}
}

// Atomic replace: the destination is swapped by rename, so a reader holding
// the old file open still sees the old content, and no temp files remain.
func TestWrite_AtomicReplaceLeavesNoTempAndNewInode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tok")
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err := Write(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, _ := old.Read(buf)
	if string(buf[:n]) != "old" {
		t.Fatalf("old handle saw %q; file was truncated in place, not replaced", buf[:n])
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("leftover files: %v", ents)
	}
}

func TestWrite_MissingDirFails(t *testing.T) {
	if err := Write(filepath.Join(t.TempDir(), "nodir", "f"), []byte("x")); err == nil {
		t.Fatal("expected error")
	}
}
