//go:build !windows

package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO named like a token must be refused, not opened: opening one for
// reading blocks until a writer appears.
func TestTSASink_FIFOAtTokenPathIsRefusedWithoutBlocking(t *testing.T) {
	a := newValidTestTSA(t, "a")
	file, sink, _ := newTSAFixture(t, a, a)
	if err := os.MkdirAll(sink.TokenDir(), 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sink.TokenDir(), tsaTokenName(10))
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- NewTeeSink(file, sink).PublishRoot(context.Background(), 10, "root-10") }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrTSATokenFileRefused) {
			t.Fatalf("err = %v, want ErrTSATokenFileRefused", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PublishRoot blocked on a FIFO at the token path")
	}
	if _, err := readTokenFile(path); !errors.Is(err, ErrTSATokenFileRefused) {
		t.Fatalf("readTokenFile err = %v, want ErrTSATokenFileRefused", err)
	}
}

// The path is swapped for a FIFO after the Lstat check: the open must not
// block (O_NONBLOCK) and the check on the open descriptor must refuse it.
func TestReadTokenFile_FIFOSwappedInAfterLstatIsRefused(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular.tsr")
	if err := os.WriteFile(regular, []byte{0x05, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo.tsr")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	orig := tokenLstat
	tokenLstat = func(string) (os.FileInfo, error) { return os.Lstat(regular) }
	t.Cleanup(func() { tokenLstat = orig })

	done := make(chan error, 1)
	go func() { _, err := readTokenFile(fifo); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrTSATokenFileRefused) {
			t.Fatalf("err = %v, want ErrTSATokenFileRefused", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readTokenFile blocked opening a FIFO")
	}
}
