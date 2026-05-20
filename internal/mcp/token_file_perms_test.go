package mcp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Phase 1.8 — refuse JWT token files with insecure permissions
// (audit C-HIGH-7). A token file with mode > 0600 lets any
// non-owner read the admin JWT off the host.

func TestReadToken_RejectsWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	tmp := t.TempDir()
	path := filepath.Join(tmp, "jwt")
	// 0o644 = owner rw + world readable. The dangerous case.
	if err := os.WriteFile(path, []byte("a-valid-jwt"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := NewClient("http://example.invalid", "ignored")
	c.SetTokenFile(path)
	_, err := c.readToken()
	if err == nil {
		t.Fatal("readToken must reject world-readable token file")
	}
	if !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("error should mention permissions: %v", err)
	}
}

func TestReadToken_RejectsGroupReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	tmp := t.TempDir()
	path := filepath.Join(tmp, "jwt")
	// 0o640 = owner rw + group readable. Also unacceptable —
	// a sibling daemon running as the same group could read.
	if err := os.WriteFile(path, []byte("a-valid-jwt"), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := NewClient("http://example.invalid", "ignored")
	c.SetTokenFile(path)
	if _, err := c.readToken(); err == nil {
		t.Fatal("readToken must reject group-readable token file")
	}
}

func TestReadToken_AcceptsMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	tmp := t.TempDir()
	path := filepath.Join(tmp, "jwt")
	if err := os.WriteFile(path, []byte("a-valid-jwt"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := NewClient("http://example.invalid", "ignored")
	c.SetTokenFile(path)
	tok, err := c.readToken()
	if err != nil {
		t.Fatalf("0600 must be accepted: %v", err)
	}
	if tok != "a-valid-jwt" {
		t.Fatalf("token = %q, want a-valid-jwt", tok)
	}
}

func TestReadToken_AcceptsMode0400(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	tmp := t.TempDir()
	path := filepath.Join(tmp, "jwt")
	if err := os.WriteFile(path, []byte("a-valid-jwt"), 0o400); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := NewClient("http://example.invalid", "ignored")
	c.SetTokenFile(path)
	if _, err := c.readToken(); err != nil {
		t.Fatalf("0400 must be accepted: %v", err)
	}
}
