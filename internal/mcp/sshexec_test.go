package mcp

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testSigner makes a throwaway host key to feed the callback.
func testSigner(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, privPEM, err := generateEphemeralSSHKey("hostkey")
	if err != nil {
		t.Fatalf("generateEphemeralSSHKey: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	return signer.PublicKey()
}

// TestTOFUHostKeyCallback verifies accept-new semantics: an unknown host is
// recorded and trusted, the same key on a later connect still verifies, and
// a CHANGED key for a known host is rejected (MITM detection).
func TestTOFUHostKeyCallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 22}
	const hostport = "192.0.2.10:22"
	key1 := testSigner(t)

	cb, err := tofuHostKeyCallback()
	if err != nil {
		t.Fatalf("tofuHostKeyCallback: %v", err)
	}

	// First contact with an unknown host → accept-new (recorded + trusted).
	if err := cb(hostport, remote, key1); err != nil {
		t.Fatalf("first contact should be accepted (accept-new), got: %v", err)
	}

	// known_hosts should now hold the entry.
	kh := filepath.Join(home, ".ssh", "known_hosts")
	data, err := os.ReadFile(kh)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("known_hosts is empty after accept-new")
	}

	// A fresh callback (reloads known_hosts) must trust the same key.
	cb2, err := tofuHostKeyCallback()
	if err != nil {
		t.Fatalf("tofuHostKeyCallback (reload): %v", err)
	}
	if err := cb2(hostport, remote, key1); err != nil {
		t.Fatalf("known host with same key should verify, got: %v", err)
	}

	// A DIFFERENT key for the same host must be rejected (potential MITM).
	key2 := testSigner(t)
	if err := cb2(hostport, remote, key2); err == nil {
		t.Fatal("changed host key should be rejected, but callback accepted it")
	}
}
