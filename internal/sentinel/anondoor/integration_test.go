//go:build integration

package anondoor

// Integration: a REAL sshpiperd running this plugin (through the
// `containarium sentinel anon-door-plugin` subcommand), a fake daemon that
// answers /v1/anon/boxes:ensure with the address of a REAL sshd, and an
// ssh client with a never-seen key that must land in a shell on that sshd.
//
// It needs three things the unit tests do not, all supplied by env so the
// e2e lane (scripts/k8s-sentinel-e2e.sh pattern) can drive it and a laptop
// without them skips cleanly:
//
//	ANONDOOR_SSHPIPERD     path to an sshpiperd binary
//	ANONDOOR_CONTAINARIUM  path to a containarium client binary (the plugin)
//	ANONDOOR_SSHD_ADDR     host:port of an sshd that accepts ANONDOOR_UPSTREAM_KEY
//	ANONDOOR_UPSTREAM_KEY  private key sshd accepts; its user is ANONDOOR_SSHD_USER
//	ANONDOOR_SSHD_USER     login on that sshd
//
// Run: go test -tags integration ./internal/sentinel/anondoor/ -run Integration -v

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestIntegration_FreshKeyLandsInShell(t *testing.T) {
	piperd, ctn, sshdAddr, upKey, sshdUser := os.Getenv("ANONDOOR_SSHPIPERD"), os.Getenv("ANONDOOR_CONTAINARIUM"),
		os.Getenv("ANONDOOR_SSHD_ADDR"), os.Getenv("ANONDOOR_UPSTREAM_KEY"), os.Getenv("ANONDOOR_SSHD_USER")
	if piperd == "" || ctn == "" || sshdAddr == "" || upKey == "" || sshdUser == "" {
		t.Skip("set ANONDOOR_SSHPIPERD, ANONDOOR_CONTAINARIUM, ANONDOOR_SSHD_ADDR, ANONDOOR_UPSTREAM_KEY, ANONDOOR_SSHD_USER")
	}
	sshdHost, sshdPortStr, err := net.SplitHostPort(sshdAddr)
	if err != nil {
		t.Fatal(err)
	}
	sshdPort, _ := strconv.Atoi(sshdPortStr)

	// Fake daemon: every key gets the same real sshd; records what it saw.
	var seen []string
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		seen = append(seen, fmt.Sprint(req["fingerprint"]))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"boxName": "anon-test-container", "sshHost": sshdHost, "sshPort": sshdPort, "sshUser": sshdUser,
			"reused": len(seen) > 1,
		})
	}))
	defer daemon.Close()

	// sshpiperd on a free port with host key + our plugin.
	dir := t.TempDir()
	hostKey := filepath.Join(dir, "host_key")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-f", hostKey, "-N", "", "-q").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	port := freePort(t)
	cmd := exec.Command(piperd, "-i", hostKey, "-p", strconv.Itoa(port), "--drop-hostkeys-message",
		ctn, "sentinel", "anon-door-plugin", "--daemon-url", daemon.URL, "--upstream-key", upKey)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	waitPort(t, port)

	// A never-seen client key.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ClientConfig{
		User:            "anything",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test
		Timeout:         20 * time.Second,
	}
	for i := 0; i < 2; i++ {
		c, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		s, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		out, err := s.Output("echo door-ok")
		_ = s.Close()
		_ = c.Close()
		if err != nil || strings.TrimSpace(string(out)) != "door-ok" {
			t.Fatalf("session %d: %q %v", i, out, err)
		}
	}
	if len(seen) != 2 || seen[0] != seen[1] || !strings.HasPrefix(seen[0], "SHA256:") {
		t.Errorf("daemon saw %v, want the same fingerprint twice", seen)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("sshpiperd never listened on %d", port)
}
