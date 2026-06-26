package mcp

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/connectcore"
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

// fakeSSHServer is a minimal in-process SSH server: it accepts exactly the
// managed public key, answers one "session" channel's "exec" request by
// writing canned stdout/stderr and an exit status, then closes. It exists to
// drive runMCPSSHExec end-to-end with NO system ssh binary and NO daemon.
type fakeSSHServer struct {
	ln       net.Listener
	hostKey  ssh.Signer
	authKey  ssh.PublicKey // the only key allowed
	stdout   string
	stderr   string
	exitCode uint32
	wg       sync.WaitGroup
	// rejectFirstN rejects that many otherwise-valid auth attempts before
	// accepting, to simulate the keysync-propagation race (#830). 0 = accept
	// immediately. authAttempts counts valid-key auth attempts seen.
	rejectFirstN int32
	authAttempts int32
}

func newFakeSSHServer(t *testing.T, authKey ssh.PublicKey, stdout, stderr string, exitCode uint32) *fakeSSHServer {
	t.Helper()
	_, hostPEM, err := generateEphemeralSSHKey("fakehost")
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostSigner, err := ssh.ParsePrivateKey(hostPEM)
	if err != nil {
		t.Fatalf("parse host key: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeSSHServer{ln: ln, hostKey: hostSigner, authKey: authKey, stdout: stdout, stderr: stderr, exitCode: exitCode}
	s.wg.Add(1)
	go s.serve()
	return s
}

func (s *fakeSSHServer) addr() string { return s.ln.Addr().String() }

func (s *fakeSSHServer) close() {
	_ = s.ln.Close()
	s.wg.Wait()
}

func (s *fakeSSHServer) serve() {
	defer s.wg.Done()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) != string(s.authKey.Marshal()) {
				return nil, errUnauthorizedKey
			}
			// Reject the first rejectFirstN otherwise-valid auths to simulate
			// the keysync-propagation race (#830): the key isn't live yet,
			// then becomes valid on a later attempt.
			if atomic.AddInt32(&s.authAttempts, 1) <= atomic.LoadInt32(&s.rejectFirstN) {
				return nil, errUnauthorizedKey
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(s.hostKey)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		s.handleConn(conn, cfg)
	}
}

func (s *fakeSSHServer) handleConn(conn net.Conn, cfg *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()

	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return // auth failed (expected during the reject window)
	}
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		for req := range chReqs {
			if req.Type != "exec" {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			if s.stdout != "" {
				_, _ = ch.Write([]byte(s.stdout))
			}
			if s.stderr != "" {
				_, _ = ch.Stderr().Write([]byte(s.stderr))
			}
			// exit-status request: a single big-endian uint32.
			payload := make([]byte, 4)
			binary.BigEndian.PutUint32(payload, s.exitCode)
			_, _ = ch.SendRequest("exit-status", false, payload)
			_ = ch.Close()
			return
		}
	}
}

var errUnauthorizedKey = &sshAuthError{}

type sshAuthError struct{}

func (*sshAuthError) Error() string { return "unauthorized key" }

// writeManagedKey writes a fresh private key to a temp file and returns its
// path plus the matching public key, mirroring what sshkey.LocateOrGenerate
// hands runMCPSSHExec at runtime.
func writeManagedKey(t *testing.T) (privPath string, pub ssh.PublicKey) {
	t.Helper()
	pubOpenSSH, privPEM, err := generateEphemeralSSHKey("client")
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	privPath = filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubOpenSSH))
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	return privPath, parsed
}

// TestRunMCPSSHExec_PureGo drives the real exec path against an in-process
// SSH server: no system `ssh` binary is consulted, proving the tool works
// inside a minimal image. It asserts stdout, stderr, and exit code all
// round-trip.
func TestRunMCPSSHExec_PureGo(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // isolate known_hosts (accept-new writes here)

	privPath, pub := writeManagedKey(t)
	srv := newFakeSSHServer(t, pub, "CONNECT_OK\nhello\n", "a warning\n", 0)
	defer srv.close()

	host, portStr, err := net.SplitHostPort(srv.addr())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	target := connectcore.Target{User: "tester", Host: host, Port: port}

	out, err := runMCPSSHExec(target, privPath, "echo hi")
	if err != nil {
		t.Fatalf("runMCPSSHExec: %v", err)
	}
	if !strings.Contains(out, "exit_code: 0") {
		t.Errorf("missing exit_code 0 in:\n%s", out)
	}
	if !strings.Contains(out, "CONNECT_OK") || !strings.Contains(out, "hello") {
		t.Errorf("stdout not surfaced in:\n%s", out)
	}
	if !strings.Contains(out, "a warning") {
		t.Errorf("stderr not surfaced in:\n%s", out)
	}
}

// TestRunMCPSSHExec_NonZeroExit confirms a non-zero remote exit is returned
// as data (exit_code), not as a tool error.
func TestRunMCPSSHExec_NonZeroExit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	privPath, pub := writeManagedKey(t)
	srv := newFakeSSHServer(t, pub, "", "boom\n", 7)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	target := connectcore.Target{User: "tester", Host: host, Port: port}

	out, err := runMCPSSHExec(target, privPath, "false")
	if err != nil {
		t.Fatalf("non-zero remote exit must not be a tool error, got: %v", err)
	}
	if !strings.Contains(out, "exit_code: 7") {
		t.Errorf("expected exit_code 7 in:\n%s", out)
	}
}

// TestRunMCPSSHExec_RetriesThroughAuthRace proves the exec path retries the
// dial when the key isn't live yet (the keysync-propagation race, #830): the
// server rejects the first two otherwise-valid auths, then accepts, and
// runMCPSSHExec still succeeds.
func TestRunMCPSSHExec_RetriesThroughAuthRace(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Shrink the retry knobs so the test is fast.
	oldW, oldI := authRetryWindow, authRetryInterval
	authRetryWindow = 5 * time.Second
	authRetryInterval = 50 * time.Millisecond
	t.Cleanup(func() { authRetryWindow, authRetryInterval = oldW, oldI })

	privPath, pub := writeManagedKey(t)
	srv := newFakeSSHServer(t, pub, "CONNECT_OK\n", "", 0)
	srv.rejectFirstN = 2 // first two auths denied (key not propagated yet)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	target := connectcore.Target{User: "tester", Host: host, Port: port}

	out, err := runMCPSSHExec(target, privPath, "echo hi")
	if err != nil {
		t.Fatalf("expected retry to succeed past the auth race, got: %v", err)
	}
	if !strings.Contains(out, "CONNECT_OK") {
		t.Errorf("stdout not surfaced after retry:\n%s", out)
	}
	if got := atomic.LoadInt32(&srv.authAttempts); got < 3 {
		t.Errorf("expected ≥3 auth attempts (2 rejected + 1 accepted), got %d", got)
	}
}

// TestRunMCPSSHExec_NonAuthErrorFailsFast confirms a non-auth dial failure
// (nothing listening) is NOT retried for the whole window.
func TestRunMCPSSHExec_NonAuthErrorFailsFast(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	oldW, oldI := authRetryWindow, authRetryInterval
	authRetryWindow = 10 * time.Second
	authRetryInterval = 50 * time.Millisecond
	t.Cleanup(func() { authRetryWindow, authRetryInterval = oldW, oldI })

	privPath, _ := writeManagedKey(t)
	// 127.0.0.1:1 — nothing listening → connection refused (not an auth error).
	target := connectcore.Target{User: "tester", Host: "127.0.0.1", Port: 1}

	start := time.Now()
	_, err := runMCPSSHExec(target, privPath, "echo hi")
	if err == nil {
		t.Fatal("expected a dial error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("non-auth error should fail fast, took %s (retried the whole window?)", elapsed)
	}
}
