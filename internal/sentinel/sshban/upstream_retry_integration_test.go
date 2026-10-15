//go:build integration && linux

package sshban

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

// retryFixture runs the production plugin chain under a syscall tracer so
// failed TCP attempts are observable even when no backend is listening.
type retryFixture struct {
	password                 bool
	listener                 pb.SSHBanListener
	addr, backend, tracePath string
	keys                     []ssh.Signer
	keyPaths                 []string
	host, upstream           ssh.Signer
	control                  pb.SentinelSSHBanServiceClient
}

// retryMode keeps transport and host-key comparisons explicit at each callsite.
type retryMode struct {
	bundled, routed, pinnedHost, anonymous, certificate, wrongPrincipal, password bool
	controlSocket, backend, backendUser                                           string
}

// retryUnusedAddress reserves and releases an ephemeral loopback destination.
// A test restoring the backend binds this same address again explicitly.
func retryUnusedAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// newRetryFixture selects the first-party production failure policy.
func newRetryFixture(t *testing.T, threshold, keyCount int) *retryFixture {
	t.Helper()
	return newRetryFixtureMode(t, threshold, keyCount, false)
}

// newRetryFixtureMode authorizes synthetic keys in the real YAML plugin and
// guarantees teardown for either the owned or bundled failure-policy process.
func newRetryFixtureMode(t *testing.T, threshold, keyCount int, bundled bool, routed ...bool) *retryFixture {
	t.Helper()
	return newConfiguredRetryFixture(t, threshold, keyCount, retryMode{bundled: bundled, routed: len(routed) > 0 && routed[0]})
}

// newConfiguredRetryFixture can require a pinned backend host key while keeping
// the same child YAML authorization and real process topology.
func newConfiguredRetryFixture(t *testing.T, threshold, keyCount int, mode retryMode) *retryFixture {
	t.Helper()
	piper, yaml, daemon := os.Getenv("SSH_BAN_SSHPIPERD"), os.Getenv("SSH_BAN_YAML"), os.Getenv("SSH_BAN_DAEMON")
	if piper == "" || yaml == "" || daemon == "" {
		t.Fatal("set SSH_BAN_SSHPIPERD, SSH_BAN_YAML and SSH_BAN_DAEMON; real integration prerequisites are mandatory")
	}
	tracer := os.Getenv("SSH_UPSTREAM_STRACE")
	if tracer == "" {
		var err error
		tracer, err = exec.LookPath("strace")
		if err != nil {
			t.Fatal("install strace or set SSH_UPSTREAM_STRACE; TCP attempts must be measured, not inferred from SSH errors")
		}
	}
	dir := t.TempDir()
	f := &retryFixture{backend: retryUnusedAddress(t), addr: retryUnusedAddress(t), tracePath: filepath.Join(dir, "connect.trace"), listener: mainListener}
	if mode.backend != "" {
		f.backend = mode.backend
	}
	hostPath, host := integrationKey(t, dir, "host")
	upstreamPath, upstream := integrationKey(t, dir, "upstream")
	f.host, f.upstream = host, upstream
	var paths []string
	for i := range keyCount {
		path, key := integrationKey(t, dir, fmt.Sprintf("client-%d", i))
		paths = append(paths, strconv.Quote(path+".pub"))
		f.keys = append(f.keys, key)
		f.keyPaths = append(f.keyPaths, path)
	}
	config := fmt.Sprintf("version: \"1.0\"\npipes:\n- from:\n  - username: fixture\n    authorized_keys: [%s]\n  to:\n    host: %q\n    username: fixture\n    private_key: %q\n    ignore_host_key: true\n", strings.Join(paths, ", "), f.backend, upstreamPath)
	if mode.password {
		f.password = true
		config = fmt.Sprintf("version: \"1.0\"\npipes:\n- from:\n  - username: fixture\n  to:\n    host: %q\n    username: fixture\n", f.backend)
	}
	if mode.certificate {
		caPath, ca := integrationKey(t, dir, "user-ca")
		principal := "fixture"
		if mode.wrongPrincipal {
			principal = "unrelated-user"
		}
		cert := &ssh.Certificate{Key: f.keys[0].PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{principal}, ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
		if err := cert.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewCertSigner(cert, f.keys[0])
		if err != nil {
			t.Fatal(err)
		}
		f.keys[0] = signer
		config = strings.Replace(config, "    authorized_keys: ["+strings.Join(paths, ", ")+"]", "    trusted_user_ca_keys: ["+strconv.Quote(caPath+".pub")+"]", 1)
	}
	if mode.pinnedHost {
		knownPath := filepath.Join(dir, "known_hosts")
		if err := os.WriteFile(knownPath, []byte(knownhosts.Line([]string{f.backend}, host.PublicKey())+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		config = strings.Replace(config, "    ignore_host_key: true", "    known_hosts: "+strconv.Quote(knownPath), 1)
	}
	if mode.backendUser != "" {
		config = strings.ReplaceAll(config, "username: fixture\n    private_key:", "username: "+mode.backendUser+"\n    private_key:")
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(f.addr)
	if err != nil {
		t.Fatal(err)
	}
	listener := "main"
	if mode.anonymous {
		listener = "anonymous"
		f.listener = pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS
	}
	socket := filepath.Join(dir, "private", listener+".sock")
	logPath := filepath.Join(dir, "sshpiper.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-f", "-ttt", "-s", "256", "-e", "trace=connect", "-o", f.tracePath, "--", piper,
		"-l", "127.0.0.1", "-p", port, "-i", hostPath, "--log-level", "debug", "--login-grace-time", "5s", "--drop-hostkeys-message"}
	router := []string{yaml, "--config", configPath}
	if mode.anonymous {
		// The real anon plugin retains its Ensure and upstream-key behavior;
		// only its daemon's provisioning response is a typed contract stub.
		host, port, err := net.SplitHostPort(f.backend)
		if err != nil {
			t.Fatal(err)
		}
		number, err := strconv.ParseInt(port, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		backendUser := mode.backendUser
		if backendUser == "" {
			backendUser = "fixture"
		}
		response, err := protojson.Marshal(&pb.EnsureAnonymousBoxResponse{SshHost: host, SshPort: int32(number), SshUser: backendUser, BoxName: "synthetic-box"})
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/anon/boxes:ensure" {
				http.Error(w, "unexpected ensure route", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(response)
		}))
		t.Cleanup(server.Close)
		router = []string{daemon, "sentinel", "anon-door-plugin", "--daemon-url", server.URL, "--upstream-key", upstreamPath}
		if mode.controlSocket != "" {
			router = append(router, "--upstream-control-socket", mode.controlSocket)
		}
	}
	if mode.routed {
		args = append(args, daemon, "sentinel", "ssh-upstream-plugin", "--plugin", router[0])
		if mode.controlSocket != "" {
			args = append(args, "--upstream-control-socket", mode.controlSocket, "--listener", listener)
		}
		for _, arg := range router[1:] {
			args = append(args, "--plugin-arg="+arg)
		}
	} else {
		args = append(args, router...)
	}
	args = append(args, "--")
	if mode.bundled {
		guard := os.Getenv("SSH_BAN_UPSTREAM_GUARD")
		if guard == "" {
			_ = logFile.Close()
			t.Fatal("set SSH_BAN_UPSTREAM_GUARD for the pinned pre-#2556 comparison")
		}
		args = append(args, guard)
	} else {
		args = append(args, daemon, "sentinel", "ssh-ban-plugin", "--listener", listener, "--control-socket", socket)
		if mode.controlSocket != "" {
			args = append(args, "--upstream-control-socket", mode.controlSocket)
		}
	}
	args = append(args, "--max-failures", strconv.Itoa(threshold), "--ban-duration", "5m")
	cmd := exec.Command(tracer, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		_ = logFile.Close()
		if root := os.Getenv("SSH_UPSTREAM_EVIDENCE_DIR"); root != "" {
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Error(err)
				return
			}
			out, err := os.MkdirTemp(root, strings.ReplaceAll(t.Name(), "/", "-")+"-")
			if err != nil {
				t.Error(err)
				return
			}
			artifacts := []string{f.tracePath, logPath}
			if _, err := os.Stat(filepath.Join(dir, "openssh.log")); err == nil {
				artifacts = append(artifacts, filepath.Join(dir, "openssh.log"))
			}
			for _, path := range artifacts {
				data, err := os.ReadFile(path)
				if err == nil {
					err = os.WriteFile(filepath.Join(out, filepath.Base(path)), data, 0600)
				}
				if err != nil {
					t.Error(err)
				}
			}
			t.Logf("evidence: %s (trace and logs only; fixture private keys are not copied)", out)
		}
		if t.Failed() {
			data, _ := os.ReadFile(logPath)
			t.Logf("sshpiper log:\n%s", data)
		}
	})
	deadline := time.Now().Add(8 * time.Second)
	for {
		select {
		case err := <-done:
			// Preserve the exit result for cleanup's single receive.
			done <- err
			t.Fatalf("traced sshpiperd exited before readiness: %v", err)
		default:
		}
		c, err := net.DialTimeout("tcp", f.addr, 25*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("traced sshpiperd did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if mode.bundled {
		return f
	}
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	f.control = pb.NewSentinelSSHBanServiceClient(conn)
	return f
}

// TestIntegrationSSHUpstreamPinnedHostKey prevents solving retry amplification
// by silently opting out of the selected router's host identity policy.
func TestIntegrationSSHUpstreamPinnedHostKey(t *testing.T) {
	for _, routed := range []bool{false, true} {
		for _, wrong := range []bool{false, true} {
			t.Run(fmt.Sprintf("adapter=%v/wrong-key=%v", routed, wrong), func(t *testing.T) {
				f := newConfiguredRetryFixture(t, 100, 1, retryMode{routed: routed, pinnedHost: true})
				if wrong {
					_, f.host = integrationKey(t, t.TempDir(), "wrong-backend-host")
				}
				f.retryBackend(t)
				err := retryHandshake(f.addr, "127.0.0.2", f.keys[0])
				if (err != nil) != wrong {
					t.Fatalf("pinned host policy changed: wrong=%v error=%v", wrong, err)
				}
			})
		}
	}
}

// TestIntegrationSSHUpstreamAnonymousTransportHook proves the second routing
// plugin reaches the same transport hook and retains its configured proxy key.
func TestIntegrationSSHUpstreamAnonymousTransportHook(t *testing.T) {
	f := newConfiguredRetryFixture(t, 100, 1, retryMode{routed: true, anonymous: true})
	if err := retryHandshake(f.addr, "127.0.0.2", f.keys[0]); err == nil {
		t.Fatal("unavailable backend unexpectedly accepted a session")
	}
	if got := f.status(t, "127.0.0.2").Listener; got != pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS {
		t.Fatalf("anonymous chain used the wrong failure-policy listener: %v", got)
	}
	if got := len(f.attempts(t)); got != 1 {
		t.Fatalf("anonymous route bypassed transport hook: %d backend dials", got)
	}
	f.retryBackend(t)
	if err := retryHandshake(f.addr, "127.0.0.3", f.keys[0]); err != nil {
		t.Fatalf("anonymous route lost the ensured endpoint or proxy key: %v", err)
	}
	if got := len(f.attempts(t)); got != 2 {
		t.Fatalf("unexpected anonymous backend dial count: %d", got)
	}
}

// TestIntegrationSSHUpstreamCertificateAuthorization keeps CA authorization and
// principal rejection in the real YAML router when transport creation is owned.
func TestIntegrationSSHUpstreamCertificateAuthorization(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrong-principal=%v", wrong), func(t *testing.T) {
			f := newConfiguredRetryFixture(t, 100, 1, retryMode{routed: true, certificate: true, wrongPrincipal: wrong})
			f.retryBackend(t)
			err := retryHandshake(f.addr, "127.0.0.2", f.keys[0])
			if (err != nil) != wrong {
				t.Fatalf("certificate policy changed: wrong principal=%v error=%v", wrong, err)
			}
			want := 1
			if wrong {
				want = 0
			}
			if got := len(f.attempts(t)); got != want {
				t.Fatalf("certificate selection reached backend %d times, want %d", got, want)
			}
		})
	}
}

// TestIntegrationSSHUpstreamHookRetainsFailurePolicy records the first increment's
// explicit limit: transport interception alone does not change #933 accounting.
func TestIntegrationSSHUpstreamHookRetainsFailurePolicy(t *testing.T) {
	f := newRetryFixtureMode(t, 3, 1, false, true)
	for i := uint64(1); i <= 3; i++ {
		if err := retryHandshake(f.addr, "127.0.0.2", f.keys[0]); err == nil {
			t.Fatal("unavailable backend unexpectedly accepted a session")
		}
		f.waitForFailures(t, "127.0.0.2", i)
	}
	if got := len(f.attempts(t)); got != 3 {
		t.Fatalf("got %d dials across three connections, want 3", got)
	}
	if f.status(t, "127.0.0.2").Status.State != pb.SSHBanState_SSH_BAN_STATE_BANNED {
		t.Fatal("transport spike silently weakened existing source failure policy")
	}
}

// retryHandshake uses one explicit downstream TCP connection and optionally
// offers multiple authorized client identities on that same connection.
func retryHandshake(addr, source string, keys ...ssh.Signer) error {
	return retryHandshakeAuth(addr, source, ssh.PublicKeys(keys...))
}

// retryHandshakeAuth exercises authentication retries on one downstream socket.
func retryHandshakeAuth(addr, source string, auth ...ssh.AuthMethod) error {
	dialer := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	c, err := dialer.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	cfg := &ssh.ClientConfig{User: "fixture", Auth: auth, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	conn, _, _, err := ssh.NewClientConn(c, addr, cfg)
	if err == nil {
		_ = conn.Close()
	}
	return err
}

// attempts counts actual connect(2) calls to exactly this backend destination;
// tracing the entire process family also captures connections opened by plugins.
func (f *retryFixture) attempts(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(f.tracePath)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(f.backend)
	if err != nil {
		t.Fatal(err)
	}
	var matches []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "connect(") && strings.Contains(line, "sin_port=htons("+port+")") && strings.Contains(line, "inet_addr(\""+host+"\")") {
			matches = append(matches, line)
		}
	}
	return matches
}

// observeQuiet continuously checks for autonomous redials after a client stops;
// this is a measured observation interval, not a readiness sleep.
func (f *retryFixture) observeQuiet(t *testing.T, duration time.Duration) {
	t.Helper()
	want := len(f.attempts(t))
	timer, ticker := time.NewTimer(duration), time.NewTicker(20*time.Millisecond)
	defer timer.Stop()
	defer ticker.Stop()
	for {
		select {
		case <-timer.C:
			if got := len(f.attempts(t)); got != want {
				t.Fatalf("autonomous upstream redial: before=%d after=%d", want, got)
			}
			return
		case <-ticker.C:
			if got := len(f.attempts(t)); got != want {
				t.Fatalf("autonomous upstream redial: before=%d after=%d", want, got)
			}
		}
	}
}

// retryBackend restores the exact destination with a real SSH server and counts
// accepted transports independently from strace's attempted connections.
func (f *retryFixture) retryBackend(t *testing.T) *atomic.Int64 {
	t.Helper()
	var accepted atomic.Int64
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if ssh.FingerprintSHA256(key) != ssh.FingerprintSHA256(f.upstream.PublicKey()) {
			return nil, fmt.Errorf("unexpected upstream key")
		}
		return nil, nil
	}}
	cfg.AddHostKey(f.host)
	if f.password {
		cfg.PublicKeyCallback = nil
		cfg.PasswordCallback = func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != "correct-fixture-password" {
				return nil, fmt.Errorf("incorrect fixture password")
			}
			return nil, nil
		}
	}
	l, err := net.Listen("tcp", f.backend)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer func() { _ = server.Close() }()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					_ = channel.Reject(ssh.Prohibited, "handshake measurement only")
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		wg.Wait()
	})
	return &accepted
}

// status reads the authoritative source-IP failure state for this live plugin.
func (f *retryFixture) status(t *testing.T, ip string) *pb.GetSSHBanResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	state, err := f.control.GetSSHBan(ctx, &pb.GetSSHBanRequest{Listener: f.listener, Ip: ip})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// waitForFailures polls for the asynchronous pipe-create notice; a client may
// finish its handshake before the enforcing plugin receives that notice.
func (f *retryFixture) waitForFailures(t *testing.T, ip string, minimum uint64) *pb.GetSSHBanResponse {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		state := f.status(t, ip)
		if state.GetStatus().GetFailures() >= minimum {
			return state
		}
		if time.Now().After(deadline) {
			t.Fatalf("failure callback did not arrive: want at least %d, got %v", minimum, state)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestIntegrationSSHPiperUpstreamRetryCharacterization measures existing
// behavior for #1138; passing establishes observations, not a backoff fix.
func TestIntegrationSSHPiperUpstreamRetryCharacterization(t *testing.T) {
	t.Run("one_client_then_idle", func(t *testing.T) {
		f := newRetryFixture(t, 100, 1)
		if err := retryHandshake(f.addr, "127.0.0.2", f.keys...); err == nil {
			t.Fatal("unavailable backend authenticated")
		}
		attempts := len(f.attempts(t))
		if attempts == 0 {
			t.Fatal("no upstream connect syscall observed")
		}
		observe := 500 * time.Millisecond
		if raw := os.Getenv("SSH_UPSTREAM_IDLE_OBSERVE"); raw != "" {
			var err error
			observe, err = time.ParseDuration(raw)
			if err != nil || observe < 100*time.Millisecond || observe > 3*time.Minute {
				t.Fatalf("SSH_UPSTREAM_IDLE_OBSERVE must be between 100ms and 3m: %q", raw)
			}
		}
		f.observeQuiet(t, observe)
		t.Logf("downstream_connections=1 backend_connect_calls=%d idle_observation=%s autonomous_redials=0", attempts, observe)
	})
	t.Run("sequential_client_reconnects", func(t *testing.T) {
		f := newRetryFixture(t, 100, 1)
		start := time.Now()
		for range 12 {
			if err := retryHandshake(f.addr, "127.0.0.2", f.keys...); err == nil {
				t.Fatal("unavailable backend authenticated")
			}
		}
		elapsed := time.Since(start)
		attempts := len(f.attempts(t))
		if attempts < 12 {
			t.Fatalf("upstream attempts=%d, want at least one per client reconnect", attempts)
		}
		f.observeQuiet(t, 200*time.Millisecond)
		t.Logf("downstream_connections=12 backend_connect_calls=%d elapsed=%s calls_per_second=%.1f", attempts, elapsed, float64(attempts)/elapsed.Seconds())
	})
	t.Run("bundled_failtoban_one_key_one_connection", func(t *testing.T) {
		f := newRetryFixtureMode(t, 100, 1, true)
		if err := retryHandshake(f.addr, "127.0.0.2", f.keys...); err == nil {
			t.Fatal("unavailable backend authenticated")
		}
		attempts := len(f.attempts(t))
		if attempts <= 1 {
			t.Fatalf("bundled upstream comparison did not reproduce dial amplification: %d", attempts)
		}
		f.observeQuiet(t, 200*time.Millisecond)
		t.Logf("guard=bundled_failtoban downstream_connections=1 authorized_identities=1 backend_connect_calls=%d", attempts)
	})
	t.Run("concurrent_independent_sources", func(t *testing.T) {
		f := newRetryFixture(t, 100, 1)
		start := make(chan struct{})
		results := make(chan error, 12)
		for i := range 12 {
			go func() {
				<-start
				results <- retryHandshake(f.addr, fmt.Sprintf("127.0.0.%d", i+2), f.keys...)
			}()
		}
		began := time.Now()
		close(start)
		for range 12 {
			if err := <-results; err == nil {
				t.Fatal("unavailable backend authenticated")
			}
		}
		elapsed := time.Since(began)
		attempts := len(f.attempts(t))
		if attempts < 12 {
			t.Fatalf("upstream attempts=%d, want at least one per independent client", attempts)
		}
		f.observeQuiet(t, 200*time.Millisecond)
		t.Logf("downstream_connections=12 distinct_sources=12 backend_connect_calls=%d elapsed=%s calls_per_second=%.1f", attempts, elapsed, float64(attempts)/elapsed.Seconds())
	})
	t.Run("multiple_keys_one_connection", func(t *testing.T) {
		f := newRetryFixture(t, 100, 3)
		if err := retryHandshake(f.addr, "127.0.0.2", f.keys...); err == nil {
			t.Fatal("unavailable backend authenticated")
		}
		attempts := len(f.attempts(t))
		if attempts < len(f.keys) {
			t.Fatalf("upstream attempts=%d, want each authorized candidate key characterized", attempts)
		}
		f.observeQuiet(t, 200*time.Millisecond)
		t.Logf("downstream_connections=1 authorized_candidate_keys=%d backend_connect_calls=%d", len(f.keys), attempts)
	})
	t.Run("openssh_one_key_one_connection", func(t *testing.T) {
		f := newRetryFixture(t, 100, 1)
		client, err := exec.LookPath("ssh")
		if err != nil {
			t.Fatal("OpenSSH client is required to cross-check the Go SSH client")
		}
		_, port, err := net.SplitHostPort(f.addr)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, client, "-vvv", "-F", "/dev/null", "-i", f.keyPaths[0],
			"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
			"-o", "PreferredAuthentications=publickey", "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=4",
			"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
			"-o", "BindAddress=127.0.0.2", "-p", port, "fixture@127.0.0.1", "true")
		out, err := cmd.CombinedOutput()
		if err == nil || ctx.Err() != nil {
			t.Fatalf("unavailable-backend OpenSSH must fail within the deadline: err=%v context=%v", err, ctx.Err())
		}
		if err := os.WriteFile(filepath.Join(filepath.Dir(f.tracePath), "openssh.log"), out, 0600); err != nil {
			t.Fatal(err)
		}
		attempts := len(f.attempts(t))
		if attempts == 0 {
			t.Fatalf("OpenSSH did not reach the backend: %s", out)
		}
		f.observeQuiet(t, 200*time.Millisecond)
		t.Logf("openssh_connection_attempts_option=1 authorized_identities=1 backend_connect_calls=%d public_key_offers=%d partial_success_messages=%d", attempts, strings.Count(string(out), "Offering public key:"), strings.Count(string(out), "Authenticated using \"publickey\" with partial success"))
	})
	t.Run("healthy_successful_burst", func(t *testing.T) {
		f := newRetryFixture(t, 100, 1)
		accepted := f.retryBackend(t)
		start := time.Now()
		for range 12 {
			if err := retryHandshake(f.addr, "127.0.0.2", f.keys...); err != nil {
				t.Fatalf("healthy backend: %v", err)
			}
		}
		elapsed := time.Since(start)
		attempts := len(f.attempts(t))
		state := f.status(t, "127.0.0.2")
		if attempts < 12 || accepted.Load() != int64(attempts) || state.GetStatus().GetFailures() != 0 {
			t.Fatalf("connect_calls=%d accepted=%d failure_state=%v", attempts, accepted.Load(), state.GetStatus())
		}
		t.Logf("successful_connections=12 backend_connect_calls=%d backend_accepted=%d failed_callbacks=0 elapsed=%s", attempts, accepted.Load(), elapsed)
	})
	t.Run("outage_ban_survives_backend_recovery", func(t *testing.T) {
		f := newRetryFixture(t, 3, 1)
		var state *pb.GetSSHBanResponse
		failures := 0
		for failures < 3 {
			if err := retryHandshake(f.addr, "127.0.0.2", f.keys...); err == nil {
				t.Fatal("unavailable backend authenticated")
			}
			failures++
			state = f.waitForFailures(t, "127.0.0.2", uint64(failures))
			if state.GetStatus().GetState() == pb.SSHBanState_SSH_BAN_STATE_BANNED {
				break
			}
		}
		if state.GetStatus().GetState() != pb.SSHBanState_SSH_BAN_STATE_BANNED {
			t.Fatalf("outage did not consume source failure budget: %v", state)
		}
		before := len(f.attempts(t))
		accepted := f.retryBackend(t)
		if err := retryHandshake(f.addr, "127.0.0.2", f.keys...); err == nil {
			t.Fatal("banned source recovered merely because backend returned")
		}
		if got := len(f.attempts(t)); got != before || accepted.Load() != 0 {
			t.Fatalf("banned source reached backend: before=%d after=%d accepted=%d", before, got, accepted.Load())
		}
		if err := retryHandshake(f.addr, "127.0.0.3", f.keys...); err != nil {
			t.Fatalf("independent source could not use restored backend: %v", err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if _, err := f.control.UnbanSSHSource(ctx, &pb.UnbanSSHSourceRequest{Listener: mainListener, Ip: "127.0.0.2", Reason: "#1138 outage characterization"}); err != nil {
			t.Fatal(err)
		}
		if err := retryHandshake(f.addr, "127.0.0.2", f.keys...); err != nil {
			t.Fatalf("targeted unban did not restore healthy backend access: %v", err)
		}
		t.Logf("failed_client_connections=%d backend_connect_calls_before_ban=%d failed_callbacks=%d restored_backend_still_rejected_banned_source=true independent_source_succeeds=true targeted_unban_recovers=true", failures, before, state.GetStatus().GetFailures())
	})
}

// TestIntegrationSSHUpstreamRoutingTransportHook proves the selected router's
// CreateConn hook owns every real backend socket without granting a bad key.
func TestIntegrationSSHUpstreamRoutingTransportHook(t *testing.T) {
	f := newRetryFixtureMode(t, 100, 1, false, true)
	if err := retryHandshake(f.addr, "127.0.0.2", f.keys[0]); err == nil {
		t.Fatal("unavailable backend unexpectedly accepted a session")
	}
	if got := len(f.attempts(t)); got != 1 {
		t.Fatalf("hook did not reduce the protocol-driven dial amplification: got %d actual dials, want 1", got)
	}
	accepted := f.retryBackend(t)
	if err := retryHandshake(f.addr, "127.0.0.3", f.keys[0]); err != nil {
		t.Fatalf("adapter lost authorized upstream credential: %v", err)
	}
	_, bad := integrationKey(t, t.TempDir(), "unauthorized")
	if err := retryHandshake(f.addr, "127.0.0.4", bad); err == nil {
		t.Fatal("adapter granted an unauthorized client")
	}
	if got := len(f.attempts(t)); got != 2 || accepted.Load() != 1 {
		t.Fatalf("unauthorized attempt reached backend: dials=%d accepted=%d", got, accepted.Load())
	}
}

// TestIntegrationSSHUpstreamProxyCredentialFailure distinguishes a reachable
// backend rejecting the configured proxy key from a refused TCP connection.
func TestIntegrationSSHUpstreamProxyCredentialFailure(t *testing.T) {
	for _, routed := range []bool{false, true} {
		t.Run(fmt.Sprintf("adapter=%v", routed), func(t *testing.T) {
			f := newConfiguredRetryFixture(t, 100, 1, retryMode{routed: routed})
			_, f.upstream = integrationKey(t, t.TempDir(), "different-expected-proxy-key")
			accepted := f.retryBackend(t)
			if err := retryHandshake(f.addr, "127.0.0.2", f.keys[0]); err == nil {
				t.Fatal("backend accepted a rejected proxy credential")
			}
			calls := len(f.attempts(t))
			if calls != 7 || int64(calls) != accepted.Load() {
				t.Fatalf("proxy-key rejection was not measured against a reachable backend: connects=%d accepted=%d", calls, accepted.Load())
			}
			failures := f.waitForFailures(t, "127.0.0.2", 8).Status.Failures
			if failures != 8 {
				t.Fatalf("proxy auth failures changed source-policy accounting: %d callbacks, want 8", failures)
			}
			t.Logf("adapter=%v rejected_proxy_key=true backend_connect_calls=%d client_failure_callbacks=%d", routed, calls, failures)
		})
	}
}

// TestIntegrationSSHUpstreamPasswordRetry preserves a legitimate corrected
// password on the same socket instead of mistaking it for a pending setup.
func TestIntegrationSSHUpstreamPasswordRetry(t *testing.T) {
	for _, routed := range []bool{false, true} {
		t.Run(fmt.Sprintf("adapter=%v", routed), func(t *testing.T) {
			f := newConfiguredRetryFixture(t, 100, 1, retryMode{routed: routed, password: true})
			f.retryBackend(t)
			offers := 0
			auth := ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
				offers++
				if offers == 1 {
					return "wrong-fixture-password", nil
				}
				return "correct-fixture-password", nil
			}), 2)
			if err := retryHandshakeAuth(f.addr, "127.0.0.2", auth); err != nil {
				t.Fatalf("corrected password could not authenticate: %v", err)
			}
			if offers != 2 || len(f.attempts(t)) != 2 {
				t.Fatalf("password retry changed: offers=%d backend connects=%d", offers, len(f.attempts(t)))
			}
		})
	}
}
