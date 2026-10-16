//go:build integration && !windows

package sshauthz

// A real sshpiperd drives the production CLI plugins, then its real yaml
// routing plugin, against a stub daemon and an in-process SSH upstream.
// SSH_AUTHZ_SSHPIPERD, SSH_AUTHZ_YAML and SSH_AUTHZ_CONTAINARIUM point to the
// three binaries. No deployment, cloud account, or external sshd is required.

import (
	"bytes"
	"context"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestIntegrationAuditOnlyChain(t *testing.T) {
	piperd, yaml, ctn := os.Getenv("SSH_AUTHZ_SSHPIPERD"), os.Getenv("SSH_AUTHZ_YAML"), os.Getenv("SSH_AUTHZ_CONTAINARIUM")
	if piperd == "" || yaml == "" || ctn == "" {
		t.Skip("set SSH_AUTHZ_SSHPIPERD, SSH_AUTHZ_YAML, SSH_AUTHZ_CONTAINARIUM")
	}
	dir := t.TempDir()
	hostKey, upstreamKey := filepath.Join(dir, "host_key"), filepath.Join(dir, "upstream_key")
	for _, path := range []string{hostKey, upstreamKey} {
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v %s", err, out)
		}
	}
	raw, err := os.ReadFile(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	upstream := integrationSSHServer(t, hostSigner)
	allowKey, denyKey := testKey(t), testKey(t)
	allowFP := ssh.FingerprintSHA256(allowKey.PublicKey())
	keysFile := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(keysFile, append(ssh.MarshalAuthorizedKey(allowKey.PublicKey()), ssh.MarshalAuthorizedKey(denyKey.PublicKey())...), 0600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(dir, "config.yaml")
	config := fmt.Sprintf("version: \"1.0\"\npipes:\n  - from:\n      - username: alice\n        authorized_keys:\n          - %s\n    to:\n      username: alice\n      host: %s\n      private_key: %s\n      ignore_hostkey: true\n", keysFile, upstream, upstreamKey)
	if err := os.WriteFile(configFile, []byte(config), 0400); err != nil {
		t.Fatal(err)
	}

	var outage atomic.Bool
	var calls atomic.Int32
	secret := []byte("integration-sentinel-secret-32-bytes")
	verifier := auth.NewSentinelVerifier(nil, secret)
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != AuthorizePath || r.Method != http.MethodPost {
			t.Error("wrong daemon request")
			w.WriteHeader(404)
			return
		}
		if err := verifier.VerifyRequest(r, time.Now()); err != nil {
			t.Errorf("signature: %v", err)
			w.WriteHeader(401)
			return
		}
		if outage.Load() {
			w.WriteHeader(503)
			return
		}
		var wire json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		req := &pb.AuthorizeSSHRequest{}
		if err := protojson.Unmarshal(wire, req); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		res := &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY}
		if req.GetCredential().GetPublicKey().GetFingerprintSha256() == allowFP {
			res = allowed("user-allow")
		}
		raw, _ := protojson.Marshal(res)
		_, _ = w.Write(raw)
	}))
	defer daemon.Close()
	socket := filepath.Join(dir, "authz.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	resolver := resolverFunc(func(_ context.Context, login string) (string, bool, error) {
		return "backend-test", login == "alice", nil
	})
	authorizer := &HTTPAuthorizer{BackendURL: func(string) (string, error) { return daemon.URL, nil }, Sign: func(r *http.Request) { auth.SignSentinelRequest(r, secret) }}
	bridge := &http.Server{Handler: BridgeHandler(resolver, authorizer), ReadHeaderTimeout: time.Second}
	defer bridge.Close()
	go func() { _ = bridge.Serve(ln) }()
	records := filepath.Join(dir, "sessions.jsonl")
	port := integrationFreePort(t)
	logFile, err := os.Create(filepath.Join(dir, "piper.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd := exec.Command(piperd, "-l", "127.0.0.1", "-p", strconv.Itoa(port), "-i", hostKey, "--drop-hostkeys-message",
		ctn, "sentinel", "ssh-authz-plugin", "--ssh-authz-socket", socket, "--ssh-authz-grace", "2s", "--",
		ctn, "sentinel", "ssh-session-plugin", "--records-file", records, "--sshpiper-config", configFile, "--", yaml, "--config", configFile)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			logs, _ := os.ReadFile(logFile.Name())
			t.Log(string(logs))
		}
	}()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sshpiperd not listening")
		}
		time.Sleep(25 * time.Millisecond)
	}

	connect := func(key ssh.Signer) {
		t.Helper()
		client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second}) //nolint:gosec // loopback test
		if err != nil {
			t.Fatalf("audit-only login failed: %v", err)
		}
		defer client.Close()
		s, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		out, err := s.Output("echo audit-ok")
		if err != nil || strings.TrimSpace(string(out)) != "audit-ok" {
			t.Fatalf("session: %q %v", out, err)
		}
	}
	assertOpen := func(index int, decision sshsession.AuthzDecision, reason sshsession.DenyReason, user string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			data, _ := os.ReadFile(records)
			var open []sshsession.Record
			for _, line := range bytes.Split(data, []byte("\n")) {
				var rec sshsession.Record
				if json.Unmarshal(line, &rec) == nil && rec.Phase == sshsession.SessionPhaseOpen {
					open = append(open, rec)
				}
			}
			if len(open) > index {
				rec := open[index]
				if rec.UserID != user || rec.AuthzDecision != sshsession.DecisionToProto(decision) || rec.DenyReason != sshsession.ReasonToProto(reason) || rec.Enforced {
					t.Fatalf("open %d: %+v", index, rec)
				}
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("missing open %d: %s", index, data)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	connect(allowKey)
	assertOpen(0, sshsession.AuthzAllow, "", "user-allow")
	connect(denyKey)
	assertOpen(1, sshsession.AuthzDeny, sshsession.DenyUnknownKey, "")
	outage.Store(true)
	connect(allowKey)
	assertOpen(2, sshsession.AuthzAllow, "", "user-allow")
	if calls.Load() != 3 {
		t.Fatalf("grace must follow failed revalidation; calls=%d", calls.Load())
	}
	time.Sleep(2100 * time.Millisecond)
	connect(allowKey)
	assertOpen(3, sshsession.AuthzDeny, sshsession.DenyUpstreamUnavailable, "")
}

func integrationFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func integrationSSHServer(t *testing.T, host ssh.Signer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(host)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					if ch.ChannelType() != "session" {
						_ = ch.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					channel, requests, err := ch.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer channel.Close()
						for r := range requests {
							if r.Type == "exec" {
								_ = r.Reply(true, nil)
								_, _ = channel.Write([]byte("audit-ok\n"))
								_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								return
							}
							_ = r.Reply(false, nil)
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String()
}
