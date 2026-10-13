//go:build integration

package sshauthz_test

// Reuses anondoor/integration_test.go's real-sshpiperd stdio-chain pattern.
// SSHAUTHZ_SSHPIPERD and SSHAUTHZ_CONTAINARIUM supply the real binaries;
// SSHAUTHZ_YAML_PLUGIN is optional (defaults to plugins/yaml beside sshpiperd).
// The upstream is an actual SSH protocol server with an isolated test key,
// avoiding root, Docker and a shared system sshd configuration.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	authz "github.com/footprintai/containarium/internal/sentinel/sshauthz"
	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestIntegrationRealSSHPiperdAuditOnly(t *testing.T) {
	piperd, ctn := os.Getenv("SSHAUTHZ_SSHPIPERD"), os.Getenv("SSHAUTHZ_CONTAINARIUM")
	if piperd == "" || ctn == "" {
		t.Skip("set SSHAUTHZ_SSHPIPERD and SSHAUTHZ_CONTAINARIUM to run the real SSH chain")
	}
	yaml := os.Getenv("SSHAUTHZ_YAML_PLUGIN")
	if yaml == "" {
		yaml = filepath.Join(filepath.Dir(piperd), "plugins", "yaml")
	}
	for _, scenario := range []string{"allow", "deny", "grace"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			clientSigner, _ := offeredKey(t)
			upstreamHostKey, _ := offeredKey(t)
			hostKeyPath := filepath.Join(dir, "host_key")
			if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-f", hostKeyPath, "-N", "", "-q").CombinedOutput(); err != nil {
				t.Fatalf("ssh-keygen: %v %s", err, out)
			}
			hostPrivate, err := os.ReadFile(hostKeyPath)
			if err != nil {
				t.Fatal(err)
			}
			piperHostSigner, err := ssh.ParsePrivateKey(hostPrivate)
			if err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(dir, "upstream_key")
			if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-q").CombinedOutput(); err != nil {
				t.Fatalf("upstream key: %v %s", err, out)
			}
			raw, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			actualUpstreamSigner, err := ssh.ParsePrivateKey(raw)
			if err != nil {
				t.Fatal(err)
			}
			// Use an independent upstream listener with the serialized signer.
			upstreamAddr := sshUpstream(t, actualUpstreamSigner, upstreamHostKey)
			ak := filepath.Join(dir, "authorized_keys")
			if err := os.WriteFile(ak, ssh.MarshalAuthorizedKey(clientSigner.PublicKey()), 0600); err != nil {
				t.Fatal(err)
			}
			kh := filepath.Join(dir, "known_hosts")
			if err := os.WriteFile(kh, []byte(knownhosts.Line([]string{upstreamAddr}, upstreamHostKey.PublicKey())+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(dir, "config.yaml")
			cfg := fmt.Sprintf("version: \"1.0\"\npipes:\n- from:\n  - username: alice\n    authorized_keys: %s\n  to:\n    host: %s\n    username: upstream\n    private_key: %s\n    known_hosts: %s\n", ak, upstreamAddr, keyPath, kh)
			if err := os.WriteFile(config, []byte(cfg), 0600); err != nil {
				t.Fatal(err)
			}
			secret := strings.Repeat("s", auth.SentinelMinSecretLen)
			var calls atomic.Int32
			var offline atomic.Bool
			daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != authz.AuthorizePath || r.Method != http.MethodPost {
					t.Error("wrong authorization path")
					w.WriteHeader(404)
					return
				}
				data, _ := io.ReadAll(r.Body)
				if err := auth.NewSentinelVerifier(nil, []byte(secret)).VerifyBodyRequest(r, data, time.Now()); err != nil {
					t.Error(err)
					w.WriteHeader(401)
					return
				}

				req := new(pb.AuthorizeSSHRequest)
				if err := protojson.Unmarshal(data, req); err != nil || req.Login != "alice" || req.GetCredential().GetPublicKey().GetFingerprintSha256() != ssh.FingerprintSHA256(clientSigner.PublicKey()) {
					t.Errorf("authorization request %v %v", req, err)
				}
				calls.Add(1)
				if offline.Load() {
					w.WriteHeader(503)
					return
				}
				response := allow(0) // immediate TTL expiry forces the outage query to run
				if scenario == "deny" {
					response = &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY, UserId: "denied-user"}
				}
				data, err := protojson.Marshal(response)
				if err != nil {
					t.Error(err)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(data)
			}))
			defer daemon.Close()
			routes := filepath.Join(dir, "routes.json")
			if err := authz.WriteRoutes(routes, authz.Routes{Logins: map[string]string{"alice": "a"}, BackendURLs: map[string]string{"a": daemon.URL}}); err != nil {
				t.Fatal(err)
			}
			records := filepath.Join(dir, "sessions.jsonl")
			port := integrationFreePort(t)
			cmd := exec.Command(piperd, "-i", hostKeyPath, "-p", strconv.Itoa(port), "--drop-hostkeys-message", ctn, "sentinel", "ssh-authz-plugin", "--ssh-authz-routes", routes, "--", ctn, "sentinel", "ssh-session-plugin", "--records-file", records, "--sshpiper-config", config, "--", yaml, "--config", config)
			cmd.Env = append(os.Environ(), "CONTAINARIUM_SENTINEL_AUTH_SECRET="+secret, "CONTAINARIUM_SENTINEL_SIGNING_KEY=")
			logPath := filepath.Join(dir, "piper.log")
			logFile, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stdout, cmd.Stderr = logFile, logFile
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = logFile.Close() })
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			integrationWait(t, func() bool {
				c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
				if err != nil {
					return false
				}
				_ = c.Close()
				return true
			})
			connect := func() {
				client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(clientSigner)}, HostKeyCallback: ssh.FixedHostKey(piperHostSigner.PublicKey()), Timeout: 5 * time.Second})
				if err != nil {
					log, _ := os.ReadFile(logPath)
					t.Fatalf("audit-only login rejected: %v\n%s", err, log)
				}
				session, err := client.NewSession()
				if err != nil {
					_ = client.Close()
					t.Fatal(err)
				}
				out, err := session.Output("echo audit-ok")
				_ = session.Close()
				_ = client.Close()
				if err != nil || strings.TrimSpace(string(out)) != "audit-ok" {
					t.Fatalf("functional SSH command: %q %v", out, err)
				}
			}
			connect()
			expectedOpens := 1
			if scenario == "grace" {
				offline.Store(true)
				connect()
				expectedOpens = 2
			}
			var got []sshsession.Record
			integrationWait(t, func() bool {
				data, err := os.ReadFile(records)
				if err != nil {
					return false
				}
				got = nil
				for _, line := range bytes.Split(data, []byte("\n")) {
					if len(line) == 0 {
						continue
					}
					var r sshsession.Record
					if err := json.Unmarshal(line, &r); err != nil {
						return false
					}
					if r.Phase == sshsession.SessionPhaseOpen {
						got = append(got, r)
					}
				}
				return len(got) == expectedOpens
			})
			wantDecision := pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW
			wantReason := pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED
			wantUser := "user-a"
			if scenario == "deny" {
				wantDecision = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY
				wantReason = pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY
				wantUser = "denied-user"
			}
			for _, r := range got {
				if r.AuthzDecision != wantDecision || r.DenyReason != wantReason || r.UserID != wantUser || r.Enforced {
					t.Fatalf("metadata did not survive real chain: %+v", r)
				}
			}
			if int(calls.Load()) != expectedOpens {
				t.Fatalf("HTTP calls=%d want=%d", calls.Load(), expectedOpens)
			}
		})
	}
}

func sshUpstream(t *testing.T, accepted, host ssh.Signer) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), accepted.PublicKey().Marshal()) {
			return nil, fmt.Errorf("unexpected upstream key")
		}
		return nil, nil
	}}
	cfg.AddHostKey(host)
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = listener.Close(); wg.Wait() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				sc, channels, requests, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(requests)
				for newCh := range channels {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					ch, reqs, err := newCh.Accept()
					if err != nil {
						return
					}
					for req := range reqs {
						if req.Type != "exec" {
							_ = req.Reply(false, nil)
							continue
						}
						_ = req.Reply(true, nil)
						_, _ = io.WriteString(ch, "audit-ok\n")
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						_ = ch.Close()
						break
					}
				}
			}()
		}
	}()
	return listener.Addr().String()
}
func integrationFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}
func integrationWait(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("real SSH harness did not become ready")
}
