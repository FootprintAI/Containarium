//go:build integration

package sshban

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// integrationKey creates a real SSH keypair and its OpenSSH disk representation.
func integrationKey(t *testing.T, dir, name string) (string, ssh.Signer) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "ssh-ban-fixture")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	return path, signer
}

// integrationBackend requires the router's actual upstream key and serves real
// SSH session channels, so a successful proxy handshake alone cannot pass.
func integrationBackend(t *testing.T, host, upstream ssh.Signer) string {
	t.Helper()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if ssh.FingerprintSHA256(key) != ssh.FingerprintSHA256(upstream.PublicKey()) {
			return nil, fmt.Errorf("unexpected upstream key")
		}
		return nil, nil
	}}
	cfg.AddHostKey(host)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for next := range channels {
					if next.ChannelType() != "session" {
						_ = next.Reject(ssh.UnknownChannelType, "session required")
						continue
					}
					ch, reqs, err := next.Accept()
					if err != nil {
						return
					}
					for req := range reqs {
						if req.Type != "exec" {
							if req.WantReply {
								_ = req.Reply(false, nil)
							}
							continue
						}
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
						_, _ = ch.Write([]byte("ssh-ban-ok\n"))
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						_ = ch.Close()
						break
					}
				}
			}()
		}
	}()
	return l.Addr().String()
}

// integrationSSH binds an explicit source IP to model independent NAT exits.
func integrationSSH(addr, source string, key ssh.Signer) error {
	d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return err
	}
	_ = c.SetDeadline(time.Now().Add(time.Second))
	cfg := &ssh.ClientConfig{User: "fixture", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	conn, chans, reqs, err := ssh.NewClientConn(c, addr, cfg)
	if err != nil {
		_ = c.Close()
		return err
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	out, err := session.Output("echo ssh-ban-ok")
	if err == nil && strings.TrimSpace(string(out)) != "ssh-ban-ok" {
		return fmt.Errorf("unexpected backend output: %q", out)
	}
	return err
}

// TestIntegrationRealSSHPiperSourceIPBans exercises production plugin startup,
// successful bursts, shared-IP collateral, isolated unban, and fixed expiry.
// It also characterizes the same SSH outcomes against bundled failtoban.
func TestIntegrationRealSSHPiperSourceIPBans(t *testing.T) {
	piper, yaml, daemon, upstreamGuard := os.Getenv("SSH_BAN_SSHPIPERD"), os.Getenv("SSH_BAN_YAML"), os.Getenv("SSH_BAN_DAEMON"), os.Getenv("SSH_BAN_UPSTREAM_GUARD")
	if piper == "" || yaml == "" || daemon == "" || upstreamGuard == "" {
		t.Fatal("set SSH_BAN_SSHPIPERD, SSH_BAN_YAML, SSH_BAN_DAEMON, SSH_BAN_UPSTREAM_GUARD; integration prerequisites are mandatory")
	}
	for _, mode := range []string{"first-party", "upstream-parity"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			hostPath, host := integrationKey(t, dir, "host")
			clientPath, clientKey := integrationKey(t, dir, "client")
			_, wrongKey := integrationKey(t, dir, "wrong")
			upstreamPath, upstreamKey := integrationKey(t, dir, "upstream")
			backend := integrationBackend(t, host, upstreamKey)
			config := fmt.Sprintf("version: \"1.0\"\npipes:\n- from:\n  - username: fixture\n    authorized_keys: [%q]\n  to:\n    host: %q\n    username: fixture\n    private_key: %q\n    ignore_host_key: true\n", clientPath+".pub", backend, upstreamPath)
			configPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			reserved, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := reserved.Addr().String()
			port := fmt.Sprint(reserved.Addr().(*net.TCPAddr).Port)
			_ = reserved.Close()
			socket := filepath.Join(dir, "private", "main.sock")
			args := []string{"-l", "127.0.0.1", "-i", hostPath, "-p", port, "--drop-hostkeys-message", yaml, "--config", configPath, "--"}
			if mode == "first-party" {
				args = append(args, daemon, "sentinel", "ssh-ban-plugin", "--control-socket", socket, "--max-failures", "3", "--ban-duration", "4s")
			} else {
				args = append(args, upstreamGuard, "--max-failures", "3", "--ban-duration", "4s")
			}
			logFile, err := os.Create(filepath.Join(dir, "sshpiper.log"))
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(piper, args...)
			cmd.Stdout, cmd.Stderr = logFile, logFile
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				_ = logFile.Close()
				if t.Failed() {
					data, _ := os.ReadFile(logFile.Name())
					t.Logf("sshpiper: %s", data)
				}
			})
			ready := time.Now().Add(5 * time.Second)
			for {
				c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
				if err == nil {
					_ = c.Close()
					break
				}
				if time.Now().After(ready) {
					t.Fatal("sshpiperd did not become ready")
				}
				time.Sleep(10 * time.Millisecond)
			}
			for range 10 {
				if err := integrationSSH(addr, "127.0.0.2", clientKey); err != nil {
					t.Fatalf("successful burst consumed budget: %v", err)
				}
			}
			for range 3 {
				if err := integrationSSH(addr, "127.0.0.2", wrongKey); err == nil {
					t.Fatal("unregistered key authenticated")
				}
			}
			if err := integrationSSH(addr, "127.0.0.2", clientKey); err == nil {
				t.Fatal("valid key from banned shared IP was accepted")
			}
			if err := integrationSSH(addr, "127.0.0.3", clientKey); err != nil {
				t.Fatalf("unrelated source was blocked: %v", err)
			}
			if mode == "first-party" {
				conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = conn.Close() }()
				control := pb.NewSentinelSSHBanServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				state, err := control.GetSSHBan(ctx, &pb.GetSSHBanRequest{Listener: mainListener, Ip: "127.0.0.2"})
				if err != nil || state.GetStatus().GetState() != pb.SSHBanState_SSH_BAN_STATE_BANNED {
					t.Fatalf("SSH/control disagreement: %v %v", state, err)
				}
				for range 3 {
					_ = integrationSSH(addr, "127.0.0.3", wrongKey)
				}
				if _, err := control.UnbanSSHSource(ctx, &pb.UnbanSSHSourceRequest{Listener: mainListener, Ip: "127.0.0.2", Reason: "integration test"}); err != nil {
					t.Fatal(err)
				}
				if err := integrationSSH(addr, "127.0.0.2", clientKey); err != nil {
					t.Fatalf("unban did not change enforcement: %v", err)
				}
				if err := integrationSSH(addr, "127.0.0.3", clientKey); err == nil {
					t.Fatal("unban cleared the other source")
				}
				for range 3 {
					_ = integrationSSH(addr, "127.0.0.2", wrongKey)
				}
			}
			// Probe with a valid key throughout the cooldown. Recovery is mandatory;
			// a sliding ban or endless retry amplification fails this deadline.
			deadline := time.Now().Add(5 * time.Second)
			for {
				if err := integrationSSH(addr, "127.0.0.2", clientKey); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("source never recovered while retrying")
				}
				time.Sleep(25 * time.Millisecond)
			}
		})
	}
}
