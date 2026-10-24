//go:build integration

package anondoor

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

const approvalInstruction = "Approve this device at https://approval.example.com, code TEST-2524"
const approvalPrompt = "press Enter once approved: "

// TestIntegration_ApprovalPluginProcess runs in a child process as the throwaway
// stdio plugin. The parent reuses its test binary, so no production command or
// separately built plugin is needed. Never write the test runner's PASS to the
// gRPC transport.
func TestIntegration_ApprovalPluginProcess(t *testing.T) {
	if os.Getenv("ANONDOOR_APPROVAL_PLUGIN") != "1" {
		return
	}
	key, err := os.ReadFile(os.Getenv("ANONDOOR_APPROVAL_UPSTREAM_KEY"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	p, err := libplugin.NewFromStdio(libplugin.SshPiperPluginConfig{
		NextAuthMethodsCallback: func(conn libplugin.ConnMetadata) ([]string, error) {
			if conn.GetMeta("approval_pending") == "true" {
				return []string{"keyboard-interactive"}, nil
			}
			return []string{"publickey"}, nil
		},
		PublicKeyCallback: func(_ libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
			pub, err := ssh.ParsePublicKey(key)
			if err != nil || ssh.FingerprintSHA256(pub) != os.Getenv("ANONDOOR_APPROVAL_FINGERPRINT") {
				return nil, fmt.Errorf("unexpected client key")
			}
			return &libplugin.Upstream{Auth: libplugin.CreateRetryCurrentPluginAuth(map[string]string{
				"approval_pending": "true",
			})}, nil
		},
		KeyboardInteractiveCallback: func(conn libplugin.ConnMetadata, challenge libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {
			if conn.GetMeta("approval_pending") != "true" {
				return nil, fmt.Errorf("publickey must precede approval")
			}
			answer, err := challenge(conn.User(), approvalInstruction, approvalPrompt, false)
			if err != nil {
				return nil, err
			}
			if answer != "" {
				return nil, fmt.Errorf("expected Enter")
			}
			return &libplugin.Upstream{
				Uri: "tcp://" + os.Getenv("ANONDOOR_APPROVAL_UPSTREAM"), UserName: "approval-test",
				Auth: libplugin.CreatePrivateKeyAuth(key),
			}, nil
		},
	})
	if err == nil {
		err = p.Serve()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

// TestIntegration_PublicKeyPartialSuccessKeyboardInteractive characterizes
// libplugin v1.6.1 with a real sshpiperd and the stock OpenSSH client. It fails
// if the retry loses metadata, skips the key signature, hides the instruction,
// or cannot open an upstream session after the answer.
//
//	ANONDOOR_SSHPIPERD=/path/to/sshpiperd go test -tags integration -count=1 -v \
//	  ./internal/sentinel/anondoor -run '^TestIntegration_PublicKeyPartialSuccessKeyboardInteractive$'
func TestIntegration_PublicKeyPartialSuccessKeyboardInteractive(t *testing.T) {
	piperd := os.Getenv("ANONDOOR_SSHPIPERD")
	if piperd == "" {
		t.Skip("set ANONDOOR_SSHPIPERD to the v1.6.1 binary")
	}
	for _, tool := range []string{"ssh", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	hostKey, clientKey, upstreamKey := filepath.Join(dir, "host"), filepath.Join(dir, "client"), filepath.Join(dir, "upstream")
	for _, key := range []string{hostKey, clientKey, upstreamKey} {
		if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-f", key, "-N", "", "-q").CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v: %s", err, out)
		}
	}
	pubData, err := os.ReadFile(clientKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
	if err != nil {
		t.Fatal(err)
	}
	upstream := approvalSSHServer(t, hostKey, upstreamKey)
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(dir, "plugin")
	// Paths are passed as environment variables rather than interpolated into
	// a shell script; the workspace and macOS temp paths can contain spaces.
	if err := os.WriteFile(plugin, []byte("#!/bin/sh\nexec \"$ANONDOOR_APPROVAL_TEST_BINARY\" -test.run '^TestIntegration_ApprovalPluginProcess$'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	logFile, err := os.Create(filepath.Join(dir, "sshpiperd.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	piperArgs := []string{"-l", "127.0.0.1", "-i", hostKey, "-p", fmt.Sprint(port), "--drop-hostkeys-message", "--login-grace-time", "90s"}
	if adapter := os.Getenv("ANONDOOR_APPROVAL_ADAPTER"); adapter != "" {
		piperArgs = append(piperArgs, adapter, "sentinel", "ssh-upstream-plugin", "--plugin", plugin)
		if os.Getenv("ANONDOOR_APPROVAL_GUARDED") == "1" {
			socket, ban := approvalGuardControl(t, upstream)
			piperArgs = append(piperArgs, "--upstream-control-socket", socket, "--", adapter, "sentinel", "ssh-ban-plugin", "--upstream-control-socket", socket, "--control-socket", ban)
		}
	} else {
		piperArgs = append(piperArgs, plugin)
	}
	cmd := exec.Command(piperd, piperArgs...)
	cmd.Env = append(os.Environ(), "ANONDOOR_APPROVAL_PLUGIN=1",
		"ANONDOOR_APPROVAL_TEST_BINARY="+testBinary, "ANONDOOR_APPROVAL_UPSTREAM="+upstream,
		"ANONDOOR_APPROVAL_UPSTREAM_KEY="+upstreamKey, "ANONDOOR_APPROVAL_FINGERPRINT="+ssh.FingerprintSHA256(pub))
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			data, _ := os.ReadFile(logFile.Name())
			t.Logf("sshpiperd: %s", data)
		}
	})
	waitPort(t, port)

	for _, tc := range []struct {
		name, methods, identity string
		wantSession             bool
	}{
		{"signed-key-then-approval", "publickey,keyboard-interactive", clientKey, true},
		{"public-key-without-private-key", "publickey,keyboard-interactive", clientKey + ".pub", false},
		{"approval-without-publickey", "keyboard-interactive", clientKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			promptFile := filepath.Join(t.TempDir(), "prompt")
			askpass := filepath.Join(t.TempDir(), "askpass")
			if err := os.WriteFile(askpass, []byte("#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$ANONDOOR_APPROVAL_PROMPT_FILE\"\nprintf '\\n'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			client := exec.CommandContext(ctx, "ssh", "-vv", "-F", "/dev/null", "-T", "-p", fmt.Sprint(port), "-i", tc.identity,
				"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=no",
				"-o", "UserKnownHostsFile=/dev/null", "-o", "GlobalKnownHostsFile=/dev/null",
				"-o", "PreferredAuthentications="+tc.methods, "-o", "PasswordAuthentication=no",
				"-o", "KbdInteractiveAuthentication=yes", "-o", "NumberOfPasswordPrompts=1",
				"approval-test@127.0.0.1", "echo approval-ok")
			client.Env = append(os.Environ(), "SSH_ASKPASS="+askpass, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=approval-test:0",
				"ANONDOOR_APPROVAL_PROMPT_FILE="+promptFile)
			var stdout, stderr bytes.Buffer
			client.Stdout, client.Stderr = &stdout, &stderr
			err := client.Run()
			if ctx.Err() != nil {
				t.Fatalf("OpenSSH timed out: %s", stderr.String())
			}
			prompt, _ := os.ReadFile(promptFile)
			if !tc.wantSession {
				if err == nil || stdout.Len() != 0 || len(prompt) != 0 || strings.Contains(stderr.String(), approvalInstruction) {
					t.Fatalf("opened approval/session without key proof: %v\nstdout: %s\nprompt: %s\nstderr: %s", err, &stdout, prompt, &stderr)
				}
				return
			}
			if err != nil || strings.TrimSpace(stdout.String()) != "approval-ok" {
				t.Fatalf("session: %v\nstdout: %s\nstderr: %s", err, &stdout, &stderr)
			}
			// OpenSSH may prefix the askpass question with (user@host).
			if !strings.Contains(stderr.String(), approvalInstruction) || !strings.HasSuffix(string(prompt), approvalPrompt+"\n") || bytes.Count(prompt, []byte("\n")) != 1 {
				t.Fatalf("missing instruction or one prompt: %q\n%s", prompt, &stderr)
			}
			if !strings.Contains(stderr.String(), "Authenticated using \"publickey\" with partial success") {
				t.Fatalf("publickey did not partially succeed: %s", &stderr)
			}
			t.Logf("OpenSSH: signed publickey -> partial success -> instruction %q + one prompt %q -> %s", approvalInstruction, strings.TrimSpace(string(prompt)), strings.TrimSpace(stdout.String()))
		})
	}
}

// approvalSSHServer is a loopback SSH fixture, not a mocked plugin: sshpiperd
// must authenticate with its upstream key and open a real session channel.
func approvalSSHServer(t *testing.T, hostKey, authorizedKey string) string {
	t.Helper()
	hostData, err := os.ReadFile(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.ParsePrivateKey(hostData)
	if err != nil {
		t.Fatal(err)
	}
	keyData, err := os.ReadFile(authorizedKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(keyData)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(conn ssh.ConnMetadata, offered ssh.PublicKey) (*ssh.Permissions, error) {
		if conn.User() != "approval-test" || !bytes.Equal(offered.Marshal(), key.Marshal()) {
			return nil, fmt.Errorf("unexpected upstream credential")
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					if channel.ChannelType() != "session" {
						_ = channel.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					ch, reqs, err := channel.Accept()
					if err != nil {
						return
					}
					for req := range reqs {
						var payload struct{ Command string }
						if req.Type != "exec" || ssh.Unmarshal(req.Payload, &payload) != nil || payload.Command != "echo approval-ok" {
							_ = req.Reply(false, nil)
							continue
						}
						_ = req.Reply(true, nil)
						_, _ = ch.Write([]byte("approval-ok\n"))
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
