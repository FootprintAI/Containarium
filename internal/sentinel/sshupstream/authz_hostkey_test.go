package sshupstream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshauthz"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/ioconn"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/grpc"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
)

// authzRouterClient connects the real router to the production adapter without
// requiring an external sshpiperd process. Host verification still happens in
// an actual SSH handshake with an in-process backend, not a mocked callback.
type authzRouterClient struct {
	libplugin.SshPiperPluginClient
	router *sshauthz.Router
}

func (c authzRouterClient) ListCallbacks(context.Context, *libplugin.ListCallbackRequest, ...grpc.CallOption) (*libplugin.ListCallbackResponse, error) {
	return &libplugin.ListCallbackResponse{Callbacks: []string{"PublicKeyAuth"}}, nil
}

func (c authzRouterClient) PublicKeyAuth(_ context.Context, req *libplugin.PublicKeyAuthRequest, _ ...grpc.CallOption) (*libplugin.PublicKeyAuthResponse, error) {
	up, err := c.router.Route(req.Meta, req.PublicKey)
	return &libplugin.PublicKeyAuthResponse{Upstream: up}, err
}

func TestAuthzRouterAdapterVerifiesBackendHandshake(t *testing.T) {
	testPinnedBackendHandshake(t, "")
}

func TestYAMLRouterAdapterVerifiesBackendHandshake(t *testing.T) {
	path := os.Getenv("SSH_AUTHZ_YAML")
	if path == "" {
		t.Skip("set SSH_AUTHZ_YAML to test the real yaml plugin")
	}
	testPinnedBackendHandshake(t, path)
}

func testPinnedBackendHandshake(t *testing.T, yamlPath string) {
	newKey := func(t *testing.T) (ssh.Signer, []byte) {
		t.Helper()
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(private)
		if err != nil {
			t.Fatal(err)
		}
		block, err := ssh.MarshalPrivateKey(private, "")
		if err != nil {
			t.Fatal(err)
		}
		return signer, pem.EncodeToMemory(block)
	}
	for _, state := range []string{"correct", "wrong key", "wrong port", "empty", "missing", "malformed", "comments only", "revoked", "rotation", "old key removed"} {
		t.Run(state, func(t *testing.T) {
			host, _ := newKey(t)
			other, _ := newKey(t)
			client, private := newKey(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			endpoint := ln.Addr().String()
			done := make(chan struct{})
			go func() {
				defer close(done)
				raw, err := ln.Accept()
				if err != nil {
					return
				}
				defer func() { _ = raw.Close() }()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					if string(key.Marshal()) != string(client.PublicKey().Marshal()) {
						return nil, fmt.Errorf("unexpected client")
					}
					return nil, nil
				}}
				cfg.AddHostKey(host)
				conn, _, _, err := ssh.NewServerConn(raw, cfg)
				if err == nil {
					_ = conn.Close()
				}
			}()
			t.Cleanup(func() {
				_ = ln.Close()
				select {
				case <-done:
				case <-time.After(6 * time.Second):
					t.Error("backend handshake did not stop")
				}
			})
			dir := t.TempDir()
			write := func(name string, data []byte) string {
				t.Helper()
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			pins := knownhosts.Line([]string{endpoint}, host.PublicKey()) + "\n"
			switch state {
			case "wrong key", "old key removed":
				pins = knownhosts.Line([]string{endpoint}, other.PublicKey()) + "\n"
			case "wrong port":
				pins = knownhosts.Line([]string{"127.0.0.1:1"}, host.PublicKey()) + "\n"
			case "empty", "missing":
				pins = ""
			case "malformed":
				pins = "not a known-hosts entry\n"
			case "comments only":
				pins = "# no trusted backend keys\n"
			case "revoked":
				pins = "@revoked " + pins
			case "rotation":
				pins += knownhosts.Line([]string{endpoint}, other.PublicKey()) + "\n"
			}
			pinPath := write("known_hosts", []byte(pins))
			if state == "missing" {
				if err := os.Remove(pinPath); err != nil {
					t.Fatal(err)
				}
			}
			config := write("config.yaml", []byte(fmt.Sprintf("version: \"1.0\"\npipes:\n- from:\n  - username: fixture\n    authorized_keys: [%q]\n  to:\n    host: %q\n    private_key: %q\n    known_hosts: %q\n    ignore_hostkey: true\n", write("authorized_keys", ssh.MarshalAuthorizedKey(client.PublicKey())), endpoint, write("upstream_key", private), pinPath)))
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var child libplugin.SshPiperPluginClient = authzRouterClient{router: sshauthz.NewRouter(config)}
			if yamlPath != "" {
				child = startPinnedYAMLRouter(t, ctx, yamlPath, config)
			}
			cfg, err := NewAdapter(ctx, child, func(ctx context.Context, _ Attempt) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", endpoint)
			})
			if err != nil {
				t.Fatal(err)
			}
			meta := &libplugin.ConnMeta{UserName: "fixture", UniqId: "host-pin", FromAddr: "127.0.0.2:12345"}
			connect := func() error {
				up, err := cfg.PublicKeyCallback(meta, client.PublicKey().Marshal())
				if err != nil {
					return err
				}
				raw, err := cfg.CreateConnCallback(up.Uri)
				if err != nil {
					return err
				}
				defer func() { _ = raw.Close() }()
				conn, _, _, err := ssh.NewClientConn(raw, endpoint, &ssh.ClientConfig{User: "fixture", Auth: []ssh.AuthMethod{ssh.PublicKeys(client)}, HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
					return cfg.VerifyHostKeyCallback(meta, hostname, remote.String(), key.Marshal())
				}})
				if err == nil {
					_ = conn.Close()
				}
				return err
			}
			err = connect()
			wantOK := state == "correct" || state == "rotation"
			if (err == nil) != wantOK {
				t.Fatalf("host pin policy: state=%s error=%v", state, err)
			}
		})
	}
}

// startPinnedYAMLRouter uses the SDK's stdio transport, as the production
// routing adapter does. The executable is an explicit local test prerequisite.
func startPinnedYAMLRouter(t *testing.T, ctx context.Context, path, config string) libplugin.SshPiperPluginClient {
	t.Helper()
	cmd := exec.CommandContext(ctx, path, "--config", config)
	transport, stderr, err := ioconn.DialCmd(cmd)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(io.Discard, stderr) }()
	var used atomic.Bool
	conn, err := grpc.NewClient("passthrough:///test-yaml", grpc.WithTransportCredentials(grpcinsecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		if used.Swap(true) {
			return nil, fmt.Errorf("yaml transport already used")
		}
		return transport, nil
	}))
	t.Cleanup(func() {
		if conn != nil {
			_ = conn.Close()
		}
		_ = transport.Close()
		_ = stderr.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if err != nil {
		t.Fatal(err)
	}
	return libplugin.NewSshPiperPluginClient(conn)
}
