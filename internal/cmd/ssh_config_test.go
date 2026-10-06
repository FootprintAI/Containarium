package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/sshconfig"
	"github.com/footprintai/containarium/pkg/core/incus"
)

func resetSSHConfigGlobals(t *testing.T) {
	t.Helper()
	server, http, token := serverAddr, httpMode, authToken
	sentinel, port, identity, user := sshConfigSentinel, sshConfigPort, sshConfigIdentity, sshConfigUser
	jump := sshConfigJumpHost
	stopped, out, force := sshConfigIncludeStopped, sshConfigOutPath, sshConfigForce
	t.Cleanup(func() {
		serverAddr, httpMode, authToken = server, http, token
		sshConfigSentinel, sshConfigPort, sshConfigIdentity, sshConfigUser = sentinel, port, identity, user
		sshConfigJumpHost = jump
		sshConfigIncludeStopped, sshConfigOutPath, sshConfigForce = stopped, out, force
	})
	serverAddr, httpMode, authToken = "", false, ""
	sshConfigSentinel, sshConfigPort, sshConfigIdentity, sshConfigUser = "", 22, "", ""
	sshConfigJumpHost = ""
	sshConfigIncludeStopped, sshConfigOutPath, sshConfigForce = false, "", false
}

func TestSSHConfigOptions_RemoteSingleVM(t *testing.T) {
	for _, server := range []string{
		"http://vm.example.com:8080",
		"https://vm.example.com/api",
		"vm.example.com:50051",
		"vm.example.com",
		"http://[2001:db8::1]:8080",
		"[2001:db8::1]:50051",
	} {
		t.Run(server, func(t *testing.T) {
			resetSSHConfigGlobals(t)
			serverAddr = server
			sshConfigIdentity = "~/.ssh/containarium_ed25519"
			cs := []incus.ContainerInfo{{Name: "alice-container", Username: "alice", State: "Running", IPAddress: "10.0.3.100"}}
			g := sshconfig.Generate(cs, sshConfigOptions())
			host := "vm.example.com"
			if strings.Contains(server, "2001:db8") {
				host = "2001:db8::1"
			}
			want := "Host alice-container\n" +
				"    HostName 10.0.3.100\n" +
				"    Port 22\n" +
				"    User alice\n" +
				"    ProxyJump alice-container-jump\n" +
				"    IdentityFile ~/.ssh/containarium_ed25519\n" +
				"    IdentitiesOnly yes\n\n" +
				"Host alice-container-jump\n" +
				"    HostName " + host + "\n" +
				"    Port 22\n" +
				"    User alice\n" +
				"    IdentityFile ~/.ssh/containarium_ed25519\n" +
				"    IdentitiesOnly yes\n\n"
			if !strings.Contains(g.Content, want) || g.Count != 1 {
				t.Fatalf("missing single-VM ProxyJump config (Count=%d):\n%s", g.Count, g.Content)
			}
		})
	}
}

func TestSSHConfigSync_RemoteSingleVM(t *testing.T) {
	resetSSHConfigGlobals(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/containers" {
			t.Errorf("path = %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"containers":[{"name":"alice-container","username":"alice","state":"CONTAINER_STATE_RUNNING","sshHost":"","network":{"ipAddress":"10.0.3.100"}}]}`))
	}))
	defer srv.Close()
	serverAddr, httpMode = srv.URL, true
	sshConfigJumpHost = "vm.example.com:2222"
	sshConfigOutPath = filepath.Join(t.TempDir(), "ssh_config")
	if err := runSSHConfigSync(sshConfigSyncCmd, nil); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(sshConfigOutPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Host alice-container\n", "ProxyJump alice-container-jump\n", "Host alice-container-jump\n", "HostName vm.example.com\n", "Port 2222\n"} {
		if !strings.Contains(string(content), want) {
			t.Errorf("synced config missing %q:\n%s", want, content)
		}
	}
	t.Run("OpenSSH resolves both hops", func(t *testing.T) {
		if _, err := exec.LookPath("ssh"); err != nil {
			t.Skip("OpenSSH is not installed")
		}
		for _, tc := range []struct {
			name, host, port, proxy string
		}{
			{"alice-container", "10.0.3.100", "22", "alice-container-jump"},
			{"alice-container-jump", "vm.example.com", "2222", "none"},
		} {
			output, err := exec.Command("ssh", "-G", "-F", sshConfigOutPath, tc.name).CombinedOutput()
			if err != nil {
				t.Fatalf("OpenSSH rejected generated config: %v\n%s", err, output)
			}
			wantLines := []string{"hostname " + tc.host + "\n", "port " + tc.port + "\n", "user alice\n"}
			if tc.proxy != "none" {
				wantLines = append(wantLines, "proxyjump "+tc.proxy+"\n")
			} else if strings.Contains(string(output), "\nproxyjump ") && !strings.Contains(string(output), "\nproxyjump none\n") {
				// OpenSSH may omit proxyjump entirely when none is set.
				t.Errorf("jump host must not use another proxy:\n%s", output)
			}
			for _, want := range wantLines {
				if !strings.Contains(string(output), want) {
					t.Errorf("%s: OpenSSH output missing %q:\n%s", tc.name, want, output)
				}
			}
		}
	})
}

func TestSSHConfigSync_MissingJumpUserPreservesConfig(t *testing.T) {
	resetSSHConfigGlobals(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"containers":[{"name":"legacy-container","state":"CONTAINER_STATE_RUNNING","network":{"ipAddress":"10.0.3.100"}}]}`))
	}))
	defer srv.Close()
	serverAddr, httpMode = srv.URL, true
	sshConfigJumpHost = "vm.example.com"
	sshConfigOutPath = filepath.Join(t.TempDir(), "ssh_config")
	const previous = "Host existing\n    HostName existing.example.com\n"
	if err := os.WriteFile(sshConfigOutPath, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runSSHConfigSync(sshConfigSyncCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "username") || !strings.Contains(err.Error(), "--ssh-host") || !strings.Contains(err.Error(), "--sentinel") {
		t.Fatalf("want actionable error for unknown jump account, got %v", err)
	}
	content, err := os.ReadFile(sshConfigOutPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != previous {
		t.Fatalf("sync replaced a working config after failing to resolve the jump account:\n%s", content)
	}
}

func TestSSHConfigOptions_PreservesExistingRoutes(t *testing.T) {
	for _, tc := range []struct {
		name, server, sentinel, sshHost, username, wantHost, wantUser string
	}{
		{"local Incus", "", "", "", "", "10.0.3.100", "ubuntu"},
		{"daemon ssh_host", "http://vm.example.com:8080", "", "ssh.example.com", "alice", "ssh.example.com", "alice"},
		{"sentinel", "http://vm.example.com:8080", "sentinel.example.com", "", "alice", "sentinel.example.com", "alice-container"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetSSHConfigGlobals(t)
			serverAddr, sshConfigSentinel = tc.server, tc.sentinel
			g, err := generateManagedSSHConfig([]incus.ContainerInfo{{Name: "alice-container", Username: tc.username, State: "Running", IPAddress: "10.0.3.100", SSHHost: tc.sshHost}})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(g.Content, "ProxyJump") || !strings.Contains(g.Content, "HostName "+tc.wantHost+"\n") || !strings.Contains(g.Content, "User "+tc.wantUser+"\n") {
				t.Fatalf("existing route changed:\n%s", g.Content)
			}
		})
	}
}

func TestSSHConfigShow_LoopbackRequiresJumpHost(t *testing.T) {
	for _, server := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		t.Run(server, func(t *testing.T) {
			resetSSHConfigGlobals(t)
			serverAddr = server
			_, err := generateManagedSSHConfig([]incus.ContainerInfo{{Name: "alice-container", Username: "alice", State: "Running", IPAddress: "10.0.3.100"}})
			if err == nil || !strings.Contains(err.Error(), "--jump-host") {
				t.Fatalf("want tunnel guidance, got %v", err)
			}
		})
	}
}

func TestSSHConfigOptions_UserOverrideKeepsJumpAccount(t *testing.T) {
	resetSSHConfigGlobals(t)
	serverAddr, sshConfigUser = "http://vm.example.com:8080", "root"
	g, err := generateManagedSSHConfig([]incus.ContainerInfo{{Name: "alice-container", Username: "alice", State: "Running", IPAddress: "10.0.3.100"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(g.Content, "User root\n    ProxyJump alice-container-jump") || !strings.Contains(g.Content, "Host alice-container-jump\n    HostName vm.example.com\n    Port 22\n    User alice\n") {
		t.Fatalf("--user must only override the in-box user:\n%s", g.Content)
	}
}
