package cluster

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// golden compares rendered bootstrap output against testdata — what
// executes inside a tenant's cluster VM changes only as a reviewable
// golden diff (`go test ./pkg/core/cluster/ -update` to regenerate).
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create): %v", path, err)
	}
	if got != string(want) {
		t.Fatalf("rendered output diverges from %s.\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func TestRenderServerScript(t *testing.T) {
	got := RenderServerScript(ServerBootstrap{TLSSANs: []string{"203.0.113.10", "10.166.11.5"}})
	golden(t, "server.sh.golden", got)

	// Behavioral pins independent of the golden bytes.
	for _, must := range []string{
		"--disable traefik",
		"--node-taint node-role.kubernetes.io/control-plane=:NoSchedule",
		"--write-kubeconfig-mode 0600",
		"--tls-san 10.166.11.5",
		"--tls-san 203.0.113.10",
	} {
		if !strings.Contains(got, must) {
			t.Fatalf("server script missing %q", must)
		}
	}
	if strings.Contains(got, "curl") || strings.Contains(got, "wget") {
		t.Fatal("bootstrap must not download anything in-guest")
	}
}

func TestRenderAgentScript(t *testing.T) {
	got := RenderAgentScript(AgentBootstrap{ServerURL: "https://10.166.11.5:6443"})
	golden(t, "agent.sh.golden", got)

	for _, must := range []string{
		"k3s agent --server https://10.166.11.5:6443",
		"--token-file " + AgentTokenPath,
		"chmod 0600 " + AgentTokenPath,
	} {
		if !strings.Contains(got, must) {
			t.Fatalf("agent script missing %q", must)
		}
	}
	if strings.Contains(got, "curl") || strings.Contains(got, "wget") {
		t.Fatal("bootstrap must not download anything in-guest")
	}
}

func TestRewriteKubeconfigServer(t *testing.T) {
	in := "apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n  name: default\n"
	got := RewriteKubeconfigServer(in, "203.0.113.10:30443")
	if !strings.Contains(got, "    server: https://203.0.113.10:30443\n") {
		t.Fatalf("server line not rewritten:\n%s", got)
	}
	if strings.Contains(got, "127.0.0.1") {
		t.Fatalf("old server survived rewrite:\n%s", got)
	}
	// Indentation is preserved so the YAML stays valid.
	if !strings.Contains(got, "\n    server:") {
		t.Fatalf("indentation lost:\n%s", got)
	}
}
