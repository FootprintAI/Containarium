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

func TestRenderCAUnitScript(t *testing.T) {
	got := RenderCAUnitScript(CADeploy{ProviderAddr: "10.0.0.1:36442"})
	golden(t, "ca-unit.sh.golden", got)
	for _, must := range []string{
		CAImage, // digest-pinned, never a floating tag
		"--cloud-provider=externalgrpc",
		"--cloud-config=" + CACloudConfigPath,
		"ctr run", // containerd task, not a Pod — outside the tenant-visible API
	} {
		if !strings.Contains(got, must) {
			t.Fatalf("CA unit script missing %q", must)
		}
	}
	if strings.Contains(got, "kubectl apply") || strings.Contains(got, "Pod") {
		t.Fatal("the autoscaler must not run as a Kubernetes object")
	}
}

func TestRenderCACloudConfig(t *testing.T) {
	got := RenderCACloudConfig(CADeploy{ProviderAddr: "10.0.0.1:36442"})
	golden(t, "ca-cloud-config.yaml.golden", got)
	for _, must := range []string{`address: "10.0.0.1:36442"`, CAClientKeyPath, CAClientCertPath, CACACertPath} {
		if !strings.Contains(got, must) {
			t.Fatalf("cloud-config missing %q", must)
		}
	}
}

// --- container-variant renders (#1429) --------------------------------
//
// The container path prepends the boot-time /dev/kmsg shim into the
// systemd unit; the VM path stays byte-identical to its pre-#1429
// golden (pinned above by TestRenderServerScript/TestRenderAgentScript).

func TestRenderServerScriptContainerVariant(t *testing.T) {
	got := RenderServerScript(ServerBootstrap{
		TLSSANs:   []string{"203.0.113.10", "10.166.11.5"},
		Isolation: IsolationContainer,
	})
	golden(t, "server-container.sh.golden", got)

	// The shim runs inside the unit, before k3s, so it re-applies on
	// every boot (/dev is a fresh tmpfs each start).
	if !strings.Contains(got, "ln -s /dev/console /dev/kmsg") {
		t.Fatal("container server unit is missing the /dev/kmsg shim")
	}
	if !strings.Contains(got, "ExecStartPre="+KmsgShimCommand+"\nExecStart=") {
		t.Fatal("kmsg shim is not rendered into the unit before k3s starts")
	}
	if strings.Contains(got, "security.privileged") {
		t.Fatal("bootstrap must not touch security.privileged")
	}

	// The zero-value (VM) render carries no shim.
	vm := RenderServerScript(ServerBootstrap{TLSSANs: []string{"203.0.113.10", "10.166.11.5"}})
	if strings.Contains(vm, "kmsg") {
		t.Fatal("VM server script grew a kmsg shim")
	}
}

func TestRenderAgentScriptContainerVariant(t *testing.T) {
	got := RenderAgentScript(AgentBootstrap{
		ServerURL: "https://10.166.11.5:6443",
		Isolation: IsolationContainer,
	})
	golden(t, "agent-container.sh.golden", got)

	if !strings.Contains(got, "ExecStartPre="+KmsgShimCommand+"\nExecStart=") {
		t.Fatal("kmsg shim is not rendered into the agent unit before k3s starts")
	}

	vm := RenderAgentScript(AgentBootstrap{ServerURL: "https://10.166.11.5:6443"})
	if strings.Contains(vm, "kmsg") {
		t.Fatal("VM agent script grew a kmsg shim")
	}
}
