package k8s

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestHelmChartDoesNotOwnGatewayNamespaceByDefault pins the #2776 contract:
// the walkthroughs (docs/EKS-GKE-DEPLOY.md, docs/KIND-QUICKSTART.md) create
// the gateway namespace by hand so the sshpiper Secrets can exist before
// install. Helm 3 refuses to adopt a namespace without its ownership
// metadata, so the chart must NOT render a Namespace unless the operator opts
// in with gateway.createNamespace=true. Rendered with the walkthrough's exact
// flags for both cloud presets.
func TestHelmChartDoesNotOwnGatewayNamespaceByDefault(t *testing.T) {
	helmPath, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not found on PATH, skipping chart-rendering test")
	}
	const chartDir = "../../../../charts/containarium-k8s"
	pubKey := filepath.Join(t.TempDir(), "sshpiper_upstream.pub")
	if err := os.WriteFile(pubKey, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	render := func(t *testing.T, preset string, extra ...string) string {
		t.Helper()
		args := append([]string{"template", "containarium", chartDir,
			"-f", filepath.Join(chartDir, preset),
			"--set", "daemon.jwtSecret=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
			"--set", "gateway.upstreamKeySecret=sshpiper-upstream-key",
			"--set-file", "gateway.upstreamPublicKey=" + pubKey}, extra...)
		out, err := exec.Command(helmPath, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("helm template failed: %v\n%s", err, out)
		}
		return string(out)
	}
	const ns = "kind: Namespace\nmetadata:\n  name: agent-gateway"
	for _, preset := range []string{"values-gke.yaml", "values-eks.yaml"} {
		t.Run(preset+" default renders no Namespace", func(t *testing.T) {
			if out := render(t, preset); strings.Contains(out, "kind: Namespace") {
				t.Errorf("chart renders a Namespace by default; a hand-made gateway namespace would make helm install fail (#2776):\n%s", out)
			}
		})
		t.Run(preset+" createNamespace=true renders it", func(t *testing.T) {
			if out := render(t, preset, "--set", "gateway.createNamespace=true"); !strings.Contains(out, ns) {
				t.Errorf("gateway.createNamespace=true did not render the gateway Namespace:\n%s", out)
			}
		})
	}
}
