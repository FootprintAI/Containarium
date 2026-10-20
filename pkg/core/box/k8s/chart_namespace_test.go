package k8s

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const nsChartDir = "../../../../charts/containarium-k8s"

// nsRender renders the chart with the walkthrough's flags (jwt secret, upstream
// key secret and public key) plus extra args, and returns the manifest.
func nsRender(t *testing.T, chart string, extra ...string) string {
	t.Helper()
	helmPath, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not found on PATH, skipping chart-rendering test")
	}
	pubKey := filepath.Join(t.TempDir(), "sshpiper_upstream.pub")
	if err := os.WriteFile(pubKey, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"template", "containarium", chart,
		"--set", "daemon.jwtSecret=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
		"--set", "gateway.upstreamKeySecret=sshpiper-upstream-key",
		"--set-file", "gateway.upstreamPublicKey=" + pubKey}, extra...)
	out, err := exec.Command(helmPath, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	return string(out)
}

// nsDoc returns the rendered gateway Namespace document, or "".
func nsDoc(manifest string) string {
	for _, doc := range strings.Split(manifest, "\n---\n") {
		if strings.Contains(doc, "kind: Namespace\n") {
			return strings.TrimSpace(doc)
		}
	}
	return ""
}

// TestHelmChartGatewayNamespaceOwnership pins the #2776 contract. The default
// render keeps the gateway Namespace in the release, exactly as every earlier
// release did: dropping it from the default would make Helm DELETE the
// namespace (and the sshpiper Secrets and Deployment in it) on upgrade of an
// existing install. The walkthroughs create the namespace by hand, which Helm
// will not adopt, so they pass gateway.createNamespace=false.
func TestHelmChartGatewayNamespaceOwnership(t *testing.T) {
	const ns = "kind: Namespace\nmetadata:\n  name: agent-gateway"
	for _, preset := range []string{"values-gke.yaml", "values-eks.yaml"} {
		f := filepath.Join(nsChartDir, preset)
		t.Run(preset+" default renders the Namespace (upgrade back-compat)", func(t *testing.T) {
			if out := nsRender(t, nsChartDir, "-f", f); !strings.Contains(out, ns) {
				t.Errorf("default render lost the gateway Namespace; upgrading an existing release would delete it:\n%s", out)
			}
		})
		t.Run(preset+" walkthrough flags render no Namespace", func(t *testing.T) {
			if out := nsRender(t, nsChartDir, "-f", f, "--set", "gateway.createNamespace=false"); strings.Contains(out, "kind: Namespace") {
				t.Errorf("createNamespace=false still renders a Namespace; a hand-made one would fail helm install (#2776):\n%s", out)
			}
		})
	}
}

// TestHelmChartDefaultNamespaceMatchesPreviousRelease is the upgrade-safety
// guard: the Namespace object the candidate chart renders by default must be
// byte-identical to what the chart at origin/main renders, so an in-place
// upgrade never changes or removes it. Skips when origin/main is not
// available (shallow checkout) or helm is missing.
func TestHelmChartDefaultNamespaceMatchesPreviousRelease(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not found on PATH")
	}
	base := "origin/main"
	if err := exec.Command("git", "rev-parse", "--verify", "-q", base).Run(); err != nil {
		t.Skip("origin/main not available, skipping previous-release comparison")
	}
	root := strings.TrimSpace(func() string {
		b, _ := exec.Command("git", "rev-parse", "--show-toplevel").Output()
		return string(b)
	}())
	dir := t.TempDir()
	arch := exec.Command("sh", "-c", "git -C "+root+" archive "+base+" charts/containarium-k8s | tar -x -C "+dir)
	if out, err := arch.CombinedOutput(); err != nil {
		t.Skipf("cannot extract %s chart: %v\n%s", base, err, out)
	}
	old := nsDoc(nsRender(t, filepath.Join(dir, "charts", "containarium-k8s")))
	cur := nsDoc(nsRender(t, nsChartDir))
	if old == "" {
		t.Skip("baseline chart renders no Namespace; nothing to compare")
	}
	if cur != old {
		t.Errorf("default gateway Namespace differs from %s:\n--- previous ---\n%s\n--- candidate ---\n%s", base, old, cur)
	}
}
