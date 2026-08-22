package k8s

import (
	"os/exec"
	"strings"
	"testing"
)

// TestHelmChartSshpiperLabelMatchesNetworkPolicyContract renders the Helm
// chart's sshpiper Deployment and Service and asserts their pod-selecting
// label is exactly sshpiperNameLabel=sshpiper — the contract
// networkPolicyObject's ingress rule (networkpolicy_test.go) hardcodes and
// the comment on sshpiperNameLabel documents ("A gateway deployed by other
// means MUST carry this label or the ingress rule below will not admit
// it."). The chart previously used a chart-name-prefixed label instead
// (containarium-k8s-sshpiper), which silently made every Helm-deployed
// gateway invisible to the default-deny NetworkPolicy's ingress allowance —
// on any NetworkPolicy-enforcing CNI, sshpiper could never reach a box (#1492).
//
// Skips if helm isn't on PATH rather than failing: this guards a real
// regression when it can run, without making helm a hard dependency of
// `go test ./...` for contributors who don't have it installed.
func TestHelmChartSshpiperLabelMatchesNetworkPolicyContract(t *testing.T) {
	helmPath, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not found on PATH, skipping chart-rendering test")
	}

	out, err := exec.Command(helmPath, "template", "test-release", "../../../../charts/containarium-k8s",
		"--set", "daemon.jwtSecret=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
		// gateway.upstreamKeySecret must be set or the chart's own #1496 guard
		// (daemon-deployment.yaml) refuses to render at all — unrelated to what
		// this test checks, but required to get any output back.
		"--set", "gateway.upstreamKeySecret=sshpiper-upstream-key",
		"--show-only", "templates/sshpiper-deployment.yaml",
		"--show-only", "templates/sshpiper-service.yaml",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}

	want := sshpiperNameLabel + ": " + "sshpiper"
	wrongPrefix := sshpiperNameLabel + ": containarium-k8s-sshpiper"

	rendered := string(out)
	if strings.Contains(rendered, wrongPrefix) {
		t.Fatalf("chart still renders the chart-name-prefixed label (%q) instead of the contract label (%q) — this is exactly the #1492 regression:\n%s",
			wrongPrefix, want, rendered)
	}
	if got := strings.Count(rendered, want); got < 3 {
		t.Errorf("expected %q at least 3 times (Deployment selector.matchLabels, Deployment pod template labels, Service selector), got %d occurrences:\n%s", want, got, rendered)
	}
}

// TestHelmChartRefusesGatewayWithoutUpstreamKey covers #1496: the chart
// must refuse to render (not just let the daemon crash-loop later) when
// gateway routing is enabled (gateway.namespace non-empty, the default) but
// no upstream keypair is configured — that combination produces a Pipe
// sshpiper can never authenticate through (it falls back to password auth,
// which every box refuses). Also covers the two ways out: configuring the
// keypair, or disabling gateway routing.
func TestHelmChartRefusesGatewayWithoutUpstreamKey(t *testing.T) {
	helmPath, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not found on PATH, skipping chart-rendering test")
	}
	baseArgs := []string{"template", "test-release", "../../../../charts/containarium-k8s",
		"--set", "daemon.jwtSecret=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead"}

	t.Run("default values refuse to render", func(t *testing.T) {
		out, err := exec.Command(helmPath, baseArgs...).CombinedOutput()
		if err == nil {
			t.Fatalf("expected helm template to fail with default values (gateway enabled, no upstream key), it succeeded:\n%s", out)
		}
		if !strings.Contains(string(out), "1496") {
			t.Errorf("expected the failure to reference #1496, got:\n%s", out)
		}
	})

	t.Run("upstream key configured renders successfully", func(t *testing.T) {
		args := append(append([]string{}, baseArgs...), "--set", "gateway.upstreamKeySecret=sshpiper-upstream-key")
		if out, err := exec.Command(helmPath, args...).CombinedOutput(); err != nil {
			t.Fatalf("helm template failed with an upstream key configured: %v\n%s", err, out)
		}
	})

	t.Run("gateway disabled renders successfully without an upstream key", func(t *testing.T) {
		args := append(append([]string{}, baseArgs...), "--set", "gateway.namespace=")
		if out, err := exec.Command(helmPath, args...).CombinedOutput(); err != nil {
			t.Fatalf("helm template failed with gateway routing disabled: %v\n%s", err, out)
		}
	})
}
