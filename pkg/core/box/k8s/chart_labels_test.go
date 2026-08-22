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
