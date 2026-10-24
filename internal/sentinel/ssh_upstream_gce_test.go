package sentinel

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSSHUpstreamGCEBootStagesPolicy preserves the active hash across reboots.
func TestSSHUpstreamGCEBootStagesPolicy(t *testing.T) {
	data, err := os.ReadFile("../../terraform/gce/scripts/startup-sentinel.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "# Install the shared controller policy")
	if !ok {
		t.Fatal("missing GCE controller installation")
	}
	body, _, ok := strings.Cut(rest, "# Install and start sentinel service")
	if !ok {
		t.Fatal("missing GCE controller installation boundary")
	}
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policy")
	body = strings.ReplaceAll(body, "/etc/containarium/ssh-upstream", policyDir)
	body = strings.ReplaceAll(body, "/etc/systemd/system/containarium-sentinel.service.d", filepath.Join(dir, "unit"))
	run := func(source string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", "set -euo pipefail\nlogger() { :; }\n# Install the shared controller policy"+source)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("GCE boot: %v\n%s", err, out)
		}
	}
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(policyDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	run(body)
	active := read("policy.json")
	changed := strings.ReplaceAll(body, `"failureBudget":2`, `"failureBudget":1`)
	if changed == body {
		t.Fatal("fixture did not change the actual GCE policy")
	}
	run(changed)
	if read("policy.json") != active {
		t.Fatal("GCE reboot replaced the active policy hash")
	}
	if !strings.Contains(read("policy.pending.json"), `"failureBudget":1`) {
		t.Fatal("GCE did not stage the changed policy")
	}
	run(body)
	if _, err := os.Stat(filepath.Join(policyDir, "policy.pending.json")); !os.IsNotExist(err) {
		t.Fatal("GCE rollback left a stale pending policy")
	}
}
