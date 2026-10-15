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

// TestSSHUpstreamReconcileStagesPolicyChanges never invalidates a running checkpoint.
func TestSSHUpstreamReconcileStagesPolicyChanges(t *testing.T) {
	data, err := os.ReadFile("../../terraform/modules/containarium/scripts/startup-sentinel.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "reconcile_ssh_upstream_control() {")
	if !ok {
		t.Fatal("missing production reconciler")
	}
	body, _, ok := strings.Cut(rest, "\n}\n")
	if !ok {
		t.Fatal("unterminated production reconciler")
	}
	source := "reconcile_ssh_upstream_control() {" + body + "\n}\n"
	source = strings.ReplaceAll(source, "/etc/containarium/ssh-upstream", `"$RECONCILE_TEST_POLICY_DIR"`)
	source = strings.ReplaceAll(source, "/etc/systemd/system/containarium-sentinel.service.d", `"$RECONCILE_TEST_UNIT_DIR"`)
	dir := t.TempDir()
	policyDir, unitDir := filepath.Join(dir, "policy"), filepath.Join(dir, "unit")
	desired, calls, notices := filepath.Join(dir, "desired"), filepath.Join(dir, "calls"), filepath.Join(dir, "notices")
	script := `set -euo pipefail
curl() { cat "$RECONCILE_TEST_DESIRED"; }
systemctl() { printf '%s\n' "$*" >> "$RECONCILE_TEST_CALLS"; }
logger() { printf '%s\n' "$*" >> "$RECONCILE_TEST_NOTICES"; }
` + source + "reconcile_ssh_upstream_control\n"
	run := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", script)
		cmd.Env = append(os.Environ(), "RECONCILE_TEST_POLICY_DIR="+policyDir, "RECONCILE_TEST_UNIT_DIR="+unitDir, "RECONCILE_TEST_DESIRED="+desired, "RECONCILE_TEST_CALLS="+calls, "RECONCILE_TEST_NOTICES="+notices)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("reconcile: %v\n%s", err, out)
		}
	}
	write := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	first, second := `{"failureBudget":2}`, `{"failureBudget":1}`
	write(desired, first)
	run()
	if read(filepath.Join(policyDir, "policy.json")) != first || !strings.Contains(read(calls), "restart containarium-sentinel") {
		t.Fatal("first installation did not activate the controller")
	}
	write(calls, "")
	write(desired, second)
	run()
	if read(filepath.Join(policyDir, "policy.json")) != first {
		t.Fatal("metadata reconciliation replaced the active policy outside maintenance")
	}
	if strings.Contains(read(calls), "restart") {
		t.Fatal("policy-only reconciliation restarted a live sentinel")
	}
	if read(filepath.Join(policyDir, "policy.pending.json")) != second || !strings.Contains(read(notices), "maintenance") {
		t.Fatal("changed policy was not staged with an operator notice")
	}
	write(calls, "")
	run()
	if strings.Contains(read(calls), "restart") {
		t.Fatal("repeated pending policy restarted a live sentinel")
	}
	write(desired, first)
	run()
	if _, err := os.Stat(filepath.Join(policyDir, "policy.pending.json")); !os.IsNotExist(err) {
		t.Fatal("reverted metadata left a stale policy available for promotion")
	}
}
