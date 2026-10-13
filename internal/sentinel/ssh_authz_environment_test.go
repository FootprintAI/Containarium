package sentinel

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHPiperLoadsSentinelEnvironment(t *testing.T) {
	for _, path := range []string{"../../terraform/modules/containarium/scripts/sshpiper.service.tmpl", "../../terraform/gce/scripts/startup-sentinel.sh"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "[Service]\nEnvironmentFile=-/etc/containarium/env.secrets\nExecStart=/usr/local/bin/sshpiperd") {
			t.Errorf("%s does not load sentinel credentials into sshpiperd children", path)
		}
	}
}

// Execute the actual bootstrap block with isolated files and a fake systemctl:
// creating, rotating and removing credentials must restart the plugin process;
// replaying unchanged metadata must not terminate active SSH sessions.
func TestSentinelSecretBootstrapRestartsOnlyOnChanges(t *testing.T) {
	data, err := os.ReadFile("../../terraform/modules/containarium/scripts/startup-sentinel.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	phase := strings.Index(script, "# --- Phase 0.4 / 0.5 secret + CA bootstrap")
	if phase < 0 {
		t.Fatal("credential bootstrap section not found")
	}
	start := strings.Index(script[phase:], "mkdir -p /etc/containarium\n")
	if start >= 0 {
		start += phase
	}
	end := strings.Index(script, "# Peer-CA private key")
	if start < 0 || end <= start {
		t.Fatal("credential bootstrap block not found")
	}
	dir := t.TempDir()
	envDir := filepath.Join(dir, "containarium")
	calls := filepath.Join(dir, "calls")
	script = strings.ReplaceAll(script[start:end], "/etc/containarium", envDir)
	script = strings.ReplaceAll(script, "${sentinel_auth_secret}", "$TEST_AUTH_SECRET")
	script = strings.ReplaceAll(script, "${sentinel_admin_secret}", "$TEST_ADMIN_SECRET")
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$TEST_CALLS\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	run := func(secret string, wantRestarts int) {
		t.Helper()
		cmd := exec.Command("bash", "-eu", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TEST_CALLS="+calls, "TEST_AUTH_SECRET="+secret, "TEST_ADMIN_SECRET=")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bootstrap failed: %v %s", err, out)
		}
		callData, err := os.ReadFile(calls)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(string(callData), "restart sshpiper\n"); got != wantRestarts {
			t.Fatalf("restart count=%d want=%d", got, wantRestarts)
		}
		path := filepath.Join(envDir, "env.secrets")
		if secret == "" {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("removed credentials still present")
			}
			return
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "CONTAINARIUM_SENTINEL_AUTH_SECRET="+secret+"\n" {
			t.Fatal("credential file does not contain current fixture secret")
		}
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("credential file must be private")
		}
	}
	run(strings.Repeat("a", 32), 1)
	run(strings.Repeat("a", 32), 1)
	run(strings.Repeat("b", 32), 2)
	run("", 3)
	run("", 3)
}
