package recipes

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// #3545: the ollama recipe starts the server with `podman run -d` and pulls a
// model right after. The server needs a moment before `ollama pull` can reach
// it, so a bounded readiness wait sits between the two. These tests run the
// recipe's steps after `podman run` against a fake podman.

// ollamaTailSteps returns the post_start steps after the `podman run` step.
func ollamaTailSteps(t *testing.T) []string {
	t.Helper()
	r, err := GetDefault().Get("ollama")
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range r.PostStart {
		if strings.Contains(line, "podman run") {
			return r.PostStart[i+1:]
		}
	}
	t.Fatal("ollama post_start has no podman run step")
	return nil
}

// runOllamaTail runs the steps after `podman run` the way the daemon does.
// The fake podman fails `exec ollama ollama list` the first notReady times,
// then succeeds; every call is logged. sleep is a no-op so a timeout is quick.
func runOllamaTail(t *testing.T, notReady int) (calls string, out string, ok bool) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls")
	count := filepath.Join(dir, "count")
	podman := `#!/bin/sh
echo "$*" >> ` + log + `
case "$*" in
  "exec ollama ollama list")
    n=$(cat ` + count + ` 2>/dev/null || echo 0)
    echo $((n + 1)) > ` + count + `
    [ "$n" -ge ` + strconv.Itoa(notReady) + ` ] ;;
  *) exit 0 ;;
esac
`
	for name, body := range map[string]string{"podman": podman, "sleep": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil { //nolint:gosec // test stand-in
			t.Fatal(err)
		}
	}
	script := "set -euo pipefail\n" + strings.Join(ollamaTailSteps(t), "\n")
	cmd := exec.Command("bash", "-c", script) //nolint:gosec // embedded recipe text
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", ParamEnvName("model") + "=llama3"}
	b, err := cmd.CombinedOutput()
	c, _ := os.ReadFile(log)
	return string(c), string(b), err == nil
}

func TestOllamaPull_WaitsForServer(t *testing.T) {
	for _, notReady := range []int{0, 3} {
		calls, out, ok := runOllamaTail(t, notReady)
		if !ok {
			t.Fatalf("notReady=%d: step failed\n%s", notReady, out)
		}
		if !strings.Contains(calls, "exec ollama ollama pull llama3") {
			t.Errorf("notReady=%d: model was not pulled:\n%s", notReady, calls)
		}
		if got := strings.Count(calls, "ollama list"); got != notReady+1 {
			t.Errorf("notReady=%d: %d readiness probes, want %d", notReady, got, notReady+1)
		}
		if strings.Index(calls, "ollama list") > strings.Index(calls, "ollama pull") {
			t.Errorf("notReady=%d: pull ran before the server was ready:\n%s", notReady, calls)
		}
	}
}

func TestOllamaPull_ServerNeverReadyFailsWithoutPulling(t *testing.T) {
	calls, out, ok := runOllamaTail(t, 100000)
	if ok {
		t.Fatalf("a server that never becomes ready must fail the step\n%s", out)
	}
	if strings.Contains(calls, "ollama pull") {
		t.Errorf("pull must not run against a server that is not ready:\n%s", calls)
	}
	if got := strings.Count(calls, "ollama list"); got != 60 {
		t.Errorf("readiness probed %d times, want exactly 60 (the documented bound)", got)
	}
	if !strings.Contains(out, "ollama") || !strings.Contains(out, "not ready") {
		t.Errorf("the failure should say the ollama server was not ready:\n%s", out)
	}
}

// TestOllamaReadinessProbeIsTimeBounded: one hung `podman exec` must not hold
// the step, so the probe runs under timeout.
func TestOllamaReadinessProbeIsTimeBounded(t *testing.T) {
	for _, line := range ollamaTailSteps(t) {
		if strings.Contains(line, "ollama list") && !strings.Contains(line, "timeout 5 podman exec ollama ollama list") {
			t.Errorf("readiness probe is not wrapped in timeout 5: %s", line)
		}
	}
}
