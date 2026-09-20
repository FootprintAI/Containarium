package server

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// platformMCPFixturePath is the fixture BOTH this suite and agent-runtime's
// seed.test.ts pin: the daemon writes exactly this shape and the runtime
// parses exactly this shape, so a change to either side that isn't mirrored
// fails a test on the other. See docs/architecture/agent-tracker-broker.md
// ("daemon <-> in-box runtime" contract row).
const platformMCPFixturePath = "../../agent-runtime/fixtures/platform_mcp.json"

func TestPlatformMCPSeed_MatchesSharedFixture(t *testing.T) {
	want, err := os.ReadFile(platformMCPFixturePath)
	if err != nil {
		t.Fatalf("read shared fixture: %v", err)
	}
	got, err := json.Marshal(platformMCPSeed{
		Command:   "mcp-server",
		Args:      []string{},
		ServerURL: "http://10.9.8.1:8080",
		TokenFile: "/etc/containarium/agent/runs/run-1/token",
		Tools:     "tracker_*",
	})
	if err != nil {
		t.Fatal(err)
	}
	var a, b map[string]any
	if err := json.Unmarshal(want, &a); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	if err := json.Unmarshal(got, &b); err != nil {
		t.Fatal(err)
	}
	wa, _ := json.Marshal(a)
	wb, _ := json.Marshal(b)
	if string(wa) != string(wb) {
		t.Errorf("daemon shape drifted from the shared fixture\n daemon: %s\nfixture: %s", wb, wa)
	}
}

func TestPlatformMCPSeedScript_OnlyWhenRunIsBoundToAConnection(t *testing.T) {
	if _, ok := platformMCPSeedScript("/seed", 8080, ""); ok {
		t.Error("script produced for a run with no tracker connection — an unbound run must get no tracker tools")
	}
	if _, ok := platformMCPSeedScript("/seed", 0, "default"); ok {
		t.Error("script produced with no known daemon port — the URL would be unusable")
	}
	if _, ok := platformMCPSeedScript("/seed", 8080, "default"); !ok {
		t.Error("no script for a bound run with a known port")
	}
}

// TestPlatformMCPSeedScript_WritesResolvedSeed runs the generated script for
// real (bash, a stub `ip`) rather than asserting on its text — the host is
// resolved in-box from the default route, and that substitution is the part a
// string assertion cannot check.
func TestPlatformMCPSeedScript_WritesResolvedSeed(t *testing.T) {
	seedDir := t.TempDir()
	binDir := t.TempDir()
	stub := "#!/bin/sh\necho 'default via 10.9.8.1 dev eth0'\n"
	if err := os.WriteFile(filepath.Join(binDir, "ip"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}

	script, ok := platformMCPSeedScript(seedDir, 8080, "default")
	if !ok {
		t.Fatal("no script")
	}
	cmd := exec.Command("bash", "-c", script) //nolint:gosec // test-only, script built by the code under test
	cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}

	raw, err := os.ReadFile(filepath.Join(seedDir, "platform_mcp.json"))
	if err != nil {
		t.Fatalf("platform_mcp.json not written: %v", err)
	}
	var got platformMCPSeed
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, raw)
	}
	if got.ServerURL != "http://10.9.8.1:8080" {
		t.Errorf("server_url = %q, want the default-route host", got.ServerURL)
	}
	if got.TokenFile != seedDir+"/token" {
		t.Errorf("token_file = %q, want %q", got.TokenFile, seedDir+"/token")
	}
	if got.Tools != "tracker_*" {
		t.Errorf("tools = %q, want tracker_* — the in-box agent must see the tracker tools only", got.Tools)
	}
	if got.Command != "mcp-server" {
		t.Errorf("command = %q, want mcp-server", got.Command)
	}
}

// A box whose default route can't be resolved must not get a seed with an
// empty host (http://:8080) — that would mount a broken server silently.
func TestPlatformMCPSeedScript_NoHostWritesNothing(t *testing.T) {
	seedDir := t.TempDir()
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "ip"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script, _ := platformMCPSeedScript(seedDir, 8080, "default")
	cmd := exec.Command("bash", "-c", script) //nolint:gosec // test-only
	cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script must not fail the whole seed when the host is unresolvable: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(seedDir, "platform_mcp.json")); !os.IsNotExist(err) {
		t.Errorf("platform_mcp.json written despite an unresolvable host (stat err = %v)", err)
	}
}
