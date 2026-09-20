package recipes

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runInstallScript runs scripts/install-agent-runtime.sh hermetically: artifacts
// come from a file:// base, PREFIX/APP_DIR point at temp dirs, and npm is a stub
// (the real one would hit the network). Returns the script's combined output,
// its error, and the PREFIX dir.
func runInstallScript(t *testing.T, withMCPServer bool) (out string, prefix string, err error) {
	t.Helper()
	for _, tool := range []string{"bash", "curl", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	art := t.TempDir()
	write := func(name, body string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(art, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("agent-box-linux-amd64", "#!/bin/sh\necho agent-box\n", 0o755)
	if withMCPServer {
		write("mcp-server-linux-amd64", "#!/bin/sh\necho mcp-server\n", 0o755)
	}
	// A real tarball with the two things the script extracts.
	stage := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stage, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"dist/index.js", "package.json"} {
		if err := os.WriteFile(filepath.Join(stage, f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("tar", "-czf", filepath.Join(art, "agent-runtime-bundle.tar.gz"), "-C", stage, "dist", "package.json").CombinedOutput(); err != nil {
		t.Fatalf("tar: %v\n%s", err, out)
	}

	stubs := t.TempDir()
	if err := os.WriteFile(filepath.Join(stubs, "npm"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var appDir string
	prefix, appDir = t.TempDir(), t.TempDir()

	cmd := exec.Command("bash", "../../../scripts/install-agent-runtime.sh") //nolint:gosec // test-only, fixed path
	cmd.Env = append(os.Environ(),
		"ARTIFACT_BASE_URL=file://"+art, "PREFIX="+prefix, "APP_DIR="+appDir,
		"PATH="+stubs+":"+os.Getenv("PATH"))
	combined, runErr := cmd.CombinedOutput()
	err = runErr
	return string(combined), prefix, err
}

// The platform MCP is mounted in-box (#1922 D4) by spawning `mcp-server`; the
// daemon seeds the mount whether or not the binary exists, so the install must
// actually put it on PATH beside agent-box.
func TestInstallAgentRuntime_ShipsMCPServer(t *testing.T) {
	out, prefix, err := runInstallScript(t, true)
	if err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}
	for _, bin := range []string{"agent-box", "mcp-server", "agent-runtime"} {
		fi, statErr := os.Stat(filepath.Join(prefix, bin))
		if statErr != nil {
			t.Errorf("%s not installed: %v", bin, statErr)
		} else if fi.Mode()&0o111 == 0 {
			t.Errorf("%s is not executable (mode %v)", bin, fi.Mode())
		}
	}
}

// An older/partial release without the mcp-server asset must not take the whole
// agent box down — boxes not bound to a tracker never needed it — but the gap
// must be loud, not silent.
func TestInstallAgentRuntime_MissingMCPServerIsNonFatalButLoud(t *testing.T) {
	out, prefix, err := runInstallScript(t, false)
	if err != nil {
		t.Fatalf("a missing mcp-server asset must not fail the install: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(prefix, "agent-runtime")); statErr != nil {
		t.Errorf("agent-runtime launcher missing — the essential install was skipped: %v", statErr)
	}
	if !strings.Contains(out, "mcp-server") || !strings.Contains(strings.ToLower(out), "tracker") {
		t.Errorf("output does not warn that tracker tools won't work:\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(prefix, "mcp-server")); statErr == nil {
		t.Error("a partial mcp-server file was left behind after a failed download")
	}
}
