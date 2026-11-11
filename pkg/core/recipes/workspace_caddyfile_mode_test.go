package recipes

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The workspace Caddyfile holds the cookie token and the basic-auth hash. Its
// post_start step must create it under umask 077 so no in-box user can read it,
// even briefly (#3656, F7). These tests take the real step from the embedded
// catalog, so they fail if the step is changed back to a bare heredoc.

const caddyfileWriteLine = "cat > /opt/wsauth/Caddyfile <<EOF"
const caddyfileChmodLine = "chmod 600 /opt/wsauth/Caddyfile"

func findCaddyfileStep(t *testing.T) string {
	t.Helper()
	data, err := embeddedFS.ReadFile("recipes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Recipes []struct {
			ID        string   `yaml:"id"`
			PostStart []string `yaml:"post_start"`
		} `yaml:"recipes"`
	}
	if err := yaml.Unmarshal(data, &inventory); err != nil {
		t.Fatalf("parse embedded catalog: %v", err)
	}
	for _, r := range inventory.Recipes {
		for _, step := range r.PostStart {
			if strings.Contains(step, caddyfileWriteLine) {
				return step
			}
		}
	}
	t.Fatalf("no post_start step writes /opt/wsauth/Caddyfile")
	return ""
}

// caddyfileLines returns the step's lines from the umask 077 that precedes the
// write through the chmod that follows the heredoc terminator.
func caddyfileLines(t *testing.T, step string) (lines []string, umaskIdx, writeIdx, chmodIdx int) {
	t.Helper()
	lines = strings.Split(step, "\n")
	umaskIdx, writeIdx, chmodIdx = -1, -1, -1
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		switch {
		case trimmed == caddyfileWriteLine:
			writeIdx = i
		case trimmed == "umask 077" && writeIdx == -1:
			umaskIdx = i
		case trimmed == caddyfileChmodLine:
			chmodIdx = i
		}
	}
	return lines, umaskIdx, writeIdx, chmodIdx
}

// The step must set umask 077 before the write and chmod 600 after the
// heredoc terminator.
func TestWorkspaceCaddyfileIsCreatedPrivate(t *testing.T) {
	step := findCaddyfileStep(t)
	_, umaskIdx, writeIdx, chmodIdx := caddyfileLines(t, step)
	if umaskIdx < 0 {
		t.Fatalf("step does not set umask 077 before writing /opt/wsauth/Caddyfile")
	}
	if writeIdx < 0 || umaskIdx > writeIdx {
		t.Fatalf("umask 077 (line %d) must precede the Caddyfile write (line %d)", umaskIdx, writeIdx)
	}
	if chmodIdx < 0 {
		t.Fatalf("step does not chmod 600 /opt/wsauth/Caddyfile")
	}
	if chmodIdx < writeIdx {
		t.Fatalf("chmod 600 (line %d) must follow the Caddyfile write (line %d)", chmodIdx, writeIdx)
	}
}

// Run the real lines under a permissive umask, with the chmod removed. The
// umask 077 line by itself must give the file mode 0600.
func TestWorkspaceCaddyfileModeFromUmaskAlone(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	step := findCaddyfileStep(t)
	lines, umaskIdx, _, chmodIdx := caddyfileLines(t, step)
	if umaskIdx < 0 || chmodIdx < 0 {
		t.Fatalf("step is missing umask 077 or chmod 600 (umask=%d chmod=%d)", umaskIdx, chmodIdx)
	}

	dir := t.TempDir()
	// Run only the segment from umask 077 up to the chmod, and drop the chmod,
	// so the umask alone decides the mode. Point the path at a temp dir.
	var kept []string
	for _, l := range lines[umaskIdx:chmodIdx] {
		kept = append(kept, strings.ReplaceAll(l, "/opt/wsauth", dir))
	}
	script := "umask 022\n" + strings.Join(kept, "\n")

	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(),
		"WS_TOKEN=0123456789abcdef",
		"WS_HASH=$2a$14$examplehash",
		"CONTAINARIUM_PARAM_AUTH_USER=ws-user",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("running step lines: %v\n%s", err, out)
	}

	path := filepath.Join(dir, "Caddyfile")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Caddyfile not written: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("Caddyfile mode = %o, want 600 from umask 077 alone", got)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "basic_auth") || !strings.Contains(string(body), "0123456789abcdef") {
		t.Errorf("Caddyfile content not rendered: %q", string(body))
	}
}
