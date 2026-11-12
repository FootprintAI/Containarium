package recipes

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Secret-bearing files written inside a box must be created private from their
// first byte, not written at the default umask and chmod'ed afterwards (#3671).
// Each site below is checked in the shipped catalogs: a umask 077 in the lines
// just before the write, and a chmod on the file after it.

type inboxSecretSite struct {
	file      string // catalog file, relative to this package
	write     string // the line that creates the secret file (trimmed)
	path      string // the file it creates, for the chmod-after check
	wantChmod string // a chmod line that must follow the write (trimmed)
}

var inboxSecretSites = []inboxSecretSite{
	{"recipes.yaml", `python3 - <<'PYEOF'`, "/opt/wsauth/lc-creds", "chmod 600 /opt/wsauth/lc-creds"},
	{"recipes.yaml", `printf '%s' "$WS_TOKEN" > /opt/wsauth/token`, "/opt/wsauth/token", "chmod 600 /opt/wsauth/token"},
	{"recipes.yaml", `printf '%s' "$CONTAINARIUM_PARAM_MCP_TOKEN" > /opt/lc/ctn-token`, "/opt/lc/ctn-token", "chmod 600 /opt/lc/ctn-token"},
	{"../stacks/stacks.yaml", `} | sudo tee /etc/containarium/stack-params.env >/dev/null`, "/etc/containarium/stack-params.env", "sudo chmod 600 /etc/containarium/stack-params.env"},
	{"../stacks/stacks.yaml", `kind get kubeconfig --name kubeflow > "$HOME/.kube/config"`, `"$HOME/.kube/config"`, `chmod 600 "$HOME/.kube/config"`},
	{"../stacks/stacks.yaml", `mkdir -p ~/.vnc && echo "containarium" | vncpasswd -f > ~/.vnc/passwd && chmod 600 ~/.vnc/passwd`, "~/.vnc/passwd", "chmod 600 ~/.vnc/passwd"},
}

func readCatalog(t *testing.T, rel string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(".", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return strings.Split(string(b), "\n")
}

// A write site passes when a umask 077 sits within the six lines above it
// and a chmod on the same file follows it.
func TestInboxSecretFilesAreCreatedPrivate(t *testing.T) {
	cache := map[string][]string{}
	for _, site := range inboxSecretSites {
		lines, ok := cache[site.file]
		if !ok {
			lines = readCatalog(t, site.file)
			cache[site.file] = lines
		}
		writeIdx := -1
		for i, l := range lines {
			if strings.Contains(l, site.write) {
				writeIdx = i
				break
			}
		}
		if writeIdx < 0 {
			t.Errorf("%s: write line not found: %s", site.file, site.write)
			continue
		}
		umaskSeen := false
		for i := writeIdx - 6; i <= writeIdx; i++ {
			if i >= 0 && strings.TrimSpace(lines[i]) == "umask 077" {
				umaskSeen = true
			}
			if i >= 0 && strings.Contains(lines[i], "umask 077;") {
				umaskSeen = true
			}
		}
		if !umaskSeen {
			t.Errorf("%s: no umask 077 before the write of %s", site.file, site.path)
		}
		chmodAfter := false
		for _, l := range lines[writeIdx:] {
			if strings.Contains(l, site.wantChmod) {
				chmodAfter = true
				break
			}
		}
		if !chmodAfter {
			t.Errorf("%s: no %q after the write of %s", site.file, site.wantChmod, site.path)
		}
	}
}

// Behaviour: the real lc-creds Python step, run under a permissive umask with
// its chmod omitted, creates a 0600 file holding the credentials.
func TestLcCredsIsCreatedPrivateFromUmaskAlone(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	lines := readCatalog(t, "recipes.yaml")
	start, end := -1, -1
	for i, l := range lines {
		if start < 0 && strings.Contains(l, "python3 - <<'PYEOF'") {
			start = i
		}
		if start >= 0 && i > start && strings.TrimSpace(l) == "PYEOF" {
			end = i
			break
		}
	}
	if start < 1 || end < 0 {
		t.Fatal("lc-creds python step not found")
	}
	// The shipped step sets umask 077 on the line above the python heredoc. Run
	// that line itself, under a permissive umask, rather than adding our own.
	if strings.TrimSpace(lines[start-1]) != "umask 077" {
		t.Fatalf("line above the lc-creds python step is %q, want umask 077", lines[start-1])
	}
	dir := t.TempDir()
	// The YAML block scalar is indented 8 spaces; strip them to get the script.
	var body []string
	for _, l := range lines[start-1 : end+1] {
		body = append(body, strings.TrimPrefix(l, "        "))
	}
	script := "umask 022\n" + strings.Join(body, "\n")
	script = strings.ReplaceAll(script, "/opt/wsauth", dir)

	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(),
		"CONTAINARIUM_PARAM_AUTH_EMAIL=ops@example.test",
		"CONTAINARIUM_PARAM_AUTH_PASSWORD=pw-123",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("running lc-creds step: %v\n%s", err, out)
	}
	fi, err := os.Stat(filepath.Join(dir, "lc-creds"))
	if err != nil {
		t.Fatalf("lc-creds not written: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("lc-creds mode = %o, want 600", got)
	}
}
