package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// noOwn is the uid/gid pair meaning "don't chown" (not running under sudo).
const noOwn = -1

func TestEnsureSSHInclude(t *testing.T) {
	include := "/home/alice/.containarium/ssh_config"

	t.Run("creates file and line when missing", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, ".ssh", "config")

		added, err := ensureSSHInclude(cfg, include, noOwn, noOwn)
		if err != nil {
			t.Fatalf("ensureSSHInclude: %v", err)
		}
		if !added {
			t.Fatal("expected added=true on first run")
		}
		got := readFile(t, cfg)
		if !strings.Contains(got, "Include "+include) {
			t.Fatalf("Include line missing:\n%s", got)
		}
	})

	t.Run("idempotent — second run is a no-op", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, ".ssh", "config")

		if _, err := ensureSSHInclude(cfg, include, noOwn, noOwn); err != nil {
			t.Fatalf("first run: %v", err)
		}
		before := readFile(t, cfg)

		added, err := ensureSSHInclude(cfg, include, noOwn, noOwn)
		if err != nil {
			t.Fatalf("second run: %v", err)
		}
		if added {
			t.Fatal("expected added=false on second run")
		}
		if after := readFile(t, cfg); after != before {
			t.Fatalf("second run mutated the file:\nbefore=%q\nafter=%q", before, after)
		}
		if n := strings.Count(readFile(t, cfg), "Include "+include); n != 1 {
			t.Fatalf("expected exactly 1 Include line, got %d", n)
		}
	})

	t.Run("preserves existing content and prepends", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config")
		existing := "Host bastion\n  HostName 10.0.0.1\n"
		if err := os.WriteFile(cfg, []byte(existing), 0o600); err != nil {
			t.Fatal(err)
		}

		added, err := ensureSSHInclude(cfg, include, noOwn, noOwn)
		if err != nil {
			t.Fatalf("ensureSSHInclude: %v", err)
		}
		if !added {
			t.Fatal("expected added=true")
		}
		got := readFile(t, cfg)
		if !strings.HasPrefix(got, "Include "+include+"\n") {
			t.Fatalf("Include should be prepended, got:\n%s", got)
		}
		if !strings.Contains(got, existing) {
			t.Fatalf("existing content lost:\n%s", got)
		}
	})
}

func TestMergeMCPServerJSON(t *testing.T) {
	const key = "mcpServers"

	t.Run("creates config with the box server", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".claude.json")

		changed, err := mergeMCPServerJSON(path, key, "containarium-box", "alice")
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		if !changed {
			t.Fatal("expected changed=true")
		}
		entry := mcpServerFromFile(t, path, key, "containarium-box")
		if entry.Command != "ssh" {
			t.Fatalf("command = %q, want ssh", entry.Command)
		}
		if strings.Join(entry.Args, " ") != "alice agent-box" {
			t.Fatalf("args = %v, want [alice agent-box]", entry.Args)
		}
	})

	t.Run("preserves unrelated keys", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".claude.json")
		seed := `{"theme":"dark","mcpServers":{"other":{"command":"foo","args":["bar"]}}}`
		if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := mergeMCPServerJSON(path, key, "containarium-box", "alice"); err != nil {
			t.Fatalf("merge: %v", err)
		}

		var root map[string]any
		if err := json.Unmarshal([]byte(readFile(t, path)), &root); err != nil {
			t.Fatalf("result not valid JSON: %v", err)
		}
		if root["theme"] != "dark" {
			t.Fatalf("top-level key lost: theme=%v", root["theme"])
		}
		servers := root[key].(map[string]any)
		if _, ok := servers["other"]; !ok {
			t.Fatal("pre-existing 'other' server was dropped")
		}
		if _, ok := servers["containarium-box"]; !ok {
			t.Fatal("containarium-box not added")
		}
	})

	t.Run("does not clobber an existing entry", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".claude.json")
		seed := `{"mcpServers":{"containarium-box":{"command":"custom","args":["x"]}}}`
		if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
			t.Fatal(err)
		}

		changed, err := mergeMCPServerJSON(path, key, "containarium-box", "alice")
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		if changed {
			t.Fatal("expected changed=false — must not clobber user's entry")
		}
		if entry := mcpServerFromFile(t, path, key, "containarium-box"); entry.Command != "custom" {
			t.Fatalf("user entry was overwritten: command=%q", entry.Command)
		}
	})

	t.Run("errors on invalid JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".claude.json")
		if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := mergeMCPServerJSON(path, key, "containarium-box", "alice"); err == nil {
			t.Fatal("expected an error on invalid JSON, got nil")
		}
	})
}

func TestCodexAppendMCP(t *testing.T) {
	t.Run("appends a table when missing", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".codex", "config.toml")

		changed, err := codexAppendMCP(path, "containarium-box", "alice")
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		if !changed {
			t.Fatal("expected changed=true")
		}
		got := readFile(t, path)
		for _, want := range []string{
			"[mcp_servers.containarium-box]",
			`command = "ssh"`,
			`args = ["alice", "agent-box"]`,
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("missing %q in:\n%s", want, got)
			}
		}
	})

	t.Run("preserves existing config and idempotent", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.toml")
		existing := "model = \"o3\"\n\n[mcp_servers.other]\ncommand = \"foo\"\n"
		if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
			t.Fatal(err)
		}

		changed, err := codexAppendMCP(path, "containarium-box", "alice")
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		if !changed {
			t.Fatal("expected changed=true")
		}
		got := readFile(t, path)
		if !strings.Contains(got, "model = \"o3\"") || !strings.Contains(got, "[mcp_servers.other]") {
			t.Fatalf("existing config lost:\n%s", got)
		}

		// second run must be a no-op
		changed2, err := codexAppendMCP(path, "containarium-box", "alice")
		if err != nil {
			t.Fatalf("second append: %v", err)
		}
		if changed2 {
			t.Fatal("expected changed=false on second run")
		}
		if n := strings.Count(readFile(t, path), "[mcp_servers.containarium-box]"); n != 1 {
			t.Fatalf("expected exactly 1 containarium-box table, got %d", n)
		}
	})
}

func TestAgentMCPTargets(t *testing.T) {
	home := t.TempDir()

	// Only the primary agent's config should be targeted when no others exist.
	got := agentMCPTargets(home, "claude")
	if len(got) != 1 || got[0].agent != "claude" {
		t.Fatalf("expected only claude, got %+v", got)
	}

	// Create a gemini config; now both should be targeted, primary first.
	geminiCfg := filepath.Join(home, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(geminiCfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(geminiCfg, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	got = agentMCPTargets(home, "codex")
	if len(got) != 2 {
		t.Fatalf("expected 2 targets, got %d (%+v)", len(got), got)
	}
	if got[0].agent != "codex" {
		t.Fatalf("primary agent must be first, got %q", got[0].agent)
	}
	if got[1].agent != "gemini" {
		t.Fatalf("expected gemini as the already-configured extra, got %q", got[1].agent)
	}
}

func TestBuildInstruction(t *testing.T) {
	got := buildInstruction("containarium-box", "a coffee shop landing page", "coffee.example.com", 8080)
	for _, want := range []string{
		`"containarium-box"`,
		"a coffee shop landing page",
		"port 8080",
		"https://coffee.example.com/",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("instruction missing %q:\n%s", want, got)
		}
	}

	// No domain → generic URL phrasing, no bare "https:///".
	noDomain := buildInstruction("containarium-box", "x", "", 3000)
	if strings.Contains(noDomain, "https:///") {
		t.Fatalf("empty domain produced a malformed URL:\n%s", noDomain)
	}
}

func TestResolveSSHKey(t *testing.T) {
	t.Run("user-provided key is used verbatim, no managed identity", func(t *testing.T) {
		pub, identity, generated, err := resolveSSHKey(t.TempDir(), "/home/alice/.ssh/mine.pub")
		if err != nil {
			t.Fatalf("resolveSSHKey: %v", err)
		}
		if pub != "/home/alice/.ssh/mine.pub" {
			t.Fatalf("pub = %q, want the provided path", pub)
		}
		if identity != "" {
			t.Fatalf("identity = %q, want empty for a user-provided key", identity)
		}
		if generated {
			t.Fatal("must not generate when a key is provided")
		}
	})

	t.Run("no key → generate managed, then reuse (idempotent)", func(t *testing.T) {
		home := t.TempDir()

		pub, identity, generated, err := resolveSSHKey(home, "")
		if err != nil {
			t.Fatalf("first resolveSSHKey: %v", err)
		}
		if !generated {
			t.Fatal("expected a key to be generated on first run")
		}
		if !strings.HasSuffix(pub, ".pub") {
			t.Fatalf("pub path %q should end in .pub", pub)
		}
		if identity != strings.TrimSuffix(pub, ".pub") {
			t.Fatalf("identity %q should be the private-key path of %q", identity, pub)
		}
		if _, err := os.Stat(identity); err != nil {
			t.Fatalf("private key not written at %s: %v", identity, err)
		}

		pub2, identity2, generated2, err := resolveSSHKey(home, "")
		if err != nil {
			t.Fatalf("second resolveSSHKey: %v", err)
		}
		if generated2 {
			t.Fatal("second run must reuse the key, not regenerate")
		}
		if pub2 != pub || identity2 != identity {
			t.Fatalf("second run returned different paths: (%q,%q) vs (%q,%q)", pub2, identity2, pub, identity)
		}
	})
}

func TestResolveAgentUnknown(t *testing.T) {
	if _, err := resolveAgent("cursor"); err == nil {
		t.Fatal("expected an error for an unsupported agent")
	}
	// Every advertised agent must have a spec.
	for _, a := range supportedAgents {
		if _, ok := agentSpecs[a]; !ok {
			t.Fatalf("supportedAgents lists %q but agentSpecs has no entry", a)
		}
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func mcpServerFromFile(t *testing.T, path, key, name string) mcpServerEntry {
	t.Helper()
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readFile(t, path)), &root); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var servers map[string]mcpServerEntry
	if err := json.Unmarshal(root[key], &servers); err != nil {
		t.Fatalf("parse %s[%s]: %v", path, key, err)
	}
	entry, ok := servers[name]
	if !ok {
		t.Fatalf("%s not present under %s", name, key)
	}
	return entry
}
