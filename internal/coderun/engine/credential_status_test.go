package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCredentialStatusScript_UnknownEngine pins that an engine with no probe
// (Codex, until #2273) fails closed with ok=false, never a guessed answer.
func TestCredentialStatusScript_UnknownEngine(t *testing.T) {
	if _, ok := CredentialStatusScript(Name("codex")); ok {
		t.Error("an engine with no probe should report ok=false, not a script")
	}
}

// TestParseCredentialStatusSource pins the three valid values and rejects
// anything else loudly — "defaulting" an unrecognized probe output to "none"
// would silently misreport a box that actually has a credential.
func TestParseCredentialStatusSource(t *testing.T) {
	for _, v := range []CredentialStatusSource{CredentialStatusInteractive, CredentialStatusAPIKey, CredentialStatusNone} {
		got, err := ParseCredentialStatusSource(string(v))
		if err != nil {
			t.Errorf("ParseCredentialStatusSource(%q) error: %v", v, err)
		}
		if got != v {
			t.Errorf("ParseCredentialStatusSource(%q) = %q", v, got)
		}
	}
	if _, err := ParseCredentialStatusSource("some-token-value"); err == nil {
		t.Error("an unrecognized probe output must be an error, not silently accepted")
	}
	if _, err := ParseCredentialStatusSource(""); err == nil {
		t.Error("empty output must be an error")
	}
}

// TestCredentialStatusScript_Claude is an end-to-end proof against a REAL
// shell (not a string match on the script) — the same style
// session_discovery_test.go uses for the same reason: the interesting bug
// here is a shell-quoting or logic mistake that a string comparison of the
// rendered script would never catch.
//
// Each case asserts the script prints EXACTLY one line and never more — the
// contract this probe exists to guarantee (a credential's value must never
// appear in its output).
func TestCredentialStatusScript_Claude(t *testing.T) {
	script, ok := CredentialStatusScript(NameClaude)
	if !ok {
		t.Fatal("CredentialStatusScript(NameClaude) ok=false")
	}

	tests := []struct {
		name string
		seed func(home string)
		want CredentialStatusSource
	}{
		{
			name: "nothing present",
			seed: func(string) {},
			want: CredentialStatusNone,
		},
		{
			name: "interactive sign-in present",
			seed: func(home string) {
				mustMkdirAll(t, filepath.Join(home, ".claude"))
				// The file's PRESENCE is what the probe checks; its content
				// (if any real credential value ever landed here) must never
				// be read by the script, so an arbitrary placeholder proves
				// the point as well as a real token would — better, since a
				// real token in a test fixture is itself a thing to avoid.
				mustWriteFile(t, filepath.Join(home, ".claude", ".credentials.json"), `{"placeholder":"not a real credential"}`)
			},
			want: CredentialStatusInteractive,
		},
		{
			name: "user-placed API key in settings.json",
			seed: func(home string) {
				mustMkdirAll(t, filepath.Join(home, ".claude"))
				mustWriteFile(t, filepath.Join(home, ".claude", "settings.json"), `{"env":{"ANTHROPIC_API_KEY":"placeholder"}}`)
			},
			want: CredentialStatusAPIKey,
		},
		{
			name: "interactive wins over a settings.json that also exists",
			seed: func(home string) {
				mustMkdirAll(t, filepath.Join(home, ".claude"))
				mustWriteFile(t, filepath.Join(home, ".claude", ".credentials.json"), `{"placeholder":"not a real credential"}`)
				mustWriteFile(t, filepath.Join(home, ".claude", "settings.json"), `{"env":{"ANTHROPIC_API_KEY":"placeholder"}}`)
			},
			want: CredentialStatusInteractive,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			tc.seed(home)
			got := runCredentialStatusScript(t, script, home, nil)
			if got != string(tc.want) {
				t.Errorf("script output = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCredentialStatusScript_Claude_ProviderEnv covers the 3P-provider-env
// branch, which (unlike the file-based cases above) needs an env var set on
// the process rather than a seeded file.
func TestCredentialStatusScript_Claude_ProviderEnv(t *testing.T) {
	script, ok := CredentialStatusScript(NameClaude)
	if !ok {
		t.Fatal("CredentialStatusScript(NameClaude) ok=false")
	}
	home := t.TempDir()
	got := runCredentialStatusScript(t, script, home, []string{"CLAUDE_CODE_USE_BEDROCK=1"})
	if got != string(CredentialStatusAPIKey) {
		t.Errorf("script output = %q, want %q", got, CredentialStatusAPIKey)
	}
}

// TestCredentialStatusScript_Pi mirrors the Claude table for pi's own probe.
func TestCredentialStatusScript_Pi(t *testing.T) {
	script, ok := CredentialStatusScript(NamePi)
	if !ok {
		t.Fatal("CredentialStatusScript(NamePi) ok=false")
	}

	tests := []struct {
		name string
		seed func(home string)
		want CredentialStatusSource
	}{
		{
			name: "nothing present",
			seed: func(string) {},
			want: CredentialStatusNone,
		},
		{
			name: "pi's own /login sign-in present",
			seed: func(home string) {
				dir := filepath.Join(home, ".pi", "agent")
				mustMkdirAll(t, dir)
				mustWriteFile(t, filepath.Join(dir, "auth.json"), `{"placeholder":"not a real credential"}`)
			},
			want: CredentialStatusInteractive,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			tc.seed(home)
			got := runCredentialStatusScript(t, script, home, nil)
			if got != string(tc.want) {
				t.Errorf("script output = %q, want %q", got, tc.want)
			}
		})
	}
}

// runCredentialStatusScript runs script under /bin/sh with HOME overridden
// to home (and extraEnv appended), and asserts stdout is EXACTLY one line —
// catching a probe that accidentally prints more than the single canonical
// answer it is allowed to.
func runCredentialStatusScript(t *testing.T, script, home string, extraEnv []string) string {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", script)
	env := make([]string, 0, len(os.Environ())+len(extraEnv)+1)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "HOME=") {
			env = append(env, e)
		}
	}
	env = append(env, "HOME="+home)
	env = append(env, extraEnv...)
	cmd.Env = env

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("script failed: %v\nscript:\n%s", err, script)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("script printed %d lines, want exactly 1 (never more than the source name): %q", len(lines), string(out))
	}
	return lines[0]
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
