package coderun

import "testing"

// These helpers are the seam the CLI and the platform MCP both go through
// (#1698), so a change here moves both surfaces at once — which is the point,
// and the reason they are worth pinning.

func TestShellQuoteSingle(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain", "hello", `'hello'`},
		{"spaces", "add a health endpoint", `'add a health endpoint'`},
		{"embedded quote", "don't", `'don'\''t'`},
		// The reason this function exists: process_start runs its command
		// under /bin/sh -c on the box, so an unquoted prompt is a shell
		// injection.
		{"injection attempt", "x'; rm -rf /; echo '", `'x'\''; rm -rf /; echo '\'''`},
		{"empty", "", `''`},
		{"dollar and backtick stay literal", "$HOME `id`", "'$HOME `id`'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShellQuoteSingle(tt.in); got != tt.want {
				t.Errorf("ShellQuoteSingle(%q) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

func TestBuildClaudeRunCommand_QuotesThePromptAndSourcesSecrets(t *testing.T) {
	got := BuildClaudeRunCommand("don't panic", false)
	if want := `'don'\''t panic'`; !contains(got, want) {
		t.Errorf("prompt not shell-quoted:\n%s", got)
	}
	// The credential reaches the run by sourcing the seeded file, never as an
	// argument — otherwise it would land in the run record and process_list.
	if !contains(got, "/run/containarium/secrets.env") {
		t.Errorf("secrets not sourced:\n%s", got)
	}
	if contains(got, "--output-format stream-json") {
		t.Errorf("stream-json leaked into the non-streaming command:\n%s", got)
	}
	if streamed := BuildClaudeRunCommand("hi", true); !contains(streamed, "--output-format stream-json") {
		t.Errorf("stream-json missing when requested:\n%s", streamed)
	}
}

func TestCaptureModeFor(t *testing.T) {
	if got := CaptureModeFor(true); got != "framed" {
		t.Errorf("CaptureModeFor(true) = %q, want framed", got)
	}
	if got := CaptureModeFor(false); got != "combined" {
		t.Errorf("CaptureModeFor(false) = %q, want combined", got)
	}
}

const sampleListing = `Found 2 process(es):

🟢 code  (pid 101, running)
   Command:    claude -p 'x'
   Started at: 2026-09-03T10:00:00Z
   Log path:   /tmp/agent-box/code.log

⚪ other  (pid 202, exited)
   Command:    true
   Started at: 2026-09-03T09:00:00Z
   Exit code:  0
   Log path:   /tmp/agent-box/other.log
`

func TestRunOutcomeLine(t *testing.T) {
	tests := []struct {
		name        string
		run         string
		wantFound   bool
		wantRunning bool
	}{
		{"running run", "code", true, true},
		{"exited run", "other", true, false},
		// A name that never appears counts as not-running: there is nothing
		// left to wait for either way.
		{"absent run", "nope", false, false},
		// Must not match on a prefix — "cod" is not "code".
		{"prefix is not a match", "cod", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, running := RunOutcomeLine(sampleListing, tt.run)
			if (line != "") != tt.wantFound {
				t.Errorf("line = %q, wantFound = %v", line, tt.wantFound)
			}
			if running != tt.wantRunning {
				t.Errorf("running = %v, want %v", running, tt.wantRunning)
			}
		})
	}
}

func TestLogPathFromListing(t *testing.T) {
	got, err := LogPathFromListing(sampleListing, "code")
	if err != nil {
		t.Fatalf("LogPathFromListing: %v", err)
	}
	if got != "/tmp/agent-box/code.log" {
		t.Errorf("log path = %q", got)
	}

	// The second entry's path must not be attributed to the first.
	other, err := LogPathFromListing(sampleListing, "other")
	if err != nil || other != "/tmp/agent-box/other.log" {
		t.Errorf("other log path = %q (%v)", other, err)
	}

	// An absent run is an error, not an empty string a caller might tail.
	if _, err := LogPathFromListing(sampleListing, "nope"); err == nil {
		t.Error("absent run should error rather than return an empty path")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
