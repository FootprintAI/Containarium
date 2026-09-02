package cmd

import (
	"os/exec"
	"strings"
	"testing"
)

func TestShellQuoteSingle_RoundTripsThroughARealShell(t *testing.T) {
	cases := []string{
		"plain text",
		"it's got an apostrophe",
		"multiple ''' quotes '' in a row",
		"",
		"$(rm -rf /) and `also this`",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			quoted := shellQuoteSingle(in)
			// #nosec G204 -- fixed "sh -c" with a single literal-quoted
			// argument built by the function under test; this is the
			// injection check itself, not a caller-reachable path.
			out, err := exec.Command("/bin/sh", "-c", "printf '%s' "+quoted).Output()
			if err != nil {
				t.Fatalf("shell rejected %q (quoted as %q): %v", in, quoted, err)
			}
			if string(out) != in {
				t.Errorf("round-trip = %q, want %q (quoted form was %q)", out, in, quoted)
			}
		})
	}
}

func TestShellQuoteSingle_NeverEscapesOutOfTheQuotedString(t *testing.T) {
	// The classic injection shape: a naive quoter that doesn't handle
	// embedded quotes lets this argument terminate early and run a second
	// command.
	malicious := "'; touch /tmp/pwned; echo '"
	quoted := shellQuoteSingle(malicious)
	// #nosec G204 -- see above.
	out, err := exec.Command("/bin/sh", "-c", "echo "+quoted).Output()
	if err != nil {
		t.Fatalf("shell rejected quoted input: %v", err)
	}
	got := strings.TrimSuffix(string(out), "\n")
	if got != malicious {
		t.Errorf("got %q, want the argument echoed back verbatim (%q) — the shell ran something other than plain echo", got, malicious)
	}
}

func TestBuildClaudeRunCommand(t *testing.T) {
	cmd := buildClaudeRunCommand("fix the bug", false)
	for _, want := range []string{"secrets.env", "~/.local/bin/claude", "-p", shellQuoteSingle("fix the bug")} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command missing %q:\n%s", want, cmd)
		}
	}
	if strings.Contains(cmd, "stream-json") {
		t.Errorf("combined-mode command should not request stream-json:\n%s", cmd)
	}
}

func TestBuildClaudeRunCommand_StreamJSON(t *testing.T) {
	cmd := buildClaudeRunCommand("fix the bug", true)
	if !strings.Contains(cmd, "--output-format stream-json") {
		t.Errorf("expected --output-format stream-json in:\n%s", cmd)
	}
}

func TestRunOutcomeLine(t *testing.T) {
	listing := "Found 2 process(es):\n\n" +
		"🟢 code  (pid 111, running)\n" +
		"   Command:    sleep 5\n" +
		"   Started at: 2026-09-02T12:00:00Z\n" +
		"   Log path:   /tmp/agent-box/code.log\n\n" +
		"⚪ old-task  (pid 222, exited)\n" +
		"   Command:    true\n" +
		"   Exit code:  0\n" +
		"   Log path:   /tmp/agent-box/old-task.log\n\n"

	line, running := runOutcomeLine(listing, "code")
	if !running {
		t.Errorf("code should be reported running, line=%q", line)
	}
	if !strings.Contains(line, "code") || !strings.Contains(line, "running") {
		t.Errorf("line = %q", line)
	}

	line, running = runOutcomeLine(listing, "old-task")
	if running {
		t.Errorf("old-task should not be reported running, line=%q", line)
	}
	if !strings.Contains(line, "old-task") {
		t.Errorf("line = %q", line)
	}

	line, running = runOutcomeLine(listing, "does-not-exist")
	if running || line != "" {
		t.Errorf("unknown name should report not-running/empty line, got running=%v line=%q", running, line)
	}
}

func TestLogPathFromListing(t *testing.T) {
	listing := "Found 1 process(es):\n\n" +
		"🟢 code  (pid 111, running)\n" +
		"   Command:    claude -p hi\n" +
		"   Started at: 2026-09-02T12:00:00Z\n" +
		"   Log path:   /tmp/agent-box/code.log\n\n"

	got, err := logPathFromListing(listing, "code")
	if err != nil {
		t.Fatalf("logPathFromListing: %v", err)
	}
	if got != "/tmp/agent-box/code.log" {
		t.Errorf("got %q, want /tmp/agent-box/code.log", got)
	}

	if _, err := logPathFromListing(listing, "nope"); err == nil {
		t.Error("expected an error for a name not in the listing")
	}
}
