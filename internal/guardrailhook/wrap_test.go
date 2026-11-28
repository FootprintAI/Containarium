package guardrailhook

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// #3765 item 1. A failed shell command reaches the model as an error result,
// which the agent does not pass through PostToolUse, so its output used to
// reach the model unredacted (observed live in
// docs/verification/2026-W48-guardrail-hook.md, step 3). PreToolUse now
// prefixes a Bash command with an EXIT trap that prints the real exit status
// and exits 0, so the result takes the normal, redacted PostToolUse path.

// wrappedCommand fires PreToolUse for a Bash call and returns the command the
// agent would run, or "" when the handler left the call untouched.
func wrappedCommand(t *testing.T, h *Handler, toolInput string) string {
	t.Helper()
	out := fire(t, h, evPre, preInput("Bash", toolInput))
	if out.HookSpecificOutput == nil {
		return ""
	}
	if d := out.HookSpecificOutput.PermissionDecision; d != "" {
		t.Fatalf("PreToolUse must not decide about the call, got %q", d)
	}
	cmd, ok := stringField(out.HookSpecificOutput.UpdatedInput, "command")
	if !ok {
		t.Fatalf("updatedInput has no command: %+v", out.HookSpecificOutput.UpdatedInput)
	}
	return cmd
}

// runBash runs a command the way the agent's Bash tool would, and returns its
// output and exit status.
func runBash(t *testing.T, command string) (string, int) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	out, err := exec.Command("bash", "-c", command).CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exit):
		return string(out), exit.ExitCode()
	default:
		t.Fatalf("run %q: %v", command, err)
		return "", 0
	}
}

func bashResponse(stdout string) string {
	return `{"stdout":` + q(stdout) + `,"stderr":"","interrupted":false,"isImage":false}`
}

// Criterion: with the wrapper on, `sh -c 'echo <synthetic secret>; exit 3'`
// reaches the model as a marker plus a line naming exit status 3, and the
// tool call does not report as failed.
func TestPreToolUse_WrapsBashSoAFailedCommandIsRedacted(t *testing.T) {
	h, _ := newHandler(t, nil)
	original := "sh -c 'echo " + synthKey + "; exit 3'"
	wrapped := wrappedCommand(t, h, `{"command":`+q(original)+`,"description":"x"}`)
	if wrapped == "" {
		t.Fatal("a Bash call must be wrapped")
	}
	if !strings.HasSuffix(wrapped, original) {
		t.Fatalf("the original command must run unchanged after the prefix, got %q", wrapped)
	}

	stdout, code := runBash(t, wrapped)
	if code != 0 {
		t.Fatalf("the wrapped command must exit 0 so the call does not fail, got %d (%q)", code, stdout)
	}
	if !strings.Contains(stdout, "[exit status 3]") {
		t.Fatalf("the real exit status must be reported, got %q", stdout)
	}

	// The result now takes the normal path: PostToolUse redacts it.
	out := fire(t, h, evPost, postInput("Bash", `{"command":`+q(wrapped)+`}`, bashResponse(stdout)))
	if out.HookSpecificOutput == nil || len(out.HookSpecificOutput.UpdatedToolOutput) == 0 {
		t.Fatal("PostToolUse must replace the result")
	}
	got := string(out.HookSpecificOutput.UpdatedToolOutput)
	if strings.Contains(got, synthKey) {
		t.Fatalf("the secret reached the model: %s", got)
	}
	if !strings.Contains(got, "[[AWS_ACCESS_KEY_ID:") || !strings.Contains(got, "[exit status 3]") {
		t.Fatalf("want a marker and the exit status line, got %s", got)
	}
}

// The wrapper survives what a brace group does not: `exit N` in the command
// itself, and a failure in the middle of a `set -e` script.
func TestPreToolUse_WrapperReportsEveryWayACommandCanFail(t *testing.T) {
	h, _ := newHandler(t, nil)
	for _, tc := range []struct {
		name, command, status string
	}{
		{"exit in the command", "echo out; exit 4", "[exit status 4]"},
		{"failing last command", "echo out; false", "[exit status 1]"},
		{"set -e stops early", "set -e; echo out; false; echo never", "[exit status 1]"},
		{"pipeline status", "echo out | grep -q nomatch", "[exit status 1]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, code := runBash(t, wrappedCommand(t, h, `{"command":`+q(tc.command)+`}`))
			if code != 0 || !strings.Contains(stdout, tc.status) {
				t.Fatalf("want exit 0 and %q, got %d %q", tc.status, code, stdout)
			}
			if strings.Contains(stdout, "never") {
				t.Fatalf("set -e must still stop the script: %q", stdout)
			}
		})
	}
}

// A command that succeeds is unchanged in what it prints: no status line.
func TestPreToolUse_WrapperIsSilentOnSuccess(t *testing.T) {
	h, _ := newHandler(t, nil)
	stdout, code := runBash(t, wrappedCommand(t, h, `{"command":"echo hello"}`))
	if code != 0 || stdout != "hello\n" {
		t.Fatalf("want exit 0 and exactly %q, got %d %q", "hello\n", code, stdout)
	}
}

// Criterion: a command that sets its own EXIT trap still runs it. Its trap
// replaces ours, so such a command keeps the old behaviour on failure; that
// limit is documented rather than worked around.
func TestPreToolUse_CommandsOwnExitTrapStillRuns(t *testing.T) {
	h, _ := newHandler(t, nil)
	stdout, _ := runBash(t, wrappedCommand(t, h, `{"command":"trap 'echo mine' EXIT; echo body"}`))
	if !strings.Contains(stdout, "body") || !strings.Contains(stdout, "mine") {
		t.Fatalf("the command's own EXIT trap must still run, got %q", stdout)
	}
}

// Criterion: a background command is not wrapped. Its output is read later
// through another tool call, which PostToolUse sees on its own.
// PowerShell is not wrapped either: the prefix is POSIX shell. A command
// that is already wrapped is not wrapped twice. And the flag turns it off.
func TestPreToolUse_WhatIsNotWrapped(t *testing.T) {
	h, _ := newHandler(t, nil)
	if got := wrappedCommand(t, h, `{"command":"sleep 30","run_in_background":true}`); got != "" {
		t.Errorf("a background command must not be wrapped, got %q", got)
	}
	if out := fire(t, h, evPre, preInput("PowerShell", `{"command":"Get-Date"}`)); out.HookSpecificOutput != nil {
		t.Errorf("PowerShell must not be wrapped, got %+v", out)
	}
	once := wrappedCommand(t, h, `{"command":"false"}`)
	if again := wrappedCommand(t, h, `{"command":`+q(once)+`}`); again != "" && again != once {
		t.Errorf("a wrapped command must not be wrapped twice, got %q", again)
	}

	off, _ := newHandler(t, func(c *Config) { c.DisableCommandWrapper = true })
	if got := wrappedCommand(t, off, `{"command":"false"}`); got != "" {
		t.Errorf("with the wrapper off, Bash must pass through untouched, got %q", got)
	}
}

// The model is told what the status line means, so a failed command is not
// read as a success.
func TestSessionStart_ExplainsTheExitStatusLine(t *testing.T) {
	h, _ := newHandler(t, nil)
	out := fire(t, h, evSession, `{"session_id":"s1","source":"startup"}`)
	if out.HookSpecificOutput == nil || !strings.Contains(out.HookSpecificOutput.AdditionalContext, "[exit status") {
		t.Fatalf("the session context must explain the exit status line: %+v", out)
	}
}
