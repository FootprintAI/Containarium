package coderun

import (
	"fmt"
	"strings"
)

// The operations behind `containarium code`, shared by the CLI handlers and
// the platform MCP tools (#1698). CLAUDE.md's rule is CLI-first with MCP as a
// thin wrapper over the SAME Go function — these live here so the two surfaces
// cannot drift, rather than each parsing process_list its own way.

// DefaultRunName is the process name a run uses when the caller names none.
// A stable default is what lets `code attach <box>` find the run `code run
// <box>` started without the user tracking an identifier.
const DefaultRunName = "code"

// ShellQuoteSingle single-quotes s for a POSIX shell, escaping any embedded
// single quote by closing the quoted string, emitting a backslash-escaped
// quote, then reopening. process_start runs its command under /bin/sh -c on
// the box, so an unescaped caller-supplied prompt would be shell-interpreted
// there — this is what stands between "the agent's prompt" and arbitrary
// command injection into that shell.
func ShellQuoteSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// BuildClaudeRunCommand renders the shell command a run executes on the box.
// Sourcing the seeded secrets file is what supplies the model credential
// without it ever being a CLI argument or appearing in the run record.
func BuildClaudeRunCommand(prompt string, streamJSON bool) string {
	cmd := "set -a; [ -f /run/containarium/secrets.env ] && . /run/containarium/secrets.env; set +a; " +
		"~/.local/bin/claude -p " + ShellQuoteSingle(prompt)
	if streamJSON {
		cmd += " --output-format stream-json"
	}
	return cmd
}

// CaptureModeFor maps the stream-json flag to the capture_mode process_start
// expects. Framed exists so a JSON stream on stdout is not corrupted by
// diagnostics interleaved from stderr.
func CaptureModeFor(streamJSON bool) string {
	if streamJSON {
		return "framed"
	}
	return "combined"
}

// RunOutcomeLine finds name's own line in process_list's raw text (the
// "<icon> <name>  (pid <pid>, <outcome>)" format handleProcessList emits) and
// reports whether it is still running.
//
// A name that does not appear at all — never started, or its record rotated
// away by a later same-name run — counts as not-running: there is nothing left
// to wait for either way.
func RunOutcomeLine(listing, name string) (line string, running bool) {
	for _, l := range strings.Split(listing, "\n") {
		trimmed := strings.TrimSpace(l)
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || fields[1] != name {
			continue
		}
		return trimmed, strings.Contains(trimmed, ", running)")
	}
	return "", false
}

// LogPathFromListing extracts name's log path from process_list's raw text.
// The path is the handle every subsequent read uses, so a listing without one
// is an error rather than an empty string a caller might tail.
func LogPathFromListing(listing, name string) (string, error) {
	lines := strings.Split(listing, "\n")
	for i, l := range lines {
		fields := strings.Fields(strings.TrimSpace(l))
		if len(fields) < 2 || fields[1] != name {
			continue
		}
		for _, follow := range lines[i:] {
			if strings.HasPrefix(strings.TrimSpace(follow), "Log path:") {
				return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(follow), "Log path:")), nil
			}
		}
		return "", fmt.Errorf("process_list entry for %q has no Log path line", name)
	}
	return "", fmt.Errorf("no run named %q in process_list", name)
}
