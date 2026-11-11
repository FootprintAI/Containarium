package cmd

import (
	"strings"
	"testing"
	"time"
)

// #3425: --output-format-stream-json frames the log for a stream-json consumer;
// a plain shell command's output is not JSON, so the flag is refused with
// --command like --approvals, --prompt, --session and --continue are.
func TestValidateCommandModeFlagsRejectsStreamJSON(t *testing.T) {
	saved := []any{codeRunPrompt, codeRunSession, codeRunContinue, codeRunApprovals, codeRunStreamJSON, codeRunTimeout}
	defer func() {
		codeRunPrompt, codeRunSession, codeRunContinue = saved[0].(string), saved[1].(string), saved[2].(bool)
		codeRunApprovals, codeRunStreamJSON, codeRunTimeout = saved[3].(string), saved[4].(bool), saved[5].(time.Duration)
	}()
	codeRunPrompt, codeRunSession, codeRunContinue = "", "", false
	codeRunApprovals, codeRunStreamJSON, codeRunTimeout = "deny", false, 0

	if _, err := validateCommandModeFlags(); err != nil {
		t.Fatalf("plain --command rejected: %v", err)
	}
	codeRunStreamJSON = true
	_, err := validateCommandModeFlags()
	if err == nil || !strings.Contains(err.Error(), "--output-format-stream-json") {
		t.Fatalf("stream-json with --command: err = %v, want a rejection naming the flag", err)
	}
	codeRunStreamJSON = false
	codeRunTimeout = 1500 * time.Millisecond
	secs, err := validateCommandModeFlags()
	if err != nil || secs != 2 {
		t.Fatalf("--timeout 1500ms = (%d, %v), want (2, nil)", secs, err)
	}
}
