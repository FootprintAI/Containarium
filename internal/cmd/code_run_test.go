package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// resetCodeRunFlags saves and restores the package-level flag vars runCodeRun
// reads, so one test's flags never leak into the next.
func resetCodeRunFlags(t *testing.T) {
	t.Helper()
	origPrompt, origSession, origContinue, origName := codeRunPrompt, codeRunSession, codeRunContinue, codeName
	t.Cleanup(func() {
		codeRunPrompt, codeRunSession, codeRunContinue, codeName = origPrompt, origSession, origContinue, origName
	})
}

// TestRunCodeRun_SessionAndContinueAreMutuallyExclusive is the issue's own
// AC: "passing both is an error." This must be caught before anything
// touches the box — resolveCodeSession is never reached, so this test needs
// no session/ssh fakes at all.
func TestRunCodeRun_SessionAndContinueAreMutuallyExclusive(t *testing.T) {
	resetCodeRunFlags(t)
	codeRunPrompt = "fix the bug"
	codeRunSession = "abc-123"
	codeRunContinue = true

	cmd := &cobra.Command{}
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetContext(context.Background())

	err := runCodeRun(cmd, []string{"alice"})
	if err == nil {
		t.Fatal("expected an error when --session and --continue are both set")
	}
	if !strings.Contains(err.Error(), "--session") || !strings.Contains(err.Error(), "--continue") {
		t.Errorf("error should name both flags: %v", err)
	}
}

// TestCodeRunName_SessionIDBecomesTheDefaultName is the accepted default from
// the issue thread: resuming via --session with no explicit --name uses the
// session id as the run name, consistent with StartBoxRun's own rule.
func TestCodeRunName_SessionIDBecomesTheDefaultName(t *testing.T) {
	resetCodeRunFlags(t)

	codeRunSession = "sess-42"
	if got := codeRunName(); got != "sess-42" {
		t.Errorf("codeRunName() = %q, want the session id %q", got, "sess-42")
	}

	// An explicit --name still wins over --session.
	codeName = "explicit-name"
	if got := codeRunName(); got != "explicit-name" {
		t.Errorf("codeRunName() = %q, want the explicit --name %q", got, "explicit-name")
	}

	// Neither set: the shared default, unchanged.
	codeRunSession, codeName = "", ""
	if got := codeRunName(); got != defaultCodeRunName {
		t.Errorf("codeRunName() = %q, want the default %q", got, defaultCodeRunName)
	}
}
