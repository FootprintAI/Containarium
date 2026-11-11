package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun"
)

// #3613: `code run --workdir` starts the run in a directory under the box
// user's home. Over SSH the directory is checked on the box
// (coderun.Session.ResolveWorkdir, covered in internal/coderun); these tests
// cover what the command does before and around that.

// With --run-token-file the workdir goes to the daemon as
// StartBoxRunRequest.workdir, for an agent run and a --command run alike.
func TestCodeRunWorkdir_TokenPathSendsItToTheDaemon(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func()
	}{
		{"prompt run", func() { codeRunPrompt = "fix the bug" }},
		{"command run", func() { codeRunCommand = "pwd" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCodeRunTokenFixture(t)
			tc.set()
			codeRunWorkdir = "src/app"
			codeRunTokenFile = writeRunTokenFile(t, testRunTokenValue)
			if err := f.run("alice"); err != nil {
				t.Fatalf("code run --workdir --run-token-file: %v", err)
			}
			if len(f.daemon.starts) != 1 || f.daemon.starts[0].GetWorkdir() != "src/app" {
				t.Fatalf("StartBoxRun requests = %v, want one with workdir src/app", f.daemon.starts)
			}
		})
	}
	t.Run("no --workdir sends none", func(t *testing.T) {
		f := newCodeRunTokenFixture(t)
		codeRunPrompt = "fix the bug"
		codeRunTokenFile = writeRunTokenFile(t, testRunTokenValue)
		if err := f.run("alice"); err != nil {
			t.Fatal(err)
		}
		if got := f.daemon.starts[0].GetWorkdir(); got != "" {
			t.Errorf("workdir = %q, want none", got)
		}
	})
}

// A --workdir that is absolute, escapes the home or is not canonical is
// refused before anything connects, on every path: the daemon-API client is
// never opened, and the SSH path never reaches its first step.
func TestCodeRunWorkdir_NonCanonicalIsRefusedBeforeAnything(t *testing.T) {
	for _, bad := range []string{"/etc", "..", "../x", "a/../b", ".", "a/", ".ssh", "a\nb"} {
		t.Run("token path "+bad, func(t *testing.T) {
			f := newCodeRunTokenFixture(t)
			codeRunPrompt, codeRunWorkdir = "fix the bug", bad
			codeRunTokenFile = writeRunTokenFile(t, testRunTokenValue)
			err := f.run("alice")
			if err == nil || !strings.HasPrefix(err.Error(), "--workdir ") {
				t.Fatalf("err = %v, want a --workdir refusal", err)
			}
			if f.clientCalls != 0 || len(f.daemon.starts) != 0 {
				t.Errorf("client opened %d time(s), StartBoxRun called %d time(s); want neither", f.clientCalls, len(f.daemon.starts))
			}
		})
		t.Run("ssh path "+bad, func(t *testing.T) {
			f := newCodeRunTokenFixture(t)
			savedInputs := newRunInputsClient
			t.Cleanup(func() { newRunInputsClient = savedInputs })
			inputsCalls := 0
			newRunInputsClient = func() (runInputsAPI, error) {
				inputsCalls++
				return nil, errors.New("ssh path: approval key fetched")
			}
			// --approvals ask makes the SSH path's first step a client call
			// this test can see.
			codeRunPrompt, codeRunApprovals, codeRunWorkdir = "fix the bug", string(coderun.ApprovalsAsk), bad
			err := f.run("alice")
			if err == nil || !strings.HasPrefix(err.Error(), "--workdir ") {
				t.Fatalf("err = %v, want a --workdir refusal", err)
			}
			if inputsCalls != 0 {
				t.Errorf("the SSH path went on after a bad --workdir (%d client call(s))", inputsCalls)
			}
		})
		t.Run("command run "+bad, func(t *testing.T) {
			f := newCodeRunTokenFixture(t)
			codeRunCommand, codeRunWorkdir = "pwd", bad
			err := f.run("alice")
			if err == nil || !strings.HasPrefix(err.Error(), "--workdir ") {
				t.Fatalf("err = %v, want a --workdir refusal", err)
			}
		})
	}
}

func TestCodeRunWorkdir_FlagIsRegistered(t *testing.T) {
	f := codeRunCmd.Flags().Lookup("workdir")
	if f == nil {
		t.Fatal("code run has no --workdir flag")
	}
	if f.DefValue != "" {
		t.Errorf("--workdir default = %q, want empty (the home)", f.DefValue)
	}
}
