//go:build containarium_client

package cmd

import (
	"strings"
	"testing"
)

// TestMovedServerCommands_ExitTwoNamingContainariumd is #1777's Done-when:
// each moved-command name is registered in the client build as a leaf stub
// (not the real command — those are tagged !containarium_client and don't
// exist in this build at all) that exits 2.
func TestMovedServerCommands_ExitTwoNamingContainariumd(t *testing.T) {
	for _, name := range movedServerCommands {
		t.Run(name, func(t *testing.T) {
			cmd, _, err := rootCmd.Find([]string{name})
			if err != nil {
				t.Fatalf("command %q not registered: %v", name, err)
			}
			if cmd.Name() != name || cmd.Run == nil {
				t.Fatalf("Find(%q) resolved to %q, not the registered stub", name, cmd.Name())
			}

			orig := osExit
			var gotCode int
			exited := false
			osExit = func(code int) { gotCode = code; exited = true }
			t.Cleanup(func() { osExit = orig })

			cmd.Run(cmd, nil)

			if !exited {
				t.Fatal("expected the stub to call osExit")
			}
			if gotCode != 2 {
				t.Errorf("exit code = %d, want 2", gotCode)
			}
		})
	}
}

// TestMovedCommandMessage_NamesContainariumd pins the exact stub message
// shape: it must name the moved command and containariumd, so an
// operator's journal shows the fix instead of a bare "unknown command".
func TestMovedCommandMessage_NamesContainariumd(t *testing.T) {
	for _, name := range movedServerCommands {
		msg := movedCommandMessage(name)
		if !strings.Contains(msg, name) {
			t.Errorf("message for %q = %q, want it to name the moved command", name, msg)
		}
		if !strings.Contains(msg, "containariumd") {
			t.Errorf("message for %q = %q, want it to name containariumd", name, msg)
		}
	}
}
