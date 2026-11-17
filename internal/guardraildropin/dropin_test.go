package guardraildropin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRenderDropIn(t *testing.T) {
	raw, err := Render(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var got settings
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("drop-in is not JSON: %v", err)
	}
	if got.Env["CLAUDE_CODE_DISABLE_FILE_MENTIONS"] != "1" {
		t.Errorf("env = %v, want CLAUDE_CODE_DISABLE_FILE_MENTIONS=1", got.Env)
	}
	want := []string{"SessionStart", "PreToolUse", "PostToolUse", "PostToolBatch", "UserPromptSubmit", "InstructionsLoaded"}
	if len(got.Hooks) != len(want) {
		t.Fatalf("hook events = %d, want %d", len(got.Hooks), len(want))
	}
	for _, ev := range want {
		groups := got.Hooks[ev]
		if len(groups) != 1 || len(groups[0].Hooks) != 1 {
			t.Fatalf("%s: want one hook, got %+v", ev, groups)
		}
		h := groups[0].Hooks[0]
		// Exec form: the binary and its args, no shell in between, so the
		// hook's parent is the client process (the stamp is keyed on it).
		if h.Type != "command" || h.Command != HookBinaryPath {
			t.Errorf("%s: command = %q (%s), want %q", ev, h.Command, h.Type, HookBinaryPath)
		}
		if strings.Join(h.Args, " ") != "guardrail hook "+ev {
			t.Errorf("%s: args = %v", ev, h.Args)
		}
		if h.OnFailure != "block" || h.Timeout != 10 {
			t.Errorf("%s: onFailure=%q timeout=%d, want block/10", ev, h.OnFailure, h.Timeout)
		}
	}
	// A drop-in must leave any other managed policy alone.
	for _, banned := range []string{"allowManagedHooksOnly", "forceLoginMethod", "forceLoginOrgUUID", "disableAllHooks", "sh -c"} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("drop-in must not contain %q", banned)
		}
	}
}

func TestRenderRejectsSubSecondTimeout(t *testing.T) {
	if _, err := Render(500 * time.Millisecond); err == nil {
		t.Fatal("want an error for a timeout under one second")
	}
}
