//go:build !containarium_client

package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/guardraildropin"
)

// The drop-in tells Claude Code to run `<binary> guardrail hook <event>
// --engine <address>` with onFailure "block". If that command line does not
// resolve in the binary the daemon copies into a box (its own), every tool
// call in the box is blocked. This feeds each rendered args list to the real
// command tree.
//
// The `guardrail hook` subcommand is #3761's. Until it is in the tree this
// test skips, loudly; it must pass, not skip, before the drop-in ships.
func TestGuardrailDropInHookArgsResolveInTheCommandTree(t *testing.T) {
	raw, err := guardraildropin.Render(guardraildropin.DefaultHookTimeout, guardraildropin.DefaultEngineAddr)
	if err != nil {
		t.Fatal(err)
	}
	var dropIn struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Args []string `json:"args"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &dropIn); err != nil {
		t.Fatal(err)
	}
	if len(dropIn.Hooks) != len(guardraildropin.HookEvents) {
		t.Fatalf("drop-in has %d events, want %d", len(dropIn.Hooks), len(guardraildropin.HookEvents))
	}
	for event, groups := range dropIn.Hooks {
		args := groups[0].Hooks[0].Args
		hook, rest, err := rootCmd.Find(args)
		if err != nil || !strings.HasSuffix(hook.CommandPath(), " guardrail hook") {
			t.Skipf("`guardrail hook` is not in this command tree yet (it lands with #3761); the drop-in's args %v cannot be checked until then", args)
		}
		// The in-box smoke test looks for this in the subcommand's help.
		if !strings.Contains(hook.UseLine(), guardraildropin.SmokeMarker) {
			t.Fatalf("`guardrail hook` usage %q lacks %q, which the install's smoke test looks for", hook.UseLine(), guardraildropin.SmokeMarker)
		}
		engine := hook.Flags().Lookup("engine")
		if engine == nil {
			t.Fatalf("%s: `guardrail hook` has no --engine flag", event)
		}
		t.Cleanup(func() { _ = engine.Value.Set(engine.DefValue) })
		if err := hook.ParseFlags(rest); err != nil {
			t.Fatalf("%s: args %v do not parse: %v", event, args, err)
		}
		if got := hook.Flags().Args(); len(got) != 1 || got[0] != event {
			t.Fatalf("%s: positional args = %v, want the event alone", event, got)
		}
		if engine.Value.String() != guardraildropin.DefaultEngineAddr {
			t.Fatalf("%s: --engine = %q", event, engine.Value.String())
		}
		if err := hook.ValidateArgs(hook.Flags().Args()); err != nil {
			t.Fatalf("%s: %v", event, err)
		}
	}
}
