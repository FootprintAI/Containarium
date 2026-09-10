package cmd

import (
	"sort"

	"github.com/spf13/cobra"
)

// movedStubAnnotation marks a cobra command registered by
// moved_stubs_client.go (containarium_client only). Read here so
// renderCommandTree can tag a stub's path distinctly without this
// (untagged, shared) file needing to reference anything client-only.
const movedStubAnnotation = "containarium/moved-stub"

func isMovedStub(cmd *cobra.Command) bool {
	return cmd.Annotations[movedStubAnnotation] == "true"
}

// renderCommandTree returns every runnable command path registered under
// cmd, recursively, sorted — "pool list", "label set", "moved:daemon", …
// Group-only parents (no Run/RunE of their own — cobra prints help when
// they're invoked bare) are walked but not listed themselves; only leaves
// that actually do something are. Hidden commands (upgrade-watchdog, an
// internal-only invocation with no --help visibility) are included
// deliberately — hidden-ness is a help-text choice, not an existence
// boundary, and this gate cares about what actually compiles in, not what
// --help shows.
//
// A moved-command stub (moved_stubs_client.go, #1777) is rendered with a
// "moved:" prefix so the golden list can mark it distinctly from a real
// command of the same name — the allow-list gate (#1778) needs to tell
// "daemon exists as a stub" from "daemon exists for real" apart.
func renderCommandTree(cmd *cobra.Command) []string {
	var out []string
	var walk func(c *cobra.Command, prefix string)
	walk = func(c *cobra.Command, prefix string) {
		for _, child := range c.Commands() {
			path := prefix + child.Name()
			if child.Runnable() {
				if isMovedStub(child) {
					out = append(out, "moved:"+path)
				} else {
					out = append(out, path)
				}
			}
			walk(child, path+" ")
		}
	}
	walk(cmd, "")
	sort.Strings(out)
	return out
}
