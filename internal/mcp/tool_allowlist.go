package mcp

import (
	"fmt"
	"strings"
)

// EnvMCPTools is the operator-facing tool allow-list env var. See
// Config.MCPTools's doc comment for the full contract.
const EnvMCPTools = "CONTAINARIUM_MCP_TOOLS"

// filterToolsByAllowlist returns the subset of tools matching pattern (a
// comma-separated list of exact tool names and/or "prefix_*" globs),
// preserving tools' original registration order and never duplicating a
// tool matched by more than one entry.
//
// Fails closed: an entry that matches no registered tool is an error, not
// a silent no-op — almost certainly an operator typo, and the alternative
// (silently registering fewer tools than intended) surfaces as "the agent
// has no tools" with no clue why. Blank entries (from a trailing comma or
// stray whitespace) are ignored rather than treated as a wildcard.
func filterToolsByAllowlist(tools []Tool, pattern string) ([]Tool, error) {
	var entries []string
	for _, raw := range strings.Split(pattern, ",") {
		if e := strings.TrimSpace(raw); e != "" {
			entries = append(entries, e)
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s is set but names no tool", EnvMCPTools)
	}

	matched := make([]bool, len(entries))
	out := make([]Tool, 0, len(tools))
	for i := range tools {
		added := false
		for j, entry := range entries {
			if !toolMatchesAllowlistEntry(tools[i].Name, entry) {
				continue
			}
			// Every entry this tool satisfies counts as matched — checking
			// them all (never short-circuiting on the first hit) is what
			// makes overlapping entries, e.g. "tracker_*,tracker_get_issue",
			// each register as used rather than only whichever is listed
			// first.
			matched[j] = true
			if !added {
				out = append(out, tools[i])
				added = true
			}
		}
	}

	for j, ok := range matched {
		if !ok {
			return nil, fmt.Errorf("%s entry %q matched no registered tool", EnvMCPTools, entries[j])
		}
	}
	return out, nil
}

// toolMatchesAllowlistEntry reports whether name satisfies entry: an exact
// match, or, when entry ends in "*", a prefix match against everything
// before the "*".
func toolMatchesAllowlistEntry(name, entry string) bool {
	if prefix, ok := strings.CutSuffix(entry, "*"); ok {
		return strings.HasPrefix(name, prefix)
	}
	return name == entry
}
