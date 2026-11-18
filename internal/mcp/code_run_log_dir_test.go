package mcp

import "testing"

// The code_run tool names its run's session sidecar in the box user's own run
// directory (#3682), never in the shared root.
func TestMCPSessionSidecarIsInTheBoxUsersDirectory(t *testing.T) {
	if got := mcpSessionSidecar("alice", "code"); got != "/tmp/agent-box/alice/code.session" {
		t.Errorf("mcpSessionSidecar = %q, want /tmp/agent-box/alice/code.session", got)
	}
}
