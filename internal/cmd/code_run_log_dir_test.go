package cmd

import (
	"context"
	"strings"
	"testing"
)

// `code run` names its run's files in the box user's own run directory
// (#3682), never in the shared root.
func TestCodeRunFilesAreInTheBoxUsersDirectory(t *testing.T) {
	if got := sessionSidecarFor("alice", "code"); got != "/tmp/agent-box/alice/code.session" {
		t.Errorf("sessionSidecarFor = %q, want /tmp/agent-box/alice/code.session", got)
	}
	sess := &fakeApprovalSession{}
	_ = runUsesApprovals(context.Background(), sess, "alice", "code")
	if len(sess.execs) != 1 || !strings.Contains(sess.execs[0], "'/tmp/agent-box/alice/code.answers'") {
		t.Errorf("runUsesApprovals checked %v, want alice's answers directory", sess.execs)
	}
}
