//go:build !containarium_client

package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// End to end on Linux (the run wrapper needs setsid): a fake engine installs a tool during the run;
// the run's own wrapper records it, the daemon lists it as ADDED_DURING_RUN, and a tool that was
// already there is PRESENT_AT_START. No model is involved.
func TestStartBoxRun_RecordsTheToolchainItsWrapperMeasured(t *testing.T) {
	u := newFakeBoxUser(t, 0, 50*time.Millisecond)
	bin := filepath.Join(u.home, ".local", "bin")
	writeFakeTool(t, bin, "go", "go version go1.99.0 linux/amd64", "")
	// The fake engine "installs" node while it runs.
	engine := "#!/bin/sh\nprintf '#!/bin/sh\\necho v99.1.2\\n' > '" + filepath.Join(bin, "node") + "'\nchmod +x '" + filepath.Join(bin, "node") + "'\nsleep 0.1\necho done\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(engine), 0o755); err != nil {
		t.Fatal(err)
	}
	// The harness's PATH is hermetic (hermeticBoxPath, #2973): only the fake tools in
	// the user's bin plus plain utilities. A CI runner (or a developer machine) has a
	// real node, go, git, java..., and their presence would turn "added during the run"
	// into "changed" and make the probe slow.
	s, _, _ := boxRunStartServer(t, u)

	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{Username: "alice", Prompt: "install a tool"}); err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	waitForOutcome(t, s, "alice", "code", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 5*time.Second)
	resp, err := s.ListBoxRuns(tenantCtx("alice"), &pb.ListBoxRunsRequest{Username: "alice"})
	if err != nil || len(resp.Runs) != 1 {
		t.Fatalf("ListBoxRuns: %v %v", resp, err)
	}
	got := toolsByName(resp.Runs[0].GetTools())
	if g := got["go"]; g == nil || g.GetProvenance() != pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_PRESENT_AT_START ||
		g.GetVersion() != "go version go1.99.0 linux/amd64" || g.GetLocation() != pb.BoxRunToolLocation_BOX_RUN_TOOL_LOCATION_HOME {
		t.Errorf("go = %v, want present at start with its version, under the run user's home", g)
	}
	if n := got["node"]; n == nil || n.GetProvenance() != pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_ADDED_DURING_RUN || n.GetVersion() != "v99.1.2" {
		t.Errorf("node = %v, want added during the run at v99.1.2", n)
	}
}
