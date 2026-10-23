package runlog

import (
	"bytes"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func toolRun(name string, tools ...*pb.BoxRunTool) *pb.BoxRun {
	return &pb.BoxRun{
		RunName:   name,
		StartedAt: timestamppb.New(time.Date(2026, 10, 23, 2, 46, 0, 0, time.UTC)),
		Outcome:   pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED,
		LogPath:   "/tmp/agent-box/" + name + ".log",
		Tools:     tools,
	}
}

// Tools are printed under the table, labelled as measured on the box and as AVAILABLE (not
// used), with provenance and a location class; the table itself is unchanged.
func TestWriteBoxRuns_PrintsTheMeasuredToolsUnderTheTable(t *testing.T) {
	runs := []*pb.BoxRun{toolRun("code",
		&pb.BoxRunTool{Name: "buf", Version: "1.75.0", Provenance: pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_ADDED_DURING_RUN, Location: pb.BoxRunToolLocation_BOX_RUN_TOOL_LOCATION_HOME},
		&pb.BoxRunTool{Name: "git", Version: "", Provenance: pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_PRESENT_AT_START, Location: pb.BoxRunToolLocation_BOX_RUN_TOOL_LOCATION_SYSTEM},
	)}
	var buf bytes.Buffer
	if err := WriteBoxRuns(&buf, "alice", runs); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	table, tools, found := strings.Cut(out, "\ntools available to run code (measured on the box):\n")
	if !found {
		t.Fatalf("no tools block:\n%s", out)
	}
	if !strings.HasPrefix(table, "NAME") || strings.Contains(table, "buf") {
		t.Errorf("the table must come first and be unchanged:\n%s", table)
	}
	for _, want := range []string{"buf  1.75.0  [added during the run, run user's home]", "git  (version not reported)  [present at start, system]"} {
		if !strings.Contains(tools, want) {
			t.Errorf("tools block lacks %q:\n%s", want, tools)
		}
	}
}

// A run with no tools adds nothing: the output is byte-identical to what it was before.
func TestWriteBoxRuns_NoToolsLeavesTheOutputUnchanged(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteBoxRuns(&buf, "alice", []*pb.BoxRun{toolRun("code")}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "tools available") {
		t.Errorf("no tools block expected:\n%s", buf.String())
	}
}
