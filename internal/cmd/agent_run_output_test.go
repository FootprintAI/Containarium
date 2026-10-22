package cmd

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestPrintAgentRunResult pins what `containarium agent run` prints (#2919):
// a run id is always surfaced with a pointer to crew logs, a server-provided
// message is surfaced, and the stale "Phase 0 seam" line is gone.
func TestPrintAgentRunResult(t *testing.T) {
	tests := []struct {
		name    string
		resp    *pb.RunAgentSkillResponse
		want    []string
		notWant []string
	}{
		{
			name:    "async run: run id, no artifact",
			resp:    &pb.RunAgentSkillResponse{RunId: "run-123"},
			want:    []string{"Run:", "run-123", "crew logs run-123"},
			notWant: []string{"Phase 0", "no artifact returned"},
		},
		{
			name: "server message is rendered",
			resp: &pb.RunAgentSkillResponse{
				RunId:   "run-123",
				Message: "run enrolled; poll its status for progress",
			},
			want: []string{"run-123", "run enrolled; poll its status for progress"},
		},
		{
			name:    "synchronous artifact with run id",
			resp:    &pb.RunAgentSkillResponse{RunId: "run-9", ArtifactJson: `{"ok":true}`},
			want:    []string{"run-9", `{"ok":true}`},
			notWant: []string{"no artifact returned"},
		},
		{
			name:    "nothing returned: say so plainly",
			resp:    &pb.RunAgentSkillResponse{},
			want:    []string{"no artifact returned"},
			notWant: []string{"Phase 0", "Run:"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printAgentRunResult(&buf, tt.resp, "")
			out := buf.String()
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q:\n%s", w, out)
				}
			}
			for _, nw := range tt.notWant {
				if strings.Contains(out, nw) {
					t.Errorf("output unexpectedly contains %q:\n%s", nw, out)
				}
			}
		})
	}
}
