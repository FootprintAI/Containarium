package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// runSkillOnlyAPI implements just enough of API to drive handleRunAgentSkill.
// The embedded interface panics if the handler reaches for anything else.
type runSkillOnlyAPI struct {
	API
	resp *RunAgentSkillResponse
}

func (a *runSkillOnlyAPI) RunAgentSkill(RunAgentSkillRequest) (*RunAgentSkillResponse, error) {
	return a.resp, nil
}

// TestHandleRunAgentSkill_Output pins what the run_agent_skill tool prints
// (#2919): a run id is always surfaced with a pointer to crew_logs, a
// server-provided message is surfaced, and the stale "Phase 0 seam" line is
// gone.
func TestHandleRunAgentSkill_Output(t *testing.T) {
	tests := []struct {
		name    string
		resp    *RunAgentSkillResponse
		want    []string
		notWant []string
	}{
		{
			name: "async run: run id, no artifact",
			resp: &RunAgentSkillResponse{RunID: "run-123"},
			want: []string{"Run:", "run-123", "crew_logs"},
			notWant: []string{
				"Phase 0",
				"no artifact returned",
			},
		},
		{
			name: "server message is rendered",
			resp: &RunAgentSkillResponse{
				RunID:   "run-123",
				Message: "run enrolled; poll its status for progress",
			},
			want: []string{"run-123", "run enrolled; poll its status for progress"},
		},
		{
			name: "synchronous artifact with run id",
			resp: &RunAgentSkillResponse{RunID: "run-9", ArtifactJSON: `{"ok":true}`},
			want: []string{"run-9", `Artifact:  {"ok":true}`},
			notWant: []string{
				"no artifact returned",
			},
		},
		{
			name:    "nothing returned: say so plainly",
			resp:    &RunAgentSkillResponse{},
			want:    []string{"no artifact returned"},
			notWant: []string{"Phase 0", "Run:", "crew_logs"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := handleRunAgentSkill(&runSkillOnlyAPI{resp: tt.resp}, map[string]interface{}{"skill_id": "hello-agent"})
			if err != nil {
				t.Fatalf("handleRunAgentSkill: %v", err)
			}
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

// TestRunAgentSkillResponse_DecodesRunIDAndMessage checks the wire JSON's
// runId and message fields reach the typed response.
func TestRunAgentSkillResponse_DecodesRunIDAndMessage(t *testing.T) {
	var resp RunAgentSkillResponse
	if err := json.Unmarshal([]byte(`{"runId":"run-1","message":"run enrolled"}`), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RunID != "run-1" || resp.Message != "run enrolled" {
		t.Errorf("decoded %+v, want runId=run-1 message=%q", resp, "run enrolled")
	}
}
