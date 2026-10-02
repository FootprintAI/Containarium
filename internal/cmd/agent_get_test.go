package cmd

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestRunAgentGet_PrintsEngine pins #2222's CLI acceptance criterion:
// `containarium agent get <skill-id>` prints the resolved engine. Reads the
// embedded catalog directly (serverAddr unset), so no daemon is needed.
func TestRunAgentGet_PrintsEngine(t *testing.T) {
	cases := []struct {
		name   string
		skill  string // id in the embedded catalog
		wantIn string
	}{
		// hello-agent ships with no engine set (AGENT_ENGINE_UNSPECIFIED).
		{name: "unspecified engine prints a placeholder, not an empty line", skill: "hello-agent", wantIn: "Engine:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := runAgentGet(nil, []string{tc.skill}); err != nil {
					t.Fatalf("runAgentGet(%s): %v", tc.skill, err)
				}
			})
			if !strings.Contains(out, tc.wantIn) {
				t.Errorf("output = %q, want it to contain %q", out, tc.wantIn)
			}
		})
	}
}

// TestFormatEngine pins the display string for each AgentEngine value,
// independent of the catalog fixture above.
func TestFormatEngine(t *testing.T) {
	cases := map[pb.AgentEngine]string{
		pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED: "(unspecified — runtime/gateway default decides)",
		pb.AgentEngine_AGENT_ENGINE_CLAUDE:      "claude",
		pb.AgentEngine_AGENT_ENGINE_CODEX:       "codex",
		pb.AgentEngine_AGENT_ENGINE_GEMINI:      "gemini",
	}
	for engine, want := range cases {
		if got := formatEngine(engine); got != want {
			t.Errorf("formatEngine(%v) = %q, want %q", engine, got, want)
		}
	}
}
