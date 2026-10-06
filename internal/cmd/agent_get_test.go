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

// TestFormatModel pins #2229's display rule: whether a pinned model is
// actually honored is decided entirely by the manifest's own Engine field
// (#2222) — a bare model string would read as "this is used" even for an
// unspecified-engine skill, where it never is.
func TestFormatModel(t *testing.T) {
	cases := []struct {
		name   string
		skill  *pb.AgentSkill
		wantIn string
	}{
		{
			name:   "no model pinned",
			skill:  &pb.AgentSkill{},
			wantIn: "(none — engine's own default)",
		},
		{
			name:   "model pinned, no engine named: not enforced",
			skill:  &pb.AgentSkill{Model: "claude-opus-4-8"},
			wantIn: "claude-opus-4-8 (not enforced",
		},
		{
			name:   "model pinned, engine named: honored",
			skill:  &pb.AgentSkill{Model: "gpt-5-codex", Engine: pb.AgentEngine_AGENT_ENGINE_CODEX},
			wantIn: "gpt-5-codex (honored",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatModel(tc.skill); !strings.Contains(got, tc.wantIn) {
				t.Errorf("formatModel(%+v) = %q, want it to contain %q", tc.skill, got, tc.wantIn)
			}
		})
	}
}
