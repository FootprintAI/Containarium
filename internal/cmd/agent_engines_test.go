package cmd

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func fixtureEnginesResponse() *pb.ListAgentEnginesResponse {
	return &pb.ListAgentEnginesResponse{
		KeyOwner: "user:alice",
		Engines: []*pb.AgentEngineStatus{
			{
				Engine: pb.AgentEngine_AGENT_ENGINE_CLAUDE, Provider: pb.GatewayProvider_GATEWAY_PROVIDER_ANTHROPIC,
				Readiness: pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_READY,
				Source:    pb.AgentCredentialSource_AGENT_CREDENTIAL_SOURCE_GLOBAL_KEY,
				IsDefault: true, SkillIds: []string{"hello-agent"},
			},
			{
				Engine: pb.AgentEngine_AGENT_ENGINE_CODEX, Provider: pb.GatewayProvider_GATEWAY_PROVIDER_OPENAI,
				Readiness: pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_NOT_READY,
				Reason:    "no key for provider openai; fix: containarium gateway key set user:alice --provider openai --key <value>",
			},
			{
				Engine: pb.AgentEngine_AGENT_ENGINE_GEMINI, Provider: pb.GatewayProvider_GATEWAY_PROVIDER_GEMINI,
				Readiness: pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_UNKNOWN_DIRECT_MODE,
				Source:    pb.AgentCredentialSource_AGENT_CREDENTIAL_SOURCE_DIRECT_MODE,
				Reason:    "daemon serves no model gateway; the box's own secrets decide",
			},
		},
	}
}

// TestRenderAgentEngines_Table pins the CLI's human-readable table. Per the
// issue, the reason text must be printed byte-for-byte what the daemon sent —
// never re-worded here, since `agent engines` and a RunAgentSkill refusal
// must say the same thing for the same cause (#2222/#2223).
func TestRenderAgentEngines_Table(t *testing.T) {
	var buf bytes.Buffer
	if err := renderAgentEngines(&buf, fixtureEnginesResponse(), false); err != nil {
		t.Fatalf("renderAgentEngines: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"claude", "anthropic", "READY", "GLOBAL_KEY", "true", "hello-agent",
		"codex", "openai", "NOT_READY", "no key for provider openai",
		"gemini", "UNKNOWN_DIRECT_MODE", "daemon serves no model gateway",
		"user:alice",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q\n---\n%s", want, out)
		}
	}
}

// TestRenderAgentEngines_JSON pins --json: it must be the protojson encoding
// of the actual response, not a hand-built summary — so a reader scripting
// against it gets the same enum names the wire contract defines.
func TestRenderAgentEngines_JSON(t *testing.T) {
	var buf bytes.Buffer
	if err := renderAgentEngines(&buf, fixtureEnginesResponse(), true); err != nil {
		t.Fatalf("renderAgentEngines: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`"AGENT_ENGINE_CODEX"`, `"AGENT_ENGINE_READINESS_NOT_READY"`, `"keyOwner"`, `"user:alice"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("json output missing %q\n---\n%s", want, out)
		}
	}
}
