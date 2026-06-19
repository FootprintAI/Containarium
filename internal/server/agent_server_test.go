package server

import (
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestBuildAgentSeedScript(t *testing.T) {
	script := buildAgentSeedScript("be helpful", "tok-123", `{"q":"hi"}`, `{"id":"x"}`)

	for _, want := range []string{
		"set -euo pipefail",
		"umask 077",
		"mkdir -p " + agentSeedDir,
		agentSeedDir + "/system_prompt.txt",
		agentSeedDir + "/token",
		agentSeedDir + "/input.json",
		agentSeedDir + "/agent-card.json",
		"chmod 600 " + agentSeedDir + "/token",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("seed script missing %q\n---\n%s", want, script)
		}
	}
}

func TestBuildAgentSeedScriptDefaultsInput(t *testing.T) {
	script := buildAgentSeedScript("p", "t", "", "")
	if !strings.Contains(script, "'{}'") {
		t.Errorf("empty input should default to {}, got:\n%s", script)
	}
}

// TestSendAgentTaskRejectsDisallowedPeer is the moat as a test: an agent whose
// allowed_peers does not include the target is rejected at the API boundary,
// BEFORE any A2A send is attempted. The caller identity is taken from the
// authenticated token subject (agent-<skill-id>), not the caller-asserted
// field, so an agent box can't spoof a different caller to bypass the gate.
func TestSendAgentTaskRejectsDisallowedPeer(t *testing.T) {
	// hello-agent ships with allowed_peers: [] (a leaf), so every peer is denied.
	s := &AgentSkillServer{catalog: skills.GetDefault()}

	// Authenticate as the agent box itself; agents:call scope present.
	ctx := auth.ContextWithTestSubjectScopes(
		context.Background(), "agent-hello-agent", nil, []string{auth.ScopeAgentsCall})

	// from_skill_id deliberately lies ("admin-ish") — the authenticated subject
	// must win, so the call is still denied.
	_, err := s.SendAgentTask(ctx, &pb.SendAgentTaskRequest{
		FromSkillId: "some-privileged-skill",
		ToPeerId:    "other-peer",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for a peer not in allowed_peers, got %v", err)
	}
}

// TestSendAgentTaskRequiresCallScope confirms the agents:call gate.
func TestSendAgentTaskRequiresCallScope(t *testing.T) {
	s := &AgentSkillServer{catalog: skills.GetDefault()}
	// Authenticated, but without agents:call.
	ctx := auth.ContextWithTestSubjectScopes(
		context.Background(), "agent-hello-agent", nil, []string{auth.ScopeAgentsRead})
	_, err := s.SendAgentTask(ctx, &pb.SendAgentTaskRequest{ToPeerId: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied without agents:call, got %v", err)
	}
}

func TestAgentNetworkPolicyConfigDomains(t *testing.T) {
	t.Run("defaults to the model providers when unset", func(t *testing.T) {
		_ = os.Unsetenv("CONTAINARIUM_AGENT_EGRESS_DOMAINS")
		_, domains, _ := agentNetworkPolicyConfig()
		// The provider defaults: Anthropic, OpenAI, and Gemini (the Gemini engine
		// added generativelanguage.googleapis.com so an ENFORCE policy doesn't
		// strand a Gemini agent). Assert against the source-of-truth slice.
		if len(domains) != len(defaultAgentEgressDomains) || domains[0] != "api.anthropic.com" {
			t.Errorf("default domains = %v, want %v", domains, defaultAgentEgressDomains)
		}
	})
	t.Run("operator override wins", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_AGENT_EGRESS_DOMAINS", "api.example.com, llm.internal")
		_, domains, _ := agentNetworkPolicyConfig()
		if len(domains) != 2 || domains[0] != "api.example.com" || domains[1] != "llm.internal" {
			t.Errorf("override domains = %v", domains)
		}
	})
}

func TestCompileAllowedPeersPolicySetsDomains(t *testing.T) {
	p := compileAllowedPeersPolicy("agent-x", []string{"peer-a"},
		func(string) (string, bool) { return "10.0.0.5", true },
		nil, []string{"api.anthropic.com"}, true)
	if len(p.EgressDomains) != 1 || p.EgressDomains[0] != "api.anthropic.com" {
		t.Errorf("egress_domains = %v, want [api.anthropic.com]", p.EgressDomains)
	}
}

func TestParseArtifactOutput(t *testing.T) {
	t.Run("output", func(t *testing.T) {
		out, err := parseArtifactOutput([]byte(`{"outputJson":"{\"ok\":true}","engine":"claude","model":"claude-opus-4-8"}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != `{"ok":true}` {
			t.Errorf("output = %q", out)
		}
	})
	t.Run("error field surfaces", func(t *testing.T) {
		_, err := parseArtifactOutput([]byte(`{"outputJson":"","error":"model egress blocked"}`))
		if err == nil || !strings.Contains(err.Error(), "egress") {
			t.Errorf("expected the artifact error to surface, got %v", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		if _, err := parseArtifactOutput([]byte("not json")); err == nil {
			t.Error("expected decode error for malformed artifact")
		}
	})
}

func TestAgentRuntimeReleaseTag(t *testing.T) {
	// version.GetVersion() is the bare semver at runtime (the release workflow
	// builds with VERSION=${tag#v}); the recipe needs the v-prefixed git tag or
	// the artifact URLs 404 and box assembly silently skips. The helper must
	// re-add the prefix without double-prefixing an already-tagged value.
	got := agentRuntimeReleaseTag()
	if !strings.HasPrefix(got, "v") {
		t.Errorf("agentRuntimeReleaseTag() = %q, want a v-prefixed tag", got)
	}
	if strings.HasPrefix(got, "vv") {
		t.Errorf("agentRuntimeReleaseTag() = %q, double-prefixed", got)
	}
}

func TestGenTraceID(t *testing.T) {
	a, b := genTraceID(), genTraceID()
	if len(a) != 32 { // 16 bytes hex
		t.Errorf("trace id len = %d, want 32", len(a))
	}
	if a == "" || a == b {
		t.Errorf("trace ids should be non-empty and unique: %q %q", a, b)
	}
}

func TestAuditHopNilStoreNoPanic(t *testing.T) {
	// With no audit store wired, auditHop must be a safe no-op.
	s := &AgentSkillServer{}
	s.auditHop(context.Background(), "trace", "from", "to", "delivered", "")
}

func TestBuildAgentSeedScriptEscapesSingleQuotes(t *testing.T) {
	// A system prompt containing a single quote must be escaped so it can't
	// break out of the shell-quoted printf argument.
	script := buildAgentSeedScript("don't panic", "t", "{}", "{}")
	if strings.Contains(script, "don't") && !strings.Contains(script, `don'\''t`) {
		t.Errorf("single quote not escaped in seed script:\n%s", script)
	}
}

func TestCompileAllowedPeersPolicy(t *testing.T) {
	running := map[string]string{"peer-a": "10.0.0.5", "peer-b": "10.0.0.6"}
	resolve := func(id string) (string, bool) { ip, ok := running[id]; return ip, ok }

	// peer-c is not running, so it must be omitted from the allowlist.
	p := compileAllowedPeersPolicy("agent-caller", []string{"peer-a", "peer-b", "peer-c"}, resolve, nil, nil, false)

	if p.Tenant != "agent-caller" {
		t.Errorf("tenant = %q, want agent-caller", p.Tenant)
	}
	if p.Mode != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY {
		t.Errorf("mode = %v, want LOG_ONLY (observe-only until enforcement is armed)", p.Mode)
	}
	if p.AllowMetadata {
		t.Error("allow_metadata must be false for an agent box")
	}
	if p.AllowIntraTenant {
		t.Error("allow_intra_tenant must be false (deny-by-default)")
	}
	want := []string{"10.0.0.5/32", "10.0.0.6/32"}
	if len(p.EgressCidrs) != len(want) {
		t.Fatalf("egress_cidrs = %v, want %v", p.EgressCidrs, want)
	}
	for i := range want {
		if p.EgressCidrs[i] != want[i] {
			t.Errorf("egress_cidrs[%d] = %q, want %q", i, p.EgressCidrs[i], want[i])
		}
	}
}

func TestCompileAllowedPeersPolicyNoneRunning(t *testing.T) {
	// No peer is running -> empty allowlist (the caller skips installing it
	// rather than denying all egress under a future ENFORCE).
	p := compileAllowedPeersPolicy("t", []string{"x", "y"}, func(string) (string, bool) { return "", false }, nil, nil, false)
	if len(p.EgressCidrs) != 0 {
		t.Errorf("expected no egress cidrs when no peers run, got %v", p.EgressCidrs)
	}
}

func TestCompileAllowedPeersPolicyEnforceAndExtraCIDRs(t *testing.T) {
	resolve := func(id string) (string, bool) {
		if id == "peer-a" {
			return "10.0.0.5", true
		}
		return "", false
	}
	// Armed ENFORCE + platform egress (e.g. daemon + DNS) so the agent isn't
	// stranded by a peer-only allowlist.
	extra := []string{"10.0.1.1/32", "10.0.1.2/32"}
	p := compileAllowedPeersPolicy("agent-x", []string{"peer-a"}, resolve, extra, nil, true)

	if p.Mode != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE {
		t.Errorf("mode = %v, want ENFORCE when armed", p.Mode)
	}
	want := []string{"10.0.0.5/32", "10.0.1.1/32", "10.0.1.2/32"}
	if len(p.EgressCidrs) != len(want) {
		t.Fatalf("egress_cidrs = %v, want %v", p.EgressCidrs, want)
	}
	for i := range want {
		if p.EgressCidrs[i] != want[i] {
			t.Errorf("egress_cidrs[%d] = %q, want %q", i, p.EgressCidrs[i], want[i])
		}
	}
}

func TestPeerAllowed(t *testing.T) {
	s := &AgentSkillServer{catalog: skills.GetDefault()}

	// hello-agent ships with allowed_peers: [] (leaf) — so any peer is denied.
	if s.peerAllowed("hello-agent", "some-peer") {
		t.Error("hello-agent has no allowed_peers; call should be denied")
	}
	// Empty caller (admin/operator direct call) is allowed — eBPF is the
	// boundary for box-originated traffic.
	if !s.peerAllowed("", "some-peer") {
		t.Error("empty caller should be allowed (not gated at this layer)")
	}
	// Unknown caller skill is allowed (not ours to gate here).
	if !s.peerAllowed("does-not-exist", "some-peer") {
		t.Error("unknown caller skill should not be gated here")
	}
}
