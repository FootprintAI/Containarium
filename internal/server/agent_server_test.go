package server

import (
	"strings"
	"testing"

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
	p := compileAllowedPeersPolicy("agent-caller", []string{"peer-a", "peer-b", "peer-c"}, resolve)

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
	p := compileAllowedPeersPolicy("t", []string{"x", "y"}, func(string) (string, bool) { return "", false })
	if len(p.EgressCidrs) != 0 {
		t.Errorf("expected no egress cidrs when no peers run, got %v", p.EgressCidrs)
	}
}
