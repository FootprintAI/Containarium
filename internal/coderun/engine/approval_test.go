package engine

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
)

func TestWithApprovalsWiresClaudePromptTool(t *testing.T) {
	eng, err := For(NameClaude, Options{Credential: SecretCredential{}})
	if err != nil {
		t.Fatal(err)
	}
	base := eng.RunCommand("do it", false, false, "")
	got, ok := WithApprovals(eng, base, "my-run", 30*time.Minute)
	if !ok {
		t.Fatal("WithApprovals reported Claude has no hook")
	}
	if !strings.Contains(got, base) {
		t.Errorf("the base command is not carried through unchanged:\n%s", got)
	}
	for _, want := range []string{
		"--permission-prompt-tool mcp__containarium-approval__approve",
		"CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT=2100000; export CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT; ",
		`trap 'rm -f '\''/tmp/agent-box/my-run.approval-key'\''' EXIT; `,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("command lacks %q:\n%s", want, got)
		}
	}

	// The inline --mcp-config is valid JSON that starts this run's approval
	// server with the run name quoted for the shell.
	i := strings.Index(got, " --mcp-config '")
	j := strings.LastIndex(got, "' --permission-prompt-tool")
	if i < 0 || j < i {
		t.Fatalf("no trailing inline --mcp-config in:\n%s", got)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	// Undo shellQuoteSingle: an embedded ' was rendered as '\''.
	inline := strings.ReplaceAll(got[i+len(" --mcp-config '"):j], `'\''`, `'`)
	if err := json.Unmarshal([]byte(inline), &cfg); err != nil {
		t.Fatalf("inline --mcp-config is not JSON: %v", err)
	}
	srv, ok := cfg.MCPServers[approvalServerName]
	if !ok || srv.Command != "sh" || len(srv.Args) != 2 || srv.Args[0] != "-c" {
		t.Fatalf("approval server entry = %+v", cfg)
	}
	if want := coderun.AgentBoxPathPrefix + " exec agent-box approval-mcp --run 'my-run' --timeout 30m0s"; srv.Args[1] != want {
		t.Errorf("approval server script = %q, want %q", srv.Args[1], want)
	}
}

func TestWithApprovalsLeavesHooklessEnginesUnchanged(t *testing.T) {
	for _, n := range []Name{NamePi, NameCodex} {
		eng, err := For(n, Options{Credential: SecretCredential{}})
		if err != nil {
			t.Fatal(err)
		}
		base := eng.RunCommand("p", false, false, "")
		got, ok := WithApprovals(eng, base, "code", time.Minute)
		if ok || got != base {
			t.Errorf("%s: WithApprovals = (%q, %v), want the command unchanged and false", n, got, ok)
		}
	}
}
