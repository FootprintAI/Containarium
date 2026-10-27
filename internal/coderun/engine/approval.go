package engine

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
)

// Permission approvals (#2183): how an engine's run command hands permission
// prompts to `agent-box approval-mcp`.

// approvalServerName and approvalToolName mirror agentbox.ApprovalServerName /
// ApprovalToolName, which this package cannot import (agentbox is not built for
// Windows, and the client is); a test pins the two equal.
const (
	approvalServerName = "containarium-approval"
	approvalToolName   = "approve"
)

// approvalIdleMargin keeps Claude Code's MCP idle timer longer than a request
// can wait, on top of the progress notifications the server sends.
const approvalIdleMargin = 5 * time.Minute

// SupportsApprovals reports whether n has a permission hook `--approvals ask`
// can wire. Claude Code does (--permission-prompt-tool). pi exposes no
// permission gate to intercept, and Codex's is not mapped yet (PRD later phase).
func SupportsApprovals(n Name) bool { return n == NameClaude }

// WithApprovals returns cmd — a RunCommand result for eng — rewired so the run
// pauses on permission prompts for this run name, each expiring after timeout,
// and accepting only answers signed for pub.
// ok is false when eng has no hook; cmd is then returned unchanged.
//
// The env prefix and trailing flags wrap the command rather than editing it, so
// the --approvals deny command stays byte-identical to the shipped one.
func WithApprovals(eng Engine, cmd, runName string, pub ed25519.PublicKey, timeout time.Duration) (string, bool) {
	if eng == nil || !SupportsApprovals(eng.Name()) {
		return cmd, false
	}
	idle := strconv.FormatInt((timeout + approvalIdleMargin).Milliseconds(), 10)
	prefix := "CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT=" + idle + "; export CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT; "
	return prefix + cmd +
		" --mcp-config " + shellQuoteSingle(approvalMCPConfig(runName, pub, timeout)) +
		" --permission-prompt-tool " + ApprovalPromptTool, true
}

// ApprovalPromptTool is the --permission-prompt-tool value.
const ApprovalPromptTool = "mcp__" + approvalServerName + "__" + approvalToolName

// approvalMCPConfig is the inline --mcp-config JSON that starts the approval
// server. agent-box is found on the same PATH `code` sessions use to reach it.
// The public key is not a secret; it is on the command line so that nothing on
// the box can swap it after the run starts.
func approvalMCPConfig(runName string, pub ed25519.PublicKey, timeout time.Duration) string {
	script := coderun.AgentBoxPathPrefix + " exec agent-box approval-mcp --run " +
		shellQuoteSingle(runName) + " --public-key " + hex.EncodeToString(pub) + " --timeout " + timeout.String()
	type stdioServer struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	cfg := struct {
		MCPServers map[string]stdioServer `json:"mcpServers"`
	}{MCPServers: map[string]stdioServer{
		approvalServerName: {Command: "sh", Args: []string{"-c", script}},
	}}
	b, _ := json.Marshal(cfg)
	return string(b)
}

// ApprovalProbeCommand checks the box's agent-box has the approval mode, so an
// older box fails at start instead of denying every prompt silently. stdin is
// closed so an agent-box without the mode (which would start its MCP server)
// exits at once.
func ApprovalProbeCommand() string {
	return coderun.AgentBoxPathPrefix + " agent-box approval-mcp --probe </dev/null 2>/dev/null"
}

// ApprovalProbeOK is the line ApprovalProbeCommand prints on a box that has it.
// "v2" is the prompt-bound answer format (#2184); an older agent-box prints
// "approval-mcp ok" alone and must not match.
const ApprovalProbeOK = "approval-mcp ok v2"
