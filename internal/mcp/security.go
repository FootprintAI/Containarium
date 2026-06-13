package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Security tool kinds — match the daemon's three scanner subsystems.
// Used as the `kind` enum on security_scan and as the source label on
// each row returned by security_findings.
const (
	scanKindClamav  = "clamav"
	scanKindPentest = "pentest"
	scanKindZap     = "zap"
	scanKindAll     = "all"
)

// SecurityFinding is the normalized cross-scanner shape returned by
// security_findings. The daemon emits three scanner-specific shapes
// (ClamavReport, PentestFinding, ZapAlert); we map all three onto one
// type so agents can reason about "what's wrong" without branching on
// scanner. The `kind` field is the only thing that varies, plus
// `fix_available` which lets the agent know whether security_remediate
// can act on this row.
type SecurityFinding struct {
	Kind          string `json:"kind"`     // "clamav" | "pentest" | "zap"
	ID            int64  `json:"id"`       // daemon-side row ID; pass to security_remediate
	Severity      string `json:"severity"` // normalized to {"critical","high","medium","low","info"}
	Title         string `json:"title"`
	Description   string `json:"description,omitempty"`
	ContainerName string `json:"containerName,omitempty"`
	Target        string `json:"target,omitempty"` // pentest/ZAP-side target (URL, IP:port)
	FixAvailable  bool   `json:"fixAvailable"`     // true ↔ security_remediate can act
}

// SecurityScanResponse is what security_scan returns to the agent.
type SecurityScanResponse struct {
	Kind     string `json:"kind"`     // echoed request kind
	Message  string `json:"message"`  // human-readable summary across the scanners that ran
	Queued   int    `json:"queued"`   // total scan jobs queued (across scanners if kind=all)
	PollHint string `json:"pollHint"` // advisory for the agent on when to call security_findings next
}

// SecurityRemediateResponse mirrors the daemon's
// RemediatePentestFindingResponse but is exposed as a stable MCP shape.
type SecurityRemediateResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	PackageName string `json:"packageName,omitempty"`
	OldVersion  string `json:"oldVersion,omitempty"`
	NewVersion  string `json:"newVersion,omitempty"`
}

// --- MCP handlers ----------------------------------------------------------

// handleSecurityScan triggers one or more scanners against a container.
// The work is asynchronous on the daemon side; this call returns once
// the daemon has accepted the trigger(s). Agents should call
// security_findings after a reasonable delay (scan durations vary —
// ClamAV is fast, pentest tens of seconds, ZAP minutes).
func handleSecurityScan(client API, args map[string]interface{}) (string, error) {
	username := getStringArg(args, "username", "")
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	kind := strings.ToLower(getStringArg(args, "kind", scanKindAll))
	switch kind {
	case scanKindClamav, scanKindPentest, scanKindZap, scanKindAll:
	default:
		return "", fmt.Errorf("kind must be one of: clamav, pentest, zap, all (got %q)", kind)
	}

	containerName := username + "-container"
	resp, err := client.TriggerSecurityScan(kind, containerName, username)
	if err != nil {
		return "", fmt.Errorf("trigger scan: %w", err)
	}
	out, _ := json.MarshalIndent(resp, "", "  ")
	return string(out), nil
}

// handleSecurityFindings returns the normalized list of findings across
// scanner kinds. By default it fetches findings for the username's
// container; pass kind="all" (default) or restrict to one scanner.
func handleSecurityFindings(client API, args map[string]interface{}) (string, error) {
	username := getStringArg(args, "username", "")
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	kind := strings.ToLower(getStringArg(args, "kind", scanKindAll))
	switch kind {
	case scanKindClamav, scanKindPentest, scanKindZap, scanKindAll:
	default:
		return "", fmt.Errorf("kind must be one of: clamav, pentest, zap, all (got %q)", kind)
	}

	containerName := username + "-container"
	findings, err := client.ListSecurityFindings(kind, containerName)
	if err != nil {
		return "", fmt.Errorf("list findings: %w", err)
	}

	// Wrap in a stable envelope so the agent can read counts without
	// summing the array.
	envelope := map[string]interface{}{
		"kind":       kind,
		"container":  containerName,
		"totalCount": len(findings),
		"findings":   findings,
	}
	out, _ := json.MarshalIndent(envelope, "", "  ")
	return string(out), nil
}

// handleSecurityRemediate calls the daemon's RemediatePentestFinding
// RPC. Today only pentest findings are auto-fixable (the daemon
// upgrades the affected package). ClamAV/ZAP findings have
// `fix_available=false` and will return an error here.
//
// IMPORTANT: this is a one-shot operator-invoked action. The MCP
// description doesn't tell the agent to chain scan→pick→remediate
// autonomously. Continuous/hosted remediation is a paywalled cloud
// feature; see Containarium-cloud's prd/cloud/security-patch-agent.md.
func handleSecurityRemediate(client API, args map[string]interface{}) (string, error) {
	fid, ok := getInt64Arg(args, "finding_id")
	if !ok {
		return "", fmt.Errorf("finding_id is required")
	}
	resp, err := client.RemediateSecurityFinding(fid)
	if err != nil {
		return "", fmt.Errorf("remediate: %w", err)
	}
	out, _ := json.MarshalIndent(resp, "", "  ")
	return string(out), nil
}

// getInt64Arg is the int sibling of getStringArg. JSON numbers decode
// to float64 in map[string]interface{}, so we accept either int64,
// float64, or a string parse.
func getInt64Arg(args map[string]interface{}, key string) (int64, bool) {
	v, ok := args[key]
	if !ok {
		return 0, false
	}
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case float64:
		return int64(x), true
	case string:
		var n int64
		_, err := fmt.Sscanf(x, "%d", &n)
		return n, err == nil
	}
	return 0, false
}
