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

// InstallZapResponse mirrors the daemon's InstallZapResponse.
type InstallZapResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// SentryRuleStatus is one registered detection rule's health.
type SentryRuleStatus struct {
	Rule        string `json:"rule"`
	Healthy     bool   `json:"healthy"`
	LastError   string `json:"lastError,omitempty"`
	LastErrorAt string `json:"lastErrorAt,omitempty"`
}

// SentryStatusResponse mirrors the daemon's GetSentryStatusResponse
// (#1640): the background threat-detection engine's on/off state — one of
// DISABLED, UNAVAILABLE, DEGRADED, OK (SentryState enum names, unprefixed)
// — and every registered rule's health.
type SentryStatusResponse struct {
	State  string             `json:"state"`
	Reason string             `json:"reason,omitempty"`
	Rules  []SentryRuleStatus `json:"rules,omitempty"`
}

// BadDestinationEntry is one entry in the known-bad-destination list
// (#1641), mirroring the daemon's BadDestinationEntry.
type BadDestinationEntry struct {
	CIDR   string `json:"cidr"`
	Label  string `json:"label,omitempty"`
	Source string `json:"source"`
}

// ListBadDestinationsResponse mirrors the daemon's
// ListBadDestinationsResponse.
type ListBadDestinationsResponse struct {
	Entries []BadDestinationEntry `json:"entries"`
}

// AddBadDestinationResponse mirrors the daemon's AddBadDestinationResponse.
type AddBadDestinationResponse struct {
	Entry BadDestinationEntry `json:"entry"`
}

// FlowEvidence mirrors the daemon's FlowEvidence (#1639): one triggering
// flow's 5-tuple and volume.
// Bytes/Packets are string, not int64 — see SentryFinding's doc comment on
// why (protojson int64 encoding).
type FlowEvidence struct {
	SrcIP    string `json:"srcIp"`
	DstIP    string `json:"dstIp"`
	SrcPort  uint32 `json:"srcPort"`
	DstPort  uint32 `json:"dstPort"`
	Protocol string `json:"protocol"`
	Bytes    string `json:"bytes"`
	Packets  string `json:"packets"`
}

// DenyEvidence mirrors the daemon's DenyEvidence (#1639): an aggregated
// count of policy-deny events matching a destination/reason pair. Count is
// string, not int64 — see SentryFinding's doc comment.
type DenyEvidence struct {
	DstIP    string `json:"dstIp"`
	DstPort  uint32 `json:"dstPort"`
	Protocol string `json:"protocol"`
	Reason   string `json:"reason"`
	Count    string `json:"count"`
}

// SentryEvidence mirrors the daemon's Evidence message — the wire shape
// nested under Finding.evidence, not flattened onto SentryFinding.
type SentryEvidence struct {
	Flows  []FlowEvidence `json:"flows,omitempty"`
	Denies []DenyEvidence `json:"denies,omitempty"`
}

// SentryFinding mirrors the daemon's Finding (#1639/#1643): a single
// security finding raised by the threat-detection sentry. Named
// SentryFinding, not Finding, to keep it unambiguous next to
// SecurityFinding (the unrelated scanner-findings shape above).
//
// ID and Count are string, not int64: protojson serializes proto3 int64
// fields as JSON strings (to survive JS's float64 precision limit), and
// encoding/json refuses to unmarshal a JSON string into an int64 field.
type SentryFinding struct {
	ID        string         `json:"id"`
	Rule      string         `json:"rule"`
	Severity  string         `json:"severity"`
	TenantID  string         `json:"tenantId"`
	Container string         `json:"container,omitempty"`
	BackendID string         `json:"backendId,omitempty"`
	Subject   string         `json:"subject,omitempty"`
	State     string         `json:"state"`
	Count     string         `json:"count"`
	Evidence  SentryEvidence `json:"evidence"`
	FirstSeen string         `json:"firstSeen,omitempty"`
	LastSeen  string         `json:"lastSeen,omitempty"`
}

// ListSentryFindingsResponse mirrors the daemon's ListFindingsResponse.
type ListSentryFindingsResponse struct {
	Findings []SentryFinding `json:"findings"`
}

// ResolveSentryFindingResponse mirrors the daemon's ResolveFindingResponse.
type ResolveSentryFindingResponse struct {
	Finding SentryFinding `json:"finding"`
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

// handleSecuritySentryStatus reports the background threat-detection
// engine's on/off state and per-rule health. Takes no arguments — like
// GetClamavSummary/GetScanStatus, this is a fleet-position read, not
// scoped to a container.
func handleSecuritySentryStatus(client API, args map[string]interface{}) (string, error) {
	resp, err := client.GetSentryStatus()
	if err != nil {
		return "", fmt.Errorf("get sentry status: %w", err)
	}
	// Strip the enum's repeated prefix so the agent sees "OK"/"DISABLED"/...
	// rather than "SENTRY_STATE_OK" — same normalization the CLI applies.
	resp.State = strings.TrimPrefix(resp.State, "SENTRY_STATE_")
	for i := range resp.Rules {
		resp.Rules[i].Rule = strings.TrimPrefix(resp.Rules[i].Rule, "THREAT_RULE_ID_")
	}
	out, _ := json.MarshalIndent(resp, "", "  ")
	return string(out), nil
}

// handleListBadDestinations lists the merged baseline + operator-added
// known-bad-destination list the bad-destination rule (#1641) matches flow
// destinations against. Takes no arguments.
func handleListBadDestinations(client API, args map[string]interface{}) (string, error) {
	resp, err := client.ListBadDestinations()
	if err != nil {
		return "", fmt.Errorf("list bad destinations: %w", err)
	}
	out, _ := json.MarshalIndent(resp, "", "  ")
	return string(out), nil
}

// handleAddBadDestination adds an operator-supplied entry to the
// known-bad-destination list, effective immediately — no daemon rebuild or
// restart required.
func handleAddBadDestination(client API, args map[string]interface{}) (string, error) {
	cidr := getStringArg(args, "cidr", "")
	if cidr == "" {
		return "", fmt.Errorf("cidr is required")
	}
	label := getStringArg(args, "label", "")
	entry, err := client.AddBadDestination(cidr, label)
	if err != nil {
		return "", fmt.Errorf("add bad destination: %w", err)
	}
	out, _ := json.MarshalIndent(entry, "", "  ")
	return string(out), nil
}

// handleRemoveBadDestination removes a previously operator-added entry.
// Baseline entries cannot be removed this way.
func handleRemoveBadDestination(client API, args map[string]interface{}) (string, error) {
	cidr := getStringArg(args, "cidr", "")
	if cidr == "" {
		return "", fmt.Errorf("cidr is required")
	}
	if err := client.RemoveBadDestination(cidr); err != nil {
		return "", fmt.Errorf("remove bad destination: %w", err)
	}
	return fmt.Sprintf("Removed %s from the known-bad-destination list.", cidr), nil
}

// handleListSecuritySentryFindings lists findings raised by the background
// threat-detection sentry (#1639-#1643), most recently seen first. Named
// distinctly from security_findings (the unrelated scanner-findings tool
// above) — same naming collision the CLI has between `security findings`
// (this) and `security-findings <username>` (scanner findings).
func handleListSecuritySentryFindings(client API, args map[string]interface{}) (string, error) {
	severity := getStringArg(args, "severity", "")
	tenant := getStringArg(args, "tenant", "")
	since := getStringArg(args, "since", "")
	state := getStringArg(args, "state", "")
	limit := 0
	if v, ok := getInt64Arg(args, "limit"); ok {
		limit = int(v)
	}

	resp, err := client.ListSecuritySentryFindings(severity, tenant, since, state, limit)
	if err != nil {
		return "", fmt.Errorf("list sentry findings: %w", err)
	}
	// Strip the enums' repeated prefixes, same normalization
	// handleSecuritySentryStatus applies.
	for i := range resp.Findings {
		f := &resp.Findings[i]
		f.Rule = strings.TrimPrefix(f.Rule, "THREAT_RULE_ID_")
		f.Severity = strings.TrimPrefix(f.Severity, "THREAT_SEVERITY_")
		f.State = strings.TrimPrefix(f.State, "FINDING_STATE_")
	}
	out, _ := json.MarshalIndent(resp, "", "  ")
	return string(out), nil
}

// handleResolveSecuritySentryFinding marks an open sentry finding as
// resolved.
func handleResolveSecuritySentryFinding(client API, args map[string]interface{}) (string, error) {
	id, ok := getInt64Arg(args, "id")
	if !ok {
		return "", fmt.Errorf("id is required")
	}
	resp, err := client.ResolveSecuritySentryFinding(id)
	if err != nil {
		return "", fmt.Errorf("resolve sentry finding: %w", err)
	}
	resp.Finding.State = strings.TrimPrefix(resp.Finding.State, "FINDING_STATE_")
	out, _ := json.MarshalIndent(resp, "", "  ")
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

// handleInstallZap downloads and installs OWASP ZAP into this host's
// security container. Admin-only operator action — see #960: without
// this having been run at least once, every ZAP scan job on the host
// fails fast with a clear "not installed" error (rather than the old
// behavior of silently retrying forever with a generic 120s timeout).
func handleInstallZap(client API, _ map[string]interface{}) (string, error) {
	resp, err := client.InstallZap()
	if err != nil {
		return "", fmt.Errorf("install zap: %w", err)
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
