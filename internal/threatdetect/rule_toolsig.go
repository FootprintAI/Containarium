package threatdetect

import (
	"context"
	_ "embed" // the baseline list is embedded into the daemon binary
	"path"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// embeddedToolSigYAML is the baseline abuse-tool list (#3709): reverse-tunnel
// clients and known DDoS / stress tools, in the miner-signature list's format.
//
//go:embed rule_toolsig_list.yaml
var embeddedToolSigYAML []byte

// AbuseToolRule implements Rule and ExecConsumer for
// THREAT_RULE_ID_ABUSE_TOOL: an exec whose binary name, or the script an
// interpreter was asked to run, matches the abuse-tool baseline raises a MEDIUM
// finding with the exec attached. It reuses the miner-signature matcher but is deliberately a
// separate, record-only rule: it is not on the process responder's list
// (RespondsTo), so nothing is throttled, frozen or killed on it, and the
// baseline has no operator add/remove yet. A reverse-tunnel client has
// legitimate uses, so a hit is a prompt to look, not a verdict.
type AbuseToolRule struct {
	version string
	matcher *minerSigMatcher
}

// NewAbuseToolRule loads the embedded baseline.
func NewAbuseToolRule() (*AbuseToolRule, error) {
	return newAbuseToolRule(context.Background(), embeddedToolSigYAML)
}

func newAbuseToolRule(_ context.Context, baselineYAML []byte) (*AbuseToolRule, error) {
	version, entries, err := parseBaselineMinerSigYAML(baselineYAML)
	if err != nil {
		return nil, err
	}
	return &AbuseToolRule{version: version, matcher: newMinerSigMatcher(entries)}, nil
}

func (r *AbuseToolRule) ID() pb.ThreatRuleId { return pb.ThreatRuleId_THREAT_RULE_ID_ABUSE_TOOL }

// OnFlows, OnDeny and Sweep: this rule judges execs only.
func (r *AbuseToolRule) OnFlows(RuleContext, []netbpf.FlowRecord) []RawFinding { return nil }
func (r *AbuseToolRule) OnDeny(RuleContext, netbpf.DenyEvent) []RawFinding     { return nil }
func (r *AbuseToolRule) Sweep(RuleContext, time.Time) []RawFinding             { return nil }

// BaselineVersion is the version of the embedded list this build ships.
func (r *AbuseToolRule) BaselineVersion() string { return r.version }

// interpreterScript returns the script an interpreter exec was asked to run:
// the first non-option argument after argv[0] of a python, perl, ruby, node,
// php, bash or sh exec. It reports false for any other exec. An option that
// takes a value (python -m mod, -c code) is not special-cased: its value is then
// read as the script, which is a harmless miss, not a false match.
func interpreterScript(ev ExecEvent) (string, bool) {
	exe := strings.ToLower(path.Base(ev.Filename))
	switch {
	case strings.HasPrefix(exe, "python"), strings.HasPrefix(exe, "perl"), strings.HasPrefix(exe, "ruby"),
		strings.HasPrefix(exe, "php"), exe == "node", exe == "nodejs", exe == "bash", exe == "sh", exe == "dash":
	default:
		return "", false
	}
	for _, a := range ev.Argv[min(1, len(ev.Argv)):] {
		if a != "" && !strings.HasPrefix(a, "-") {
			return a, true
		}
	}
	return "", false
}

// match runs the name matcher on the exec itself and, for an interpreter, on
// the script it was asked to run. Only names are used: the list's argv entries
// are not consulted, and a bare argument that merely mentions a tool never
// matches.
func (r *AbuseToolRule) match(ev ExecEvent) (MinerSignatureEntry, bool) {
	if hit, ok := r.matcher.matchCheap(ExecEvent{Filename: ev.Filename, Comm: ev.Comm}); ok {
		return hit, true
	}
	if script, ok := interpreterScript(ev); ok {
		return r.matcher.matchCheap(ExecEvent{Filename: script})
	}
	return MinerSignatureEntry{}, false
}

// OnExec matches one exec. It never asks for the executable's hash: the
// baseline holds none.
func (r *AbuseToolRule) OnExec(_ RuleContext, ev ExecEvent) []RawFinding {
	hit, ok := r.match(ev)
	if !ok {
		return nil
	}
	return []RawFinding{{
		Rule:      pb.ThreatRuleId_THREAT_RULE_ID_ABUSE_TOOL,
		Severity:  pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM,
		TenantID:  ev.TenantID,
		Container: ev.Container,
		Subject:   "container:" + ev.Container + ":" + hit.Subject(),
		Evidence: Evidence{Execs: []ExecEvidence{{
			PID:           ev.PID,
			StartTime:     ev.StartTime,
			PPID:          ev.PPID,
			UID:           ev.UID,
			Comm:          ev.Comm,
			Filename:      ev.Filename,
			Argv:          ev.ArgvString(),
			ArgvTruncated: ev.ArgvTruncated,
			Matched:       hit.Subject(),
		}}},
	}}
}
