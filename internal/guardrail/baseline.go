package guardrail

import (
	"regexp"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Baseline response policy (#2736, slice A of #2575). When no admin policy
// exists the model gateway scans responses against this table instead of
// scanning nothing. It is deliberately its own table, not the engine's SECRET
// rules: a pluggable engine must not widen or narrow what a default install
// checks. The accepted scope is PEM private-key headers and common cloud-key
// shapes only; widening it is a reviewed change to TestBaselineRules_StableIDs.

// BaselineRuleID is the stable id of one baseline rule, as audit records and
// counters name it.
type BaselineRuleID string

const (
	BaselineRulePEMPrivateKey   BaselineRuleID = "baseline.pem_private_key"
	BaselineRuleAWSAccessKeyID  BaselineRuleID = "baseline.aws_access_key_id"
	BaselineRuleGoogleAPIKey    BaselineRuleID = "baseline.google_api_key"
	BaselineRuleAzureStorageKey BaselineRuleID = "baseline.azure_storage_account_key"
)

// BaselineRule is one entry of the baseline table. literals is a prefilter:
// every match contains at least one of them, so a unit with none is skipped
// without running the pattern (a leading \b defeats the regexp package's own
// literal-prefix scan, which made a clean 8 MiB response cost ~0.3 s).
type BaselineRule struct {
	ID       BaselineRuleID
	Kind     pb.GuardrailKind
	pattern  *regexp.Regexp
	literals []string
}

var baselineRules = []BaselineRule{
	// RSA, EC, DSA, OPENSSH, ENCRYPTED, PGP ("... PRIVATE KEY BLOCK") or bare.
	{BaselineRulePEMPrivateKey, pb.GuardrailKind_GUARDRAIL_KIND_SECRET,
		regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`), []string{"PRIVATE KEY"}},
	// Long-term (AKIA) and temporary (ASIA) access key ids.
	{BaselineRuleAWSAccessKeyID, pb.GuardrailKind_GUARDRAIL_KIND_SECRET,
		regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), []string{"AKIA", "ASIA"}},
	{BaselineRuleGoogleAPIKey, pb.GuardrailKind_GUARDRAIL_KIND_SECRET,
		regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}`), []string{"AIza"}},
	// Storage account key as it appears in a connection string.
	{BaselineRuleAzureStorageKey, pb.GuardrailKind_GUARDRAIL_KIND_SECRET,
		regexp.MustCompile(`AccountKey=[A-Za-z0-9+/]{86}==`), []string{"AccountKey="}},
}

func (r BaselineRule) mayMatch(text string) bool {
	for _, l := range r.literals {
		if strings.Contains(text, l) {
			return true
		}
	}
	return false
}

// BaselineRules returns the baseline table in evaluation order.
func BaselineRules() []BaselineRule {
	return append([]BaselineRule(nil), baselineRules...)
}

// BaselineAction is what the baseline did with a detection, as logs and audit
// records name it. The stored per-daemon mode (pb.GuardrailBaselineMode,
// #2738) decides which one applies.
type BaselineAction int

const (
	// BaselineActionLog flags and audits; the response is never held or blocked.
	BaselineActionLog BaselineAction = iota + 1
	// BaselineActionBlock flags and audits, and the held response is blocked.
	BaselineActionBlock
)

// String is the stable name used in logs and audit details.
func (a BaselineAction) String() string {
	switch a {
	case BaselineActionLog:
		return "log"
	case BaselineActionBlock:
		return "block"
	}
	return "unknown"
}

// BaselineDetection is one rule that matched in one response: ids and a
// count only. No field can hold the matched text
// (TestBaselineDetection_NoTextBearingField enforces this by reflection).
type BaselineDetection struct {
	RuleID  BaselineRuleID
	Kind    pb.GuardrailKind
	Matches int
}

// ScanBaseline runs the baseline table over the units and returns one
// detection per rule that matched, in table order, with matches summed over
// all units. Nil when nothing matched.
func ScanBaseline(units []*pb.GuardrailTextUnit) []BaselineDetection {
	var out []BaselineDetection
	for _, r := range baselineRules {
		n := 0
		for _, u := range units {
			if r.mayMatch(u.GetText()) {
				n += len(r.pattern.FindAllStringIndex(u.GetText(), -1))
			}
		}
		if n > 0 {
			out = append(out, BaselineDetection{RuleID: r.ID, Kind: r.Kind, Matches: n})
		}
	}
	return out
}
