package guardrail

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// GateResult is the gate's decision over a re-scan of the redacted output.
type GateResult struct {
	Verdict pb.GuardrailVerdict
	// Residual findings per kind that the gate actually judged — findings
	// that fall inside a placeholder are excluded (see Gate).
	Residual map[pb.GuardrailKind]int64
	// Findings the engine reported inside a placeholder token: an engine
	// reading "[[PERSON_NAME:…]]" as a name. Counted for transparency,
	// never held against the subject.
	InPlaceholder int64
	Gaps          int64
	// Reasons is empty on PASS and names every rule that failed otherwise.
	Reasons []string
}

// Gate decides from the re-scan. It fails on any coverage gap (an engine
// that did not look is not a clean bill), on any BLOCK finding recorded at
// redaction, and on residual findings beyond a rule's max_residual.
//
// A finding whose span lies entirely within a placeholder token in the
// wiped text is ignored: the spike that preceded this package found that
// the only residuals left after a good redaction were the detector reading
// the placeholder itself, and a gate that can never reach PASS is not a
// gate. The placeholder spans are recomputed from the wiped text here, not
// trusted from the redaction step, so the gate stands on its own.
func Gate(rescan *pb.GuardrailScanResponse, wiped map[string]string, policy *pb.GuardrailPolicy, blocked map[pb.GuardrailKind]int64) *GateResult {
	res := &GateResult{
		Verdict:  pb.GuardrailVerdict_GUARDRAIL_VERDICT_PASS,
		Residual: map[pb.GuardrailKind]int64{},
		Gaps:     int64(len(rescan.GetGaps())),
	}
	holes := map[string][][2]int{}
	for id, text := range wiped {
		holes[id] = placeholderSpans(text)
	}
	for _, f := range rescan.GetFindings() {
		if insideAny(holes[f.GetUnitId()], int(f.GetStart()), int(f.GetEnd())) {
			res.InPlaceholder++
			continue
		}
		res.Residual[f.GetKind()]++
	}

	fail := func(format string, a ...any) {
		res.Verdict = pb.GuardrailVerdict_GUARDRAIL_VERDICT_FAIL
		res.Reasons = append(res.Reasons, fmt.Sprintf(format, a...))
	}
	if res.Gaps > 0 {
		fail("%d coverage gap(s): the engine could not fully scan part of the subject", res.Gaps)
	}
	for _, k := range sortedKinds(blocked) {
		if blocked[k] > 0 {
			fail("%d %s finding(s) on the original and the policy says BLOCK", blocked[k], kindName(k))
		}
	}
	limits := map[pb.GuardrailKind]int32{}
	for _, r := range policy.GetRules() {
		limits[r.GetKind()] = r.GetMaxResidual()
	}
	for _, k := range sortedKinds(res.Residual) {
		if n := res.Residual[k]; n > int64(limits[k]) {
			fail("%d residual %s finding(s) after redaction, policy allows %d", n, kindName(k), limits[k])
		}
	}
	return res
}

// placeholderSpans returns the code-point ranges of every placeholder
// token in text.
func placeholderSpans(text string) [][2]int {
	var out [][2]int
	for _, m := range placeholderRE.FindAllStringIndex(text, -1) {
		out = append(out, [2]int{
			utf8.RuneCountInString(text[:m[0]]),
			utf8.RuneCountInString(text[:m[1]]),
		})
	}
	return out
}

func insideAny(holes [][2]int, start, end int) bool {
	for _, h := range holes {
		if start >= h[0] && end <= h[1] {
			return true
		}
	}
	return false
}

func sortedKinds(m map[pb.GuardrailKind]int64) []pb.GuardrailKind {
	out := make([]pb.GuardrailKind, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// kindName renders GUARDRAIL_KIND_PII as "PII" for messages.
func kindName(k pb.GuardrailKind) string {
	return strings.TrimPrefix(k.String(), "GUARDRAIL_KIND_")
}
