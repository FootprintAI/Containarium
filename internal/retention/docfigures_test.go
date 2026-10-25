package retention_test

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/retention"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// dataFlowDoc is the customer-facing retention document whose figures this
// test holds to the code (#2557).
const dataFlowDoc = "../../docs/security/DATA-FLOW-AND-RETENTION.md"

func readDataFlowDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(dataFlowDoc)
	if err != nil {
		t.Fatalf("read %s: %v", dataFlowDoc, err)
	}
	return string(b)
}

// TestDataFlowDoc_RetentionFiguresMatchCode is the gate: every day count the
// document states is either checked against internal/retention or listed, by
// exact phrase, as owned by another package.
func TestDataFlowDoc_RetentionFiguresMatchCode(t *testing.T) {
	for _, e := range checkRetentionDocFigures(readDataFlowDoc(t), codeFigures()) {
		t.Error(e)
	}
}

// TestCheckRetentionDocFigures_SelfTest proves the gate can fail: each case
// seeds one wrong or unclassified figure into the real document and expects
// the checker to name it.
func TestCheckRetentionDocFigures_SelfTest(t *testing.T) {
	doc := readDataFlowDoc(t)
	cases := []struct {
		name, old, new, want string
	}{
		{"class default changed", "| Prompts | 30 days | `--prompts` |", "| Prompts | 31 days | `--prompts` |", "--prompts"},
		{"class row missing", "| Evidence bundles | 365 days | `--evidence-bundles` |\n", "", "RETENTION_CLASS_EVIDENCE_BUNDLES"},
		{"unknown flag in class table", "`--responses` |", "`--answers` |", "--answers"},
		{"window cap changed", "between 1 and 36500 days", "between 1 and 3650 days", "3650"},
		{"cap in years changed", "(100 years)", "(10 years)", "10 years"},
		{"duration overflow changed", "about 106,751 days", "about 106,000 days", "106,000"},
		{"per-store sweep bound changed", "at most 100000 rows per store", "at most 50000 rows per store", "50000"},
		{"inventory enforced default changed", "| No automatic deletion | 90 days in enforce mode, as a prefix below the latest anchor (see below) | **yes** |\n| Session", "| No automatic deletion | 60 days in enforce mode, as a prefix below the latest anchor (see below) | **yes** |\n| Session", "60 days in enforce mode"},
		{"gateway-logs default in prose changed", "(90 days by default)", "(60 days by default)", "60 days by default"},
		{"crew example inconsistent", "kept for 90 days, not 30.", "kept for 30 days, not 30.", "crew"},
		{"unclassified figure added", "Box snapshots have no automatic expiry.", "Box snapshots are kept 45 days.", "45 days"},
		{"owned-elsewhere phrase gone stale", "reaper (7 days)", "reaper (8 days)", "reaper (7 days)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(doc, tc.old) {
				t.Fatalf("seed text %q not in the document; update the self-test", tc.old)
			}
			errs := checkRetentionDocFigures(strings.Replace(doc, tc.old, tc.new, 1), codeFigures())
			if len(errs) == 0 {
				t.Fatalf("checker accepted a document with %s", tc.name)
			}
			if joined := strings.Join(errs, "\n"); !strings.Contains(joined, tc.want) {
				t.Fatalf("errors do not name %q:\n%s", tc.want, joined)
			}
		})
	}
}

// docFigures are the values the document must state.
type docFigures struct {
	defaults          map[pb.RetentionClass]int32
	maxDays           int32
	maxRemovePerStore int
}

func codeFigures() docFigures {
	f := docFigures{
		defaults:          map[pb.RetentionClass]int32{},
		maxDays:           retention.MaxDays,
		maxRemovePerStore: retention.MaxRemovePerStore,
	}
	// BuildPolicy with nothing set is exactly the defaults of every class.
	for _, w := range retention.BuildPolicy(nil, 0, nil, "").GetWindows() {
		f.defaults[w.GetClass()] = w.GetDays()
	}
	return f
}

// flagClass maps the `containarium retention policy set` flags named in the
// document's class table to their class.
var flagClass = map[string]pb.RetentionClass{
	"prompts":             pb.RetentionClass_RETENTION_CLASS_PROMPTS,
	"responses":           pb.RetentionClass_RETENTION_CLASS_RESPONSES,
	"gateway-logs":        pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS,
	"session-transcripts": pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS,
	"evidence-bundles":    pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES,
}

// ownedElsewhere are day counts the document states that internal/retention
// does not own. They are not checked here; each phrase must still appear, so
// a changed figure fails until it is reclassified.
var ownedElsewhere = map[string]string{
	"reaper (7 days)":                    "internal/server/run_journal_reaper.go DefaultRunJournalRetention",
	"7 days (`--run-journal-retention`)": "internal/server/run_journal_reaper.go DefaultRunJournalRetention",
	"removes them after 7 days":          "internal/server/run_journal_reaper.go DefaultRunJournalRetention",
	"traffic cleanup (7 and 28 days)":    "internal/traffic collector RetentionDays x aggregateRetentionMultiplier",
	"after 7 and 28 days":                "internal/traffic collector RetentionDays x aggregateRetentionMultiplier",
	"7 days / 28 days, cleaned daily":    "internal/traffic collector RetentionDays x aggregateRetentionMultiplier",
	"deletes sooner (7 / 28 days)":       "internal/traffic collector RetentionDays x aggregateRetentionMultiplier",
	"90 days after rotation":             "terraform ssh_session_log_retention_days, gated by internal/sentinel/logrotate_scripts_test.go",
	"kept 30 days":                       "terraform/modules/containarium/spot-instance.tf max_retention_days",
}

// spaced turns a literal or pattern into one that allows any whitespace,
// line breaks included, wherever it has a space.
func spaced(pattern string) *regexp.Regexp {
	return regexp.MustCompile(strings.ReplaceAll(pattern, " ", `\s+`))
}

var (
	classRowRe = regexp.MustCompile("(?m)^\\| [^|\\n]+ \\| (\\d+) days \\| `--([a-z-]+)` \\|$")
	invRowRe   = regexp.MustCompile(`(?m)^\| (Prompts|Responses|Prompts and responses|Gateway logs|Session transcripts) \|[^\n]*?\| (\d+) days in enforce mode`)
	crewRe     = spaced(`With a (\d+)-day prompts window and a (\d+)-day responses window, a run's response is kept for (\d+) days, not (\d+)\.`)
	dayCountRe = regexp.MustCompile(`\b\d[\d,]*[\s-]+(?:days?|years?)\b`)
)

func checkRetentionDocFigures(doc string, want docFigures) []string {
	var errs []string
	type span struct{ start, end int }
	var covered []span
	line := func(off int) int { return strings.Count(doc[:off], "\n") + 1 }
	num := func(s string) int64 {
		n, err := strconv.ParseInt(strings.ReplaceAll(s, ",", ""), 10, 64)
		if err != nil {
			return -1
		}
		return n
	}
	fail := func(off int, format string, a ...any) {
		errs = append(errs, fmt.Sprintf("%s:%d: ", dataFlowDoc, line(off))+fmt.Sprintf(format, a...))
	}

	// The class table: one row per class, each at the code default.
	seen := map[pb.RetentionClass]int{}
	for _, m := range classRowRe.FindAllStringSubmatchIndex(doc, -1) {
		covered = append(covered, span{m[0], m[1]})
		flag, days := doc[m[4]:m[5]], num(doc[m[2]:m[3]])
		c, ok := flagClass[flag]
		if !ok {
			fail(m[0], "class table names unknown flag --%s", flag)
			continue
		}
		seen[c]++
		if days != int64(want.defaults[c]) {
			fail(m[0], "class table says --%s defaults to %d days; internal/retention says %d", flag, days, want.defaults[c])
		}
	}
	for c := range want.defaults {
		if seen[c] != 1 {
			errs = append(errs, fmt.Sprintf("%s: class table lists %v %d times, want exactly once", dataFlowDoc, c, seen[c]))
		}
	}

	// Single figures in prose, each tied to one constant.
	gw := int64(want.defaults[pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS])
	singles := []struct {
		re   *regexp.Regexp
		want int64
		what string
	}{
		{spaced(`between 1 and (\d+) days`), int64(want.maxDays), "retention.MaxDays"},
		{spaced(`clamped to (\d+) days`), int64(want.maxDays), "retention.MaxDays"},
		{spaced(`\((\d+) years\)`), int64(want.maxDays) / 365, "retention.MaxDays in years"},
		{spaced(`overflows past about ([\d,]+) days`), math.MaxInt64 / int64(24*time.Hour), "the longest time.Duration in days"},
		{spaced(`at most (\d+) rows per store per sweep`), int64(want.maxRemovePerStore), "retention.MaxRemovePerStore"},
		{spaced(`gateway-logs window \((\d+) days by default\)`), gw, "the gateway-logs default"},
	}
	for _, s := range singles {
		ms := s.re.FindAllStringSubmatchIndex(doc, -1)
		if len(ms) == 0 {
			errs = append(errs, fmt.Sprintf("%s: no figure matches %q (%s); the gate lost track of it", dataFlowDoc, s.re, s.what))
		}
		for _, m := range ms {
			covered = append(covered, span{m[0], m[1]})
			if got := num(doc[m[2]:m[3]]); got != s.want {
				fail(m[0], "%q states %d; %s is %d", doc[m[0]:m[1]], got, s.what, s.want)
			}
		}
	}

	// The inventory's enforced defaults. A crew run (prompts and responses)
	// is deleted past the longer of the two windows.
	inv := map[string]int64{
		"Prompts":               int64(want.defaults[pb.RetentionClass_RETENTION_CLASS_PROMPTS]),
		"Responses":             int64(want.defaults[pb.RetentionClass_RETENTION_CLASS_RESPONSES]),
		"Gateway logs":          gw,
		"Session transcripts":   int64(want.defaults[pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS]),
		"Prompts and responses": max(int64(want.defaults[pb.RetentionClass_RETENTION_CLASS_PROMPTS]), int64(want.defaults[pb.RetentionClass_RETENTION_CLASS_RESPONSES])),
	}
	invSeen := map[string]bool{}
	for _, m := range invRowRe.FindAllStringSubmatchIndex(doc, -1) {
		label, days := doc[m[2]:m[3]], num(doc[m[4]:m[5]])
		covered = append(covered, span{m[4], m[1]})
		invSeen[label] = true
		if days != inv[label] {
			fail(m[0], "inventory row %q says %d days in enforce mode; the class default is %d", label, days, inv[label])
		}
	}
	for label := range inv {
		if !invSeen[label] {
			errs = append(errs, fmt.Sprintf("%s: no inventory row for %q states its enforced default", dataFlowDoc, label))
		}
	}

	// The crew-run example must follow the longer-window rule it illustrates.
	if m := crewRe.FindStringSubmatchIndex(doc); m == nil {
		errs = append(errs, fmt.Sprintf("%s: the crew-run longer-window example is gone; the gate lost track of it", dataFlowDoc))
	} else {
		covered = append(covered, span{m[0], m[1]})
		p, r, kept, not := num(doc[m[2]:m[3]]), num(doc[m[4]:m[5]]), num(doc[m[6]:m[7]]), num(doc[m[8]:m[9]])
		if p <= r || kept != max(p, r) || not != r {
			fail(m[0], "crew-run example (%d-day prompts, %d-day responses, kept %d, not %d) contradicts the longer-window rule", p, r, kept, not)
		}
	}

	for phrase, owner := range ownedElsewhere {
		ms := spaced(regexp.QuoteMeta(phrase)).FindAllStringIndex(doc, -1)
		if len(ms) == 0 {
			errs = append(errs, fmt.Sprintf("%s: %q (owned by %s) no longer appears; reclassify the figure that replaced it", dataFlowDoc, phrase, owner))
		}
		for _, m := range ms {
			covered = append(covered, span{m[0], m[1]})
		}
	}

	// Anything left is a figure nobody checks.
	for _, m := range dayCountRe.FindAllStringIndex(doc, -1) {
		ok := false
		for _, c := range covered {
			if m[0] >= c.start && m[1] <= c.end {
				ok = true
				break
			}
		}
		if !ok {
			fail(m[0], "%q is neither checked against internal/retention nor listed in ownedElsewhere", doc[m[0]:m[1]])
		}
	}
	return errs
}
