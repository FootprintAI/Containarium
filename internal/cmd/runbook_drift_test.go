//go:build !containarium_client

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Upgrade-and-rollback runbook gate (#2563). An operator follows the runbook
// under pressure, mid-incident; a renamed verb, a dropped flag or a dead link
// there costs the most at the worst moment. These tests hold the runbook and
// the drill-record template to the real cobra tree (`containarium` and
// `containariumd` share one tree, see readme_drift_test.go), check every
// in-page and relative link resolves, and check the supported-release policy
// block is identical in SECURITY.md and the runbook.

var runbookDocs = []string{
	"../../docs/UPGRADE-AND-ROLLBACK.md",
	"../../docs/DRILL-RECORD-TEMPLATE.md",
}

const (
	runbookPath        = "../../docs/UPGRADE-AND-ROLLBACK.md"
	securityPolicyPath = "../../SECURITY.md"
	policyBegin        = "<!-- support-policy:begin -->"
	policyEnd          = "<!-- support-policy:end -->"
)

var runbookBinaries = map[string]bool{"containarium": true, "containariumd": true}

var (
	// inlineCLIRE matches an inline code span that starts with a binary name.
	inlineCLIRE = regexp.MustCompile("`((?:containariumd|containarium) [^`]+)`")
	// relLinkRE matches an inline Markdown link target.
	relLinkRE = regexp.MustCompile(`\]\(([^)\s]+)\)`)
)

// inlineInvocations returns the `containarium …` commands written as inline
// code spans in prose, outside fences. Steps cite verbs that way as often as
// they put them in a shell block, so both must resolve.
func inlineInvocations(markdown string) []cliInvocation {
	var out []cliInvocation
	inFence := false
	for i, line := range strings.Split(markdown, "\n") {
		if isFence, _ := fenceInfo(line); isFence {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		for _, m := range inlineCLIRE.FindAllStringSubmatch(line, -1) {
			for _, words := range splitShell(m[1]) {
				if args, ok := containariumArgs(words, runbookBinaries); ok {
					out = append(out, cliInvocation{Line: i + 1, Args: args})
				}
			}
		}
	}
	return out
}

// checkRelativeLinks reports every relative link outside fences whose file
// does not exist, and every `other.md#anchor` whose anchor is not a heading
// in that file. Pure in-page links (#x) are checkAnchors' job.
func checkRelativeLinks(docPath, markdown string) []driftProblem {
	var out []driftProblem
	inFence := false
	for i, line := range strings.Split(markdown, "\n") {
		if isFence, _ := fenceInfo(line); isFence {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		for _, m := range relLinkRE.FindAllStringSubmatch(line, -1) {
			target := m[1]
			if strings.HasPrefix(target, "#") || strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			path, frag, _ := strings.Cut(target, "#")
			full := filepath.Join(filepath.Dir(docPath), path)
			if _, err := os.Stat(full); err != nil {
				out = append(out, driftProblem{i + 1, fmt.Sprintf("link to %s: file not found", path)})
				continue
			}
			if frag == "" || !strings.HasSuffix(path, ".md") {
				continue
			}
			b, err := os.ReadFile(full) // #nosec G304 -- test reads repo docs
			if err != nil {
				out = append(out, driftProblem{i + 1, fmt.Sprintf("link to %s: %v", path, err)})
				continue
			}
			if !anchorTargets(string(b))[strings.ToLower(frag)] {
				out = append(out, driftProblem{i + 1, fmt.Sprintf("link to %s#%s has no matching heading", path, frag)})
			}
		}
	}
	return out
}

// checkRunbook runs every runbook check over one document.
func checkRunbook(root *cobra.Command, docPath, markdown string) []driftProblem {
	var out []driftProblem
	invs := append(extractInvocationsFor(markdown, runbookBinaries), inlineInvocations(markdown)...)
	for _, inv := range invs {
		out = append(out, checkInvocation(root, inv)...)
	}
	out = append(out, checkAnchors(markdown)...)
	return append(out, checkRelativeLinks(docPath, markdown)...)
}

func TestUpgradeRunbook_CommandsAndLinksResolve(t *testing.T) {
	for _, doc := range runbookDocs {
		md := readDriftFile(t, doc)
		for _, p := range checkRunbook(rootCmd, doc, md) {
			t.Errorf("%s:%d: %s", filepath.Base(doc), p.Line, p.Detail)
		}
	}
	md := readDriftFile(t, runbookPath)
	fenced, inline := len(extractInvocationsFor(md, runbookBinaries)), len(inlineInvocations(md))
	if fenced < 8 || inline < 8 {
		t.Fatalf("found %d fenced and %d inline invocations in the runbook — the extractor is broken, not the runbook", fenced, inline)
	}
}

// The bad fixture proves the runbook gate can fail: every planted mistake
// must be reported, by line, and nothing else.
func TestUpgradeRunbookChecker_CatchesBadFixture(t *testing.T) {
	const doc = "testdata/runbook_drift/bad.md"
	got := checkRunbook(rootCmd, doc, readDriftFile(t, doc))
	want := []struct {
		line int
		sub  string
	}{
		{6, `"--no-such-flag"`},
		{8, `"frobnicate"`},
		{11, `"--not-a-flag"`},
		{13, `does-not-exist.md: file not found`},
		{15, `good-target.md#no-such-heading`},
		{19, `#nope`},
	}
	for _, w := range want {
		found := false
		for _, p := range got {
			if p.Line == w.line && strings.Contains(p.Detail, w.sub) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("bad.md:%d: expected a problem mentioning %s; got %+v", w.line, w.sub, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("expected exactly %d problems, got %d: %+v", len(want), len(got), got)
	}
}

// policyBlock returns the text between the support-policy markers.
func policyBlock(markdown string) (string, error) {
	_, rest, ok := strings.Cut(markdown, policyBegin)
	if !ok {
		return "", fmt.Errorf("no %s marker", policyBegin)
	}
	block, _, ok := strings.Cut(rest, policyEnd)
	if !ok {
		return "", fmt.Errorf("no %s marker", policyEnd)
	}
	block = strings.TrimSpace(block)
	if !strings.Contains(block, "| ---") {
		return "", fmt.Errorf("support-policy block has no table")
	}
	return block, nil
}

// comparePolicy reports why SECURITY.md's and the runbook's policy blocks
// disagree, or nothing when they are identical.
func comparePolicy(security, runbook string) []string {
	s, errS := policyBlock(security)
	r, errR := policyBlock(runbook)
	var out []string
	if errS != nil {
		out = append(out, "SECURITY.md: "+errS.Error())
	}
	if errR != nil {
		out = append(out, "runbook: "+errR.Error())
	}
	if out != nil {
		return out
	}
	sl, rl := strings.Split(s, "\n"), strings.Split(r, "\n")
	for i := 0; i < max(len(sl), len(rl)); i++ {
		var a, b string
		if i < len(sl) {
			a = sl[i]
		}
		if i < len(rl) {
			b = rl[i]
		}
		if a != b {
			out = append(out, fmt.Sprintf("policy line %d differs:\n  SECURITY.md: %q\n  runbook:     %q", i+1, a, b))
		}
	}
	return out
}

func TestSupportPolicy_SecurityMDAndRunbookAgree(t *testing.T) {
	for _, p := range comparePolicy(readDriftFile(t, securityPolicyPath), readDriftFile(t, runbookPath)) {
		t.Error(p)
	}
}

// Seeded failures: the agreement check must fail when either side drifts or
// loses its markers, including on the real files with one row changed.
func TestSupportPolicyChecker_CatchesDrift(t *testing.T) {
	security := readDriftFile(t, securityPolicyPath)
	runbook := readDriftFile(t, runbookPath)
	block, err := policyBlock(security)
	if err != nil {
		t.Fatalf("SECURITY.md: %v", err)
	}
	row := ""
	for _, l := range strings.Split(block, "\n") {
		if strings.HasPrefix(l, "| ") && !strings.HasPrefix(l, "| ---") {
			row = l // the last table row
		}
	}
	tests := []struct {
		name, security, runbook, want string
	}{
		{"row changed in runbook", security, strings.Replace(runbook, row, row+" edited", 1), "differs"},
		{"row dropped from SECURITY.md", strings.Replace(security, row+"\n", "", 1), runbook, "differs"},
		{"runbook lost its markers", security, strings.ReplaceAll(runbook, policyBegin, ""), "runbook: no"},
		{"SECURITY.md lost its table", strings.ReplaceAll(security, "| ---", "|"), runbook, "has no table"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := comparePolicy(tt.security, tt.runbook)
			if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), tt.want) {
				t.Errorf("expected a problem mentioning %q, got %q", tt.want, got)
			}
		})
	}
}
