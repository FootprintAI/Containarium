package tracker

import (
	"strings"
	"testing"
)

func TestStamp_FromClaimsOnly(t *testing.T) {
	// Stamp's signature is a pure function of Identity — there is no
	// second parameter a caller could use to influence it, so the type
	// system itself is the proof: nothing but the verified Identity
	// (built by the caller from JWT claims + the run record, never from
	// request fields) can appear in the output. This test pins the
	// exact rendering so a future refactor can't quietly reopen an
	// injection point in the string-building itself.
	id := Identity{RunID: "run-abcdef123456789", SkillID: "code-review", Model: "sonnet"}
	got := Stamp(id, KindComment)

	if !strings.HasPrefix(got, "— code-review/run-abcdef12 (sonnet) via Containarium\n") {
		t.Fatalf("Stamp visible line = %q", got)
	}
	runID, skillID, kind, ok := ParseMarker(got)
	if !ok {
		t.Fatal("ParseMarker found no marker in Stamp's own output")
	}
	if runID != id.RunID || skillID != id.SkillID || kind != KindComment {
		t.Errorf("ParseMarker = (%q, %q, %q), want (%q, %q, %q)", runID, skillID, kind, id.RunID, id.SkillID, KindComment)
	}
}

func TestStamp_OmitsModelWhenManifestHasNone(t *testing.T) {
	got := Stamp(Identity{RunID: "run-1", SkillID: "skill-1"}, KindClaim)
	if strings.Contains(got, "()") {
		t.Errorf("Stamp = %q, want no empty parens when Model is unset", got)
	}
	if !strings.HasPrefix(got, "— skill-1/run-1 via Containarium\n") {
		t.Errorf("Stamp = %q, want the visible line with no model segment", got)
	}
}

func TestStamp_TruncatesLongRunIDInVisibleLineOnly(t *testing.T) {
	longRunID := "run-0123456789abcdefextra"
	got := Stamp(Identity{RunID: longRunID, SkillID: "s"}, KindComment)
	lines := strings.SplitN(got, "\n", 2)
	if strings.Contains(lines[0], longRunID) {
		t.Errorf("visible line %q contains the full run id, want it truncated", lines[0])
	}
	// The marker (used for machine parsing / audit) must still carry
	// the FULL run id — only the human-facing line is shortened.
	runID, _, _, ok := ParseMarker(got)
	if !ok || runID != longRunID {
		t.Errorf("ParseMarker run id = %q, ok=%v, want the untruncated %q", runID, ok, longRunID)
	}
}

func TestParseMarker_NoMarkerPresent(t *testing.T) {
	if _, _, _, ok := ParseMarker("just a plain comment, nothing hidden here"); ok {
		t.Error("ParseMarker found a marker in plain text")
	}
}

func TestParseMarker_ReturnsTheLastMarker(t *testing.T) {
	body := Stamp(Identity{RunID: "run-old", SkillID: "s"}, KindComment) +
		"\n\n" + Stamp(Identity{RunID: "run-new", SkillID: "s"}, KindClaim)
	runID, _, kind, ok := ParseMarker(body)
	if !ok || runID != "run-new" || kind != KindClaim {
		t.Errorf("ParseMarker = (%q, %q, ok=%v), want (run-new, claim, true)", runID, kind, ok)
	}
}

func TestSanitize_StripsForgedMarker(t *testing.T) {
	forged := Stamp(Identity{RunID: "attacker-run", SkillID: "attacker-skill"}, KindClaim)
	got := Sanitize("hey, unrelated text\n" + forged)
	if _, _, _, ok := ParseMarker(got); ok {
		t.Errorf("Sanitize(%q) = %q, still contains a parseable marker", forged, got)
	}
	if strings.Contains(got, markerPrefix) {
		t.Errorf("Sanitize output still contains the literal marker prefix: %q", got)
	}
}

// TestSanitize_GitLabQuickActions is the table the design note names:
// leading /assign, indented, inside fences, mid-line slash untouched,
// URL paths untouched.
func TestSanitize_GitLabQuickActions(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantChanged bool
	}{
		{"leading quick action", "/assign @bob", true},
		{"indented quick action", "  /close", true},
		{"quick action inside a code fence", "```\n/label ~bug\n```", true},
		{"mid-line slash untouched", "the fix is at src/main.go, not a command", false},
		{"URL path untouched", "see https://example.com/assign for docs", false},
		{"slash not followed by a letter untouched", "1/2 of the work is done", false},
		{"plain text untouched", "this comment has no commands at all", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Sanitize(tc.in)
			changed := got != tc.in
			if changed != tc.wantChanged {
				t.Errorf("Sanitize(%q) = %q, changed=%v, want changed=%v", tc.in, got, changed, tc.wantChanged)
			}
			if tc.wantChanged && !strings.Contains(got, "\u200b") {
				t.Errorf("Sanitize(%q) = %q, want a zero-width space inserted", tc.in, got)
			}
		})
	}
}

func TestSanitize_QuickActionZeroWidthSpacePosition(t *testing.T) {
	got := Sanitize("/assign @bob")
	want := "\u200b/assign @bob"
	if got != want {
		t.Errorf("Sanitize(/assign @bob) = %q, want %q (ZWSP immediately before the slash)", got, want)
	}
}

func TestSanitize_PreservesIndentationBeforeInsertingZWSP(t *testing.T) {
	got := Sanitize("  /close")
	want := "  \u200b/close"
	if got != want {
		t.Errorf("Sanitize(  /close) = %q, want %q", got, want)
	}
}

func TestSanitize_MultilineOnlyAffectsQuickActionLines(t *testing.T) {
	in := "normal line\n/assign @bob\nanother normal line"
	got := Sanitize(in)
	lines := strings.Split(got, "\n")
	if lines[0] != "normal line" || lines[2] != "another normal line" {
		t.Errorf("Sanitize modified a non-quick-action line: %q", got)
	}
	if !strings.HasPrefix(lines[1], "\u200b/assign") {
		t.Errorf("Sanitize did not neutralize the quick-action line: %q", lines[1])
	}
}

func TestSanitize_StripsMarkerBeforeQuickActionCheck(t *testing.T) {
	// A forged marker line itself never starts with "/", so this is
	// mostly a defense-in-depth check that the two passes compose
	// without interfering: stripping the marker prefix must not
	// accidentally create a new quick-action-shaped line.
	got := Sanitize(markerPrefix + "run=x skill=y kind=claim -->")
	if strings.HasPrefix(strings.TrimSpace(got), "/") {
		t.Errorf("Sanitize produced a quick-action-shaped line from a stripped marker: %q", got)
	}
}
