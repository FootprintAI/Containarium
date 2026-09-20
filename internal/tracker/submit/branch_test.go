package submit

import (
	"strings"
	"testing"
)

func TestBranchName_DaemonChosen(t *testing.T) {
	for _, tc := range []struct {
		name        string
		runID       string
		issueNumber int64
		title       string
		want        string
	}{
		{
			name:        "plain title",
			runID:       "run-abc123def456ghi789",
			issueNumber: 42,
			title:       "Fix the flaky retry test",
			want:        "agent/run-abc123de/42-fix-the-flaky-retry-test",
		},
		{
			name:        "short run id is not truncated further",
			runID:       "short",
			issueNumber: 7,
			title:       "add widget",
			want:        "agent/short/7-add-widget",
		},
		{
			name:        "empty title omits the slug entirely",
			runID:       "run-abc123def456ghi789",
			issueNumber: 9,
			title:       "",
			want:        "agent/run-abc123de/9",
		},
		{
			name:        "title punctuation collapses to single hyphens",
			runID:       "run-abc123def456ghi789",
			issueNumber: 3,
			title:       "  Weird!!  Title... with -- punctuation??  ",
			want:        "agent/run-abc123de/3-weird-title-with-punctuation",
		},
		{
			name:        "title cannot inject ref path segments",
			runID:       "run-abc123def456ghi789",
			issueNumber: 5,
			title:       "../../etc/passwd",
			want:        "agent/run-abc123de/5-etc-passwd",
		},
		{
			name:        "title cannot inject ref-breaking sequences",
			runID:       "run-abc123def456ghi789",
			issueNumber: 6,
			// git disallows "..", "~", "^", ":", "?", "*", "[", "\", a
			// leading/trailing "/", "@{", and a trailing ".lock" in a
			// ref name — none of these must survive into the slug.
			title: "a..b~c^d:e?f*g[h\\i@{j.lock",
			want:  "agent/run-abc123de/6-a-b-c-d-e-f-g-h-i-j-lock",
		},
		{
			name:        "negative issue number clamps to zero rather than emitting a minus sign",
			runID:       "run-abc123def456ghi789",
			issueNumber: -1,
			title:       "bad input",
			want:        "agent/run-abc123de/0-bad-input",
		},
		{
			name:        "long title is capped, not left to grow unbounded",
			runID:       "run-abc123def456ghi789",
			issueNumber: 1,
			title:       strings.Repeat("word ", 30),
			want:        "agent/run-abc123de/1-" + strings.Repeat("word-", 7) + "word",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := BranchName(tc.runID, tc.issueNumber, tc.title)
			if got != tc.want {
				t.Errorf("BranchName(%q, %d, %q) = %q, want %q", tc.runID, tc.issueNumber, tc.title, got, tc.want)
			}
		})
	}
}

// TestBranchName_RequestCannotInfluenceRunOrIssueSegments asserts the
// property the acceptance criteria actually care about: no matter what
// a caller puts in title, the run id and issue number segments of the
// branch are exactly what was passed as runID/issueNumber — a request
// field can only ever move the trailing, cosmetic slug.
func TestBranchName_RequestCannotInfluenceRunOrIssueSegments(t *testing.T) {
	const runID = "run-abc123def456ghi789"
	const issue = int64(42)
	wantPrefix := "agent/" + runIDShort(runID) + "/" + "42"

	for _, title := range []string{
		"", "normal title", "../../../etc/passwd",
		"refs/heads/main", "main", strings.Repeat("x", 500),
	} {
		got := BranchName(runID, issue, title)
		if !strings.HasPrefix(got, wantPrefix) {
			t.Errorf("BranchName(%q, %d, %q) = %q, want prefix %q", runID, issue, title, got, wantPrefix)
		}
	}
}

func TestSlugify(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Fix the flaky retry test", "fix-the-flaky-retry-test"},
		{"", ""},
		{"---", ""},
		{"UPPER CASE", "upper-case"},
		{"a/b/c", "a-b-c"},
	} {
		if got := slugify(tc.in); got != tc.want {
			t.Errorf("slugify(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
