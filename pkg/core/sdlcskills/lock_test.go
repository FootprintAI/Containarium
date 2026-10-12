package sdlcskills

import (
	"strings"
	"testing"
)

// The embedded lock must always parse: a binary built from a half-edited pin
// (a ref bumped, the digest not) would otherwise only fail at runtime on a
// backend host.
func TestEmbeddedLockParses(t *testing.T) {
	l, err := Embedded()
	if err != nil {
		t.Fatalf("embedded lock: %v", err)
	}
	if l.Repo != "FootprintAI/open-sdlc-skills" {
		t.Errorf("repo = %q", l.Repo)
	}
}

func TestParse_RejectsPartialPins(t *testing.T) {
	good := "repo=a/b\nref=" + strings.Repeat("a", 40) + "\nsha256=" + strings.Repeat("b", 64) + "\n"
	if _, err := Parse("# comment\n\n" + good); err != nil {
		t.Fatalf("good lock rejected: %v", err)
	}
	cases := map[string]string{
		"no repo":      "ref=" + strings.Repeat("a", 40) + "\nsha256=" + strings.Repeat("b", 64),
		"short ref":    "repo=a/b\nref=abc\nsha256=" + strings.Repeat("b", 64),
		"tag as ref":   "repo=a/b\nref=v1.0.0\nsha256=" + strings.Repeat("b", 64),
		"empty digest": "repo=a/b\nref=" + strings.Repeat("a", 40) + "\nsha256=",
		"garbage line": good + "not a pair\n",
	}
	for name, text := range cases {
		if _, err := Parse(text); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
}
