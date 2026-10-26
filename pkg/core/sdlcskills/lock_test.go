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

const pin = "repo=a/b\nref=" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "\nsha256=" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + "\n"

// The lock carries the skill sets (#3048): which namespaces each set id selects.
func TestParse_SetsAreReadAndValidated(t *testing.T) {
	l, err := Parse(pin + "set.sdlc=architect,engineer\nset.qa=qa\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := strings.Join(l.Sets["qa"], ","); got != "qa" {
		t.Errorf("qa = %q", got)
	}
	if got := strings.Join(l.Sets["sdlc"], ","); got != "architect,engineer" {
		t.Errorf("sdlc = %q", got)
	}
	if _, err := Parse(pin); err != nil {
		t.Errorf("a lock with no sets (the pre-#3048 format) must still parse: %v", err)
	}
	for name, sets := range map[string]string{
		"bad id":           "set.Bad=qa\n",
		"empty namespaces": "set.qa=\n",
		"bad namespace":    "set.qa=q a\n",
		"namespace in two": "set.a=qa\nset.b=qa\n",
		"duplicate set id": "set.a=x\nset.a=y\n",
	} {
		if _, err := Parse(pin + sets); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
}

func TestEmbeddedLockDefinesSDLCAndQASets(t *testing.T) {
	l, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"sdlc", "qa"} {
		if len(l.Sets[id]) == 0 {
			t.Errorf("embedded lock has no set %q", id)
		}
	}
}

func TestParseSkillSets(t *testing.T) {
	ok := map[string]string{
		"":            "all",
		"all":         "all",
		"none":        "none",
		"sdlc":        "sdlc",
		"sdlc,qa":     "sdlc,qa",
		" qa , sdlc ": "qa,sdlc",
		"qa,qa":       "qa",
	}
	for in, want := range ok {
		got, err := ParseSkillSets(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got.String() != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"QA", "qa;rm", "$(x)", "a b", "qa,,sdlc", ",qa", "qa,", "none,qa", "all,qa", "q_a"} {
		if _, err := ParseSkillSets(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
