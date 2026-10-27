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
	if source, ok := l.Source("sdlc"); !ok || source.Repo != l.Repo || source.Ref != l.Ref || source.SHA256 != l.SHA256 {
		t.Errorf("embedded sdlc source = %+v, %v; compatibility pin = %q@%q %q", source, ok, l.Repo, l.Ref, l.SHA256)
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

func TestParse_MultipleSources(t *testing.T) {
	text := "set.sdlc=architect\nset.qa=qa\n" +
		"[sdlc]\nrepo=a/sdlc\nref=" + strings.Repeat("a", 40) + "\nsha256=" + strings.Repeat("b", 64) + "\n" +
		"[domain]\nrepo=a/domain\nref=" + strings.Repeat("c", 40) + "\nsha256=" + strings.Repeat("d", 64) + "\n"
	l, err := Parse(text)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(l.Sources) != 2 || l.Sources[0].ID != "sdlc" || l.Sources[1].ID != "domain" {
		t.Fatalf("sources = %+v", l.Sources)
	}
	if got, ok := l.Source("domain"); !ok || got.Repo != "a/domain" || got.Ref != strings.Repeat("c", 40) || got.SHA256 != strings.Repeat("d", 64) {
		t.Errorf("domain source = %+v, %v", got, ok)
	}
	if l.Repo != "a/sdlc" || l.Ref != strings.Repeat("a", 40) || l.SHA256 != strings.Repeat("b", 64) {
		t.Errorf("compatibility pin = %q %q %q", l.Repo, l.Ref, l.SHA256)
	}
}

func TestParse_SourceSectionsAreValidated(t *testing.T) {
	ref := strings.Repeat("a", 40)
	sha := strings.Repeat("b", 64)
	good := "[sdlc]\nrepo=a/b\nref=" + ref + "\nsha256=" + sha + "\n"
	cases := map[string]string{
		"bad source id":    "[Bad_ID]\nrepo=a/b\nref=" + ref + "\nsha256=" + sha + "\n",
		"duplicate source": good + good,
		"missing repo":     "[sdlc]\nref=" + ref + "\nsha256=" + sha + "\n",
		"missing ref":      "[sdlc]\nrepo=a/b\nsha256=" + sha + "\n",
		"missing digest":   "[sdlc]\nrepo=a/b\nref=" + ref + "\n",
		"duplicate key":    good + "sha256=" + sha + "\n",
		"mixed formats":    "repo=old/flat\n" + good,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(text); err == nil {
				t.Fatal("parsed, want an error")
			}
		})
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
