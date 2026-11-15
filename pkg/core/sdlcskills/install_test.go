package sdlcskills

import (
	"strings"
	"testing"
)

func TestSkillSetsFromIDs(t *testing.T) {
	tests := []struct {
		ids  []string
		want string
	}{
		{nil, "none"},
		{[]string{}, "none"},
		{[]string{"qa"}, "qa"},
		{[]string{"sdlc", "qa", "sdlc"}, "qa,sdlc"},
	}
	for _, tt := range tests {
		if got := SkillSetsFromIDs(tt.ids).String(); got != tt.want {
			t.Errorf("SkillSetsFromIDs(%q) = %q, want %q", tt.ids, got, tt.want)
		}
	}
	if !SkillSetsFromIDs(nil).None() || SkillSetsFromIDs([]string{"qa"}).None() {
		t.Error("None() must follow the selection")
	}
}

func TestSkillSetsAllAndIDs(t *testing.T) {
	for _, v := range []string{"", "all"} {
		s, err := ParseSkillSets(v)
		if err != nil || !s.All() || s.None() || s.IDs() != nil {
			t.Errorf("ParseSkillSets(%q): all=%v none=%v ids=%v err=%v", v, s.All(), s.None(), s.IDs(), err)
		}
	}
	if s, _ := ParseSkillSets("none"); s.All() || !s.None() || s.IDs() != nil {
		t.Errorf("none: all=%v none=%v ids=%v", s.All(), s.None(), s.IDs())
	}
	s, _ := ParseSkillSets("sdlc, qa,sdlc")
	if s.All() || s.None() || strings.Join(s.IDs(), ",") != "sdlc,qa" {
		t.Errorf("ids: all=%v none=%v ids=%v", s.All(), s.None(), s.IDs())
	}
	ids := s.IDs()
	ids[0] = "mutated"
	if s.IDs()[0] != "sdlc" {
		t.Error("IDs must return a copy")
	}
}

func TestValidReleaseTag(t *testing.T) {
	for tag, want := range map[string]bool{
		"v0.127.0": true, "0.127.0": true, "v1.2.3-rc.1": true,
		"": false, "v1;rm -rf /": false, "$(x)": false, "v1 2": false, `v"1`: false, "-v1": false,
	} {
		if got := ValidReleaseTag(tag); got != want {
			t.Errorf("ValidReleaseTag(%q) = %v, want %v", tag, got, want)
		}
	}
}

// The script carries the release, repository and selection into the
// installer's environment, and never escalates.
func TestInstallScript(t *testing.T) {
	s := InstallScript(DefaultRepo, "v1.2.3", SkillSetsFromIDs([]string{"qa", "sdlc"}))
	for _, want := range []string{
		`https://raw.githubusercontent.com/FootprintAI/Containarium/v1.2.3/scripts/install-sdlc-skills.sh`,
		`SKILL_SETS="qa,sdlc" RELEASE="v1.2.3" REPO="FootprintAI/Containarium" bash "$tmp"`,
		`grep -q '^# skill-sets: v1$'`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "sudo") {
		t.Error("the installer runs as the box user; no sudo")
	}
	if none := InstallScript(DefaultRepo, "v1.2.3", SkillSetsFromIDs(nil)); !strings.Contains(none, `SKILL_SETS="none"`) {
		t.Errorf("an empty selection must be SKILL_SETS=none, never all:\n%s", none)
	}
}

func TestNewSkillsSource(t *testing.T) {
	ok := []struct{ base, version string }{
		{"", ""},
		{"https://skills.example.com/sdlc", ""},
		{"https://skills.example.com/sdlc/", "2026.11.0"},
		{"http://mirror.internal:8080/skills", "latest"},
	}
	for _, c := range ok {
		src, err := NewSkillsSource(c.base, c.version)
		if err != nil {
			t.Errorf("NewSkillsSource(%q, %q): %v", c.base, c.version, err)
			continue
		}
		if src.Version() != c.version || src.Signed() != (c.base != "") {
			t.Errorf("NewSkillsSource(%q, %q) = %+v", c.base, c.version, src)
		}
	}
	if src, _ := NewSkillsSource("https://skills.example.com/sdlc/", ""); src.BaseURL() != "https://skills.example.com/sdlc" {
		t.Errorf("trailing slash kept: %q", src.BaseURL())
	}
	bad := []struct{ base, version, want string }{
		{"", "2026.11.0", "base URL"},
		{"ftp://skills.example.com", "", "http"},
		{"https://skills.example.com/$(id)", "", "base URL"},
		{`https://skills.example.com/"x`, "", "base URL"},
		{"https://skills.example.com/a b", "", "base URL"},
		{"https://", "", "base URL"},
		{"https://skills.example.com", "1;rm", "version"},
		{"https://skills.example.com", "../1", "version"},
		{"https://skills.example.com", "$(id)", "version"},
	}
	for _, c := range bad {
		_, err := NewSkillsSource(c.base, c.version)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("NewSkillsSource(%q, %q) err = %v, want one mentioning %q", c.base, c.version, err, c.want)
		}
	}
}

// With a signed source the script hands the base URL and version to the
// installer, and refuses to ask an installer that would ignore them.
func TestInstallScriptFrom(t *testing.T) {
	sets := SkillSetsFromIDs([]string{"qa"})
	if got, want := InstallScriptFrom(DefaultRepo, "v1.2.3", sets, SkillsSource{}), InstallScript(DefaultRepo, "v1.2.3", sets); got != want {
		t.Errorf("no source must be the plain script:\n%s", got)
	}
	src, err := NewSkillsSource("https://skills.example.com/sdlc", "2026.11.0")
	if err != nil {
		t.Fatal(err)
	}
	s := InstallScriptFrom(DefaultRepo, "v1.2.3", sets, src)
	for _, want := range []string{
		`SDLC_SKILLS_BASE_URL="https://skills.example.com/sdlc" SDLC_SKILLS_VERSION="2026.11.0" SKILL_SETS="qa" RELEASE="v1.2.3" REPO="FootprintAI/Containarium" bash "$tmp"`,
		`grep -q '^# skills-source: v1$'`,
		`cannot move the box to skills release 2026.11.0`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "sudo") {
		t.Error("the installer runs as the box user; no sudo")
	}
}
