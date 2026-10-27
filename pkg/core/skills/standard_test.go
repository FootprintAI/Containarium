package skills

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2488: a skill can declare that its system prompt is composed from the
// catalog's inline text plus one section of a pinned open-sdlc-skills skill.
// Without a configured bundle the prompt is the inline text, byte for byte.

const standardYAML = `skills:
  - id: hosted-engineer
    name: Hosted engineer
    recipe_id: agent-runtime
    system_prompt: >-
      You implement issues. Your FINAL message is exactly one JSON object.
    allowed_scopes: [containers:read]
    standard_from: engineer-implement
    standard_section: Engineering principles
  - id: plain
    name: Plain
    recipe_id: agent-runtime
    system_prompt: hello
    allowed_scopes: [containers:read]
`

type fakeStandard struct {
	sections map[string]string // "skill/section" -> text
	pin      string
}

func (f fakeStandard) Section(skill, section string) (string, bool) {
	t, ok := f.sections[skill+"/"+section]
	return t, ok
}
func (f fakeStandard) Pin() string { return f.pin }

func loadStandardCatalog(t *testing.T) *Manager {
	t.Helper()
	m := New()
	if err := m.LoadFromBytes([]byte(standardYAML)); err != nil {
		t.Fatalf("load: %v", err)
	}
	return m
}

func TestLoad_PromptSourceIsInlineUntilAStandardIsApplied(t *testing.T) {
	m := loadStandardCatalog(t)
	for _, id := range []string{"hosted-engineer", "plain"} {
		s, err := m.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		if s.PromptSource != pb.PromptSource_PROMPT_SOURCE_INLINE || s.PromptPin != "" {
			t.Errorf("%s: source=%v pin=%q, want INLINE and no pin at load", id, s.PromptSource, s.PromptPin)
		}
	}
	if got := m.StandardSkills(); len(got) != 1 || got[0] != "hosted-engineer" {
		t.Errorf("StandardSkills = %v, want [hosted-engineer]", got)
	}
}

func TestApplyStandard_ComposesWrapperFirstThenStandard(t *testing.T) {
	m := loadStandardCatalog(t)
	std := fakeStandard{
		sections: map[string]string{"engineer-implement/Engineering principles": "- **Test-first** — write the failing test first"},
		pin:      "example/skills@abc123abc123",
	}
	applied, missing := m.ApplyStandard(std)
	if len(applied) != 1 || applied[0] != "hosted-engineer" || len(missing) != 0 {
		t.Fatalf("applied=%v missing=%v", applied, missing)
	}

	s, _ := m.Get("hosted-engineer")
	inline := "You implement issues. Your FINAL message is exactly one JSON object."
	if !strings.HasPrefix(s.SystemPrompt, inline) {
		t.Errorf("the inline contract must come first:\n%s", s.SystemPrompt)
	}
	if !strings.HasSuffix(strings.TrimSpace(s.SystemPrompt), "write the failing test first") {
		t.Errorf("the standard section must come last:\n%s", s.SystemPrompt)
	}
	for _, want := range []string{"engineer-implement", "example/skills@abc123abc123", "the contract above wins"} {
		if !strings.Contains(s.SystemPrompt, want) {
			t.Errorf("composed prompt is missing %q:\n%s", want, s.SystemPrompt)
		}
	}
	if s.PromptSource != pb.PromptSource_PROMPT_SOURCE_SDLC_PIN || s.PromptPin != std.pin {
		t.Errorf("source=%v pin=%q", s.PromptSource, s.PromptPin)
	}
	// A skill without a standard is untouched.
	plain, _ := m.Get("plain")
	if plain.SystemPrompt != "hello" || plain.PromptSource != pb.PromptSource_PROMPT_SOURCE_INLINE {
		t.Errorf("plain skill changed: %q %v", plain.SystemPrompt, plain.PromptSource)
	}
}

func TestApplyStandard_MissingSectionKeepsInlineByteForByte(t *testing.T) {
	m := loadStandardCatalog(t)
	before, _ := m.Get("hosted-engineer")
	inline := before.SystemPrompt

	applied, missing := m.ApplyStandard(fakeStandard{sections: map[string]string{}, pin: "p"})
	if len(applied) != 0 || len(missing) != 1 || missing[0] != "hosted-engineer" {
		t.Fatalf("applied=%v missing=%v", applied, missing)
	}
	after, _ := m.Get("hosted-engineer")
	if after.SystemPrompt != inline {
		t.Errorf("prompt changed although the section is missing:\n%s", after.SystemPrompt)
	}
	if after.PromptSource != pb.PromptSource_PROMPT_SOURCE_INLINE || after.PromptPin != "" {
		t.Errorf("source=%v pin=%q, want INLINE and no pin", after.PromptSource, after.PromptPin)
	}
}

func TestApplyStandard_IsIdempotent(t *testing.T) {
	m := loadStandardCatalog(t)
	std := fakeStandard{sections: map[string]string{"engineer-implement/Engineering principles": "- rule"}, pin: "p@1"}
	m.ApplyStandard(std)
	once, _ := m.Get("hosted-engineer")
	first := once.SystemPrompt
	m.ApplyStandard(std)
	twice, _ := m.Get("hosted-engineer")
	if twice.SystemPrompt != first {
		t.Errorf("applying twice changed the prompt (the standard was appended again):\n%s", twice.SystemPrompt)
	}
	// And a re-apply with a later pin replaces, not accumulates.
	m.ApplyStandard(fakeStandard{sections: std.sections, pin: "p@2"})
	third, _ := m.Get("hosted-engineer")
	if strings.Count(third.SystemPrompt, "- rule") != 1 || !strings.Contains(third.SystemPrompt, "p@2") || strings.Contains(third.SystemPrompt, "p@1") {
		t.Errorf("re-apply with a new pin did not replace the old composition:\n%s", third.SystemPrompt)
	}
}

func TestValidate_StandardFieldsComeTogether(t *testing.T) {
	cases := map[string]string{
		"from without section": "standard_from: engineer-implement\n",
		"section without from": "standard_section: Engineering principles\n",
	}
	for name, extra := range cases {
		y := "skills:\n  - id: x\n    name: X\n    recipe_id: agent-runtime\n    system_prompt: p\n    allowed_scopes: [containers:read]\n    " + extra
		if err := New().LoadFromBytes([]byte(y)); err == nil {
			t.Errorf("%s: loaded, want a validation error", name)
		}
	}
}

// The embedded catalog's issue-implementer is the first consumer: it shares
// the engineering principles with the box-side engineer-implement skill.
func TestEmbeddedCatalog_IssueImplementerDeclaresTheStandard(t *testing.T) {
	m := New()
	if err := m.LoadEmbedded(); err != nil {
		t.Fatal(err)
	}
	spec, ok := m.standardFor("issue-implementer")
	if !ok {
		t.Fatal("issue-implementer declares no standard")
	}
	if spec.from != "engineer-implement" || spec.section != "Engineering principles" {
		t.Errorf("standard = %+v", spec)
	}
	// The hosted output contract is still in the inline text; the standard
	// never replaces it.
	s, _ := m.Get("issue-implementer")
	for _, want := range []string{`"pr_title"`, `"tests_run"`, "Do not commit", "max_files"} {
		if !strings.Contains(s.SystemPrompt, want) {
			t.Errorf("issue-implementer inline prompt lost %q", want)
		}
	}
}
