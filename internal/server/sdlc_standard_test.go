package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2488: CONTAINARIUM_SDLC_SKILLS_BUNDLE points the daemon at the pinned
// sdlc-skills.tar.gz. Every way that can go wrong ends with the inline prompt
// and a log line saying why; nothing is half-applied.

const stdYAML = `skills:
  - id: hosted
    name: Hosted
    recipe_id: agent-runtime
    system_prompt: contract text
    allowed_scopes: [containers:read]
    standard_from: engineer-implement
    standard_section: Engineering principles
`

type stubStd struct{ sec string }

func (s stubStd) Section(skill, section string) (string, bool) {
	if skill == "engineer-implement" && section == "Engineering principles" && s.sec != "" {
		return s.sec, true
	}
	return "", false
}
func (stubStd) Pin() string { return "example/skills@abc123abc123" }

func newStdCatalog(t *testing.T) *skills.Manager {
	t.Helper()
	m := skills.New()
	if err := m.LoadFromBytes([]byte(stdYAML)); err != nil {
		t.Fatal(err)
	}
	return m
}

func source(t *testing.T, m *skills.Manager) pb.PromptSource {
	t.Helper()
	s, err := m.Get("hosted")
	if err != nil {
		t.Fatal(err)
	}
	return s.PromptSource
}

func TestApplyPinnedStandard_NotConfiguredIsASilentNoOp(t *testing.T) {
	m := newStdCatalog(t)
	msg := applyPinnedStandard(m, "", func(string) (skills.StandardProvider, error) {
		t.Fatal("the loader must not run when no bundle path is configured")
		return nil, nil
	})
	if msg != "" {
		t.Errorf("message = %q, want none when unconfigured", msg)
	}
	if source(t, m) != pb.PromptSource_PROMPT_SOURCE_INLINE {
		t.Error("prompt changed without a configured bundle")
	}
}

func TestApplyPinnedStandard_AppliesAVerifiedBundle(t *testing.T) {
	m := newStdCatalog(t)
	msg := applyPinnedStandard(m, "/x/sdlc-skills.tar.gz", func(string) (skills.StandardProvider, error) {
		return stubStd{sec: "- be small"}, nil
	})
	if !strings.Contains(msg, "hosted") || !strings.Contains(msg, "example/skills@abc123abc123") {
		t.Errorf("message %q should name the skill and the pin", msg)
	}
	if source(t, m) != pb.PromptSource_PROMPT_SOURCE_SDLC_PIN {
		t.Error("the standard was not applied")
	}
}

func TestApplyPinnedStandard_FailuresFallBackAndSayWhy(t *testing.T) {
	cases := map[string]struct {
		load    func(string) (skills.StandardProvider, error)
		wantMsg string
	}{
		"bundle fails verification": {
			func(string) (skills.StandardProvider, error) {
				return nil, errors.New("digest abc does not match the pinned digest def")
			},
			"digest",
		},
		"section missing from the bundle": {
			func(string) (skills.StandardProvider, error) { return stubStd{}, nil },
			"hosted",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := newStdCatalog(t)
			msg := applyPinnedStandard(m, "/x/sdlc-skills.tar.gz", tc.load)
			if !strings.Contains(msg, tc.wantMsg) || !strings.Contains(strings.ToLower(msg), "inline") {
				t.Errorf("message %q should mention %q and that the inline prompt is used", msg, tc.wantMsg)
			}
			s, _ := m.Get("hosted")
			if s.SystemPrompt != "contract text" || s.PromptSource != pb.PromptSource_PROMPT_SOURCE_INLINE {
				t.Errorf("prompt/source changed on a failure: %q %v", s.SystemPrompt, s.PromptSource)
			}
		})
	}
}
