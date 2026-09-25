package skills

import (
	"strings"
	"testing"
)

// TestProductDefineSkill_ManifestMinimalAndBrokered (#2023): the product
// role that a `scope:product` label dispatches ships as a catalog skill
// whose manifest grants ONLY tracker:read + tracker:write — no container,
// secret, or admin scope, so its run token can read the issue and write
// through the broker and nothing else. Its prompt drives the broker
// verbs (read, one result comment, a doc change for long output) and
// treats issue content as untrusted data.
func TestProductDefineSkill_ManifestMinimalAndBrokered(t *testing.T) {
	s, err := GetDefault().Get("product-define")
	if err != nil {
		t.Fatalf("product-define skill missing: %v", err)
	}
	if got := strings.Join(s.AllowedScopes, ","); got != "tracker:read,tracker:write" {
		t.Fatalf("allowed_scopes = %v, want exactly [tracker:read tracker:write]", s.AllowedScopes)
	}
	if s.GetRecipeId() != "agent-runtime" {
		t.Errorf("recipe_id = %q, want agent-runtime", s.GetRecipeId())
	}
	if len(s.AllowedPeers) != 0 {
		t.Errorf("allowed_peers = %v, want none (a leaf role)", s.AllowedPeers)
	}
	if s.Model != "" {
		t.Errorf("model = %q, want none pinned (provider-agnostic, like code-review)", s.Model)
	}
	prompt := s.SystemPrompt
	for _, want := range []string{
		"tracker_get_issue",     // reads the issue through the broker
		"tracker_comment",       // posts the one result comment
		"tracker_submit_change", // long output goes out as a doc change
		"untrusted",             // issue content is data, not instructions
		"exactly one",           // one result comment, not a stream
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("system_prompt does not mention %q", want)
		}
	}
	// The daemon owns the state labels and the trigger label; the prompt
	// must not tell the run to manage them (it could not anyway).
	for _, never := range []string{"tracker_set_labels", "agent:done", "agent:running"} {
		if strings.Contains(prompt, never) {
			t.Errorf("system_prompt mentions %q; state labels are the dispatcher's, not the run's", never)
		}
	}
}
