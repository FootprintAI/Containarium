package agentengine

import (
	"context"
	"errors"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		want    pb.AgentEngine
		wantErr bool
	}{
		{"claude", pb.AgentEngine_AGENT_ENGINE_CLAUDE, false},
		{"Claude", pb.AgentEngine_AGENT_ENGINE_CLAUDE, false},
		{"  codex  ", pb.AgentEngine_AGENT_ENGINE_CODEX, false},
		{"gemini", pb.AgentEngine_AGENT_ENGINE_GEMINI, false},
		{"cluade", pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED, true},
		{"", pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED, true},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Parse(%q): want error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q): unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParse_UnknownErrorListsValidNames(t *testing.T) {
	_, err := Parse("cluade")
	if err == nil {
		t.Fatal("want error")
	}
	for _, name := range []string{"claude", "codex", "gemini"} {
		if !contains(err.Error(), name) {
			t.Errorf("error %q should list valid name %q", err.Error(), name)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(sub) > 0 && indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestProviderRoundTrip(t *testing.T) {
	for _, e := range All() {
		p, ok := Provider(e)
		if !ok {
			t.Errorf("Provider(%v) = (_, false), want a provider", e)
			continue
		}
		if back := ForProvider(p); back != e {
			t.Errorf("ForProvider(Provider(%v)=%q) = %v, want %v", e, p, back, e)
		}
	}
	if _, ok := Provider(pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED); ok {
		t.Error("Provider(UNSPECIFIED) should report ok=false")
	}
	if got := ForProvider("bogus"); got != pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED {
		t.Errorf("ForProvider(bogus) = %v, want UNSPECIFIED", got)
	}
}

func TestEnvValue(t *testing.T) {
	cases := map[pb.AgentEngine]string{
		pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED: "",
		pb.AgentEngine_AGENT_ENGINE_CLAUDE:      "claude",
		pb.AgentEngine_AGENT_ENGINE_CODEX:       "codex",
		pb.AgentEngine_AGENT_ENGINE_GEMINI:      "gemini",
	}
	for e, want := range cases {
		if got := EnvValue(e); got != want {
			t.Errorf("EnvValue(%v) = %q, want %q", e, got, want)
		}
	}
}

// fakeKeyResolver records every call it receives, so tests can assert which
// lookups actually happened — e.g. that a global key short-circuits an
// owner-key check rather than always performing both.
type fakeKeyResolver struct {
	has   map[string]bool // "owner/provider" -> has key
	calls []string
}

func (f *fakeKeyResolver) KeyFor(_ context.Context, keyOwner, provider string) (string, bool) {
	key := keyOwner + "/" + provider
	f.calls = append(f.calls, key)
	if f.has[key] {
		return "fake-key-value", true
	}
	return "", false
}

func TestResolve(t *testing.T) {
	ctx := context.Background()
	claude := pb.AgentEngine_AGENT_ENGINE_CLAUDE
	codex := pb.AgentEngine_AGENT_ENGINE_CODEX
	unspecified := pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED

	t.Run("direct mode (gw=nil), unspecified exports nothing", func(t *testing.T) {
		res, err := Resolve(ctx, unspecified, "user:alice", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Engine != unspecified || res.Provider != "" || !res.Default {
			t.Errorf("got %+v, want {Engine:UNSPECIFIED Provider:\"\" Default:true}", res)
		}
	})

	t.Run("direct mode, named engine passes through, never refused", func(t *testing.T) {
		res, err := Resolve(ctx, codex, "user:alice", nil)
		if err != nil {
			t.Fatalf("direct mode must never refuse, got: %v", err)
		}
		if res.Engine != codex || res.Provider != "" || res.Default {
			t.Errorf("got %+v, want {Engine:CODEX Provider:\"\" Default:false}", res)
		}
	})

	t.Run("gateway mode, unspecified resolves to the default provider's engine", func(t *testing.T) {
		gw := &Gateway{DefaultProvider: "anthropic", GlobalProviders: map[string]bool{"anthropic": true}}
		res, err := Resolve(ctx, unspecified, "user:alice", gw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Engine != claude || res.Provider != "anthropic" || !res.Default {
			t.Errorf("got %+v, want {Engine:CLAUDE Provider:anthropic Default:true}", res)
		}
	})

	t.Run("gateway mode, named engine with a global key: ready, owner lookup skipped", func(t *testing.T) {
		resolver := &fakeKeyResolver{has: map[string]bool{}}
		gw := &Gateway{DefaultProvider: "anthropic", GlobalProviders: map[string]bool{"anthropic": true, "openai": true}, Keys: resolver}
		res, err := Resolve(ctx, codex, "user:alice", gw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Engine != codex || res.Provider != "openai" || res.Default {
			t.Errorf("got %+v, want {Engine:CODEX Provider:openai Default:false}", res)
		}
		if len(resolver.calls) != 0 {
			t.Errorf("a global key must short-circuit the owner-key lookup; calls = %v", resolver.calls)
		}
	})

	t.Run("gateway mode, named engine with no global key but an owner key: ready", func(t *testing.T) {
		resolver := &fakeKeyResolver{has: map[string]bool{"user:alice/openai": true}}
		gw := &Gateway{DefaultProvider: "anthropic", GlobalProviders: map[string]bool{"anthropic": true}, Keys: resolver}
		res, err := Resolve(ctx, codex, "user:alice", gw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Provider != "openai" {
			t.Errorf("got %+v, want provider openai", res)
		}
		if len(resolver.calls) != 1 || resolver.calls[0] != "user:alice/openai" {
			t.Errorf("want exactly one owner lookup for user:alice/openai, got %v", resolver.calls)
		}
	})

	t.Run("gateway mode, named engine with no key anywhere: NotReadyError naming provider and fix", func(t *testing.T) {
		resolver := &fakeKeyResolver{has: map[string]bool{}}
		gw := &Gateway{DefaultProvider: "anthropic", GlobalProviders: map[string]bool{"anthropic": true}, Keys: resolver}
		_, err := Resolve(ctx, codex, "user:alice", gw)
		if err == nil {
			t.Fatal("want a NotReadyError")
		}
		var nr *NotReadyError
		if !errors.As(err, &nr) {
			t.Fatalf("want *NotReadyError, got %T: %v", err, err)
		}
		if nr.Provider != "openai" {
			t.Errorf("Provider = %q, want openai", nr.Provider)
		}
		if !contains(nr.Reason, "openai") {
			t.Errorf("Reason %q should name the provider", nr.Reason)
		}
		if nr.Fix == "" {
			t.Error("Fix should not be empty")
		}
	})

	t.Run("gateway mode, nil Keys resolver: no owner check attempted, straight refusal", func(t *testing.T) {
		gw := &Gateway{DefaultProvider: "anthropic", GlobalProviders: map[string]bool{"anthropic": true}, Keys: nil}
		_, err := Resolve(ctx, codex, "user:alice", gw)
		var nr *NotReadyError
		if !errors.As(err, &nr) {
			t.Fatalf("want *NotReadyError, got %T: %v", err, err)
		}
	})
}

func statusFor(rows []*pb.AgentEngineStatus, e pb.AgentEngine) *pb.AgentEngineStatus {
	for _, r := range rows {
		if r.GetEngine() == e {
			return r
		}
	}
	return nil
}

func TestStatuses(t *testing.T) {
	ctx := context.Background()
	claude, codex, gemini := pb.AgentEngine_AGENT_ENGINE_CLAUDE, pb.AgentEngine_AGENT_ENGINE_CODEX, pb.AgentEngine_AGENT_ENGINE_GEMINI

	t.Run("direct mode: every row UNKNOWN_DIRECT_MODE, no default, no ready=true", func(t *testing.T) {
		rows := Statuses(ctx, "", nil, nil)
		if len(rows) != len(All()) {
			t.Fatalf("rows = %d, want %d (one per concrete engine)", len(rows), len(All()))
		}
		for _, r := range rows {
			if r.GetReadiness() != pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_UNKNOWN_DIRECT_MODE {
				t.Errorf("engine %v: readiness = %v, want UNKNOWN_DIRECT_MODE", r.GetEngine(), r.GetReadiness())
			}
			if r.GetSource() != pb.AgentCredentialSource_AGENT_CREDENTIAL_SOURCE_DIRECT_MODE {
				t.Errorf("engine %v: source = %v, want DIRECT_MODE", r.GetEngine(), r.GetSource())
			}
			if r.GetIsDefault() {
				t.Errorf("engine %v: is_default = true, want false (no daemon-side default in direct mode)", r.GetEngine())
			}
			if r.GetReason() == "" {
				t.Errorf("engine %v: reason is empty, want it to say why this daemon can't tell", r.GetEngine())
			}
		}
	})

	t.Run("gateway mode: global key ready, others not, default flagged, skill_ids explicit only", func(t *testing.T) {
		gw := &Gateway{DefaultProvider: "anthropic", GlobalProviders: map[string]bool{"anthropic": true}}
		skills := []SkillEngine{
			{ID: "codex-skill", Engine: codex},
			{ID: "unspecified-1", Engine: pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED},
			{ID: "unspecified-2", Engine: pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED},
		}
		rows := Statuses(ctx, "user:alice", gw, skills)

		c := statusFor(rows, claude)
		if c.GetReadiness() != pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_READY {
			t.Errorf("claude: readiness = %v, want READY", c.GetReadiness())
		}
		if c.GetSource() != pb.AgentCredentialSource_AGENT_CREDENTIAL_SOURCE_GLOBAL_KEY {
			t.Errorf("claude: source = %v, want GLOBAL_KEY", c.GetSource())
		}
		if !c.GetIsDefault() {
			t.Error("claude: is_default = false, want true (it's the daemon's DefaultProvider's engine)")
		}
		if len(c.GetSkillIds()) != 0 {
			t.Errorf("claude: skill_ids = %v, want none — unspecified-engine skills are never attributed (#2222 Q2)", c.GetSkillIds())
		}

		cx := statusFor(rows, codex)
		if cx.GetReadiness() != pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_NOT_READY {
			t.Errorf("codex: readiness = %v, want NOT_READY", cx.GetReadiness())
		}
		if cx.GetReason() == "" || !contains(cx.GetReason(), "openai") {
			t.Errorf("codex: reason = %q, want it to name openai", cx.GetReason())
		}
		if cx.GetIsDefault() {
			t.Error("codex: is_default = true, want false")
		}
		if got := cx.GetSkillIds(); len(got) != 1 || got[0] != "codex-skill" {
			t.Errorf("codex: skill_ids = %v, want [codex-skill]", got)
		}

		g := statusFor(rows, gemini)
		if g.GetReadiness() != pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_NOT_READY {
			t.Errorf("gemini: readiness = %v, want NOT_READY", g.GetReadiness())
		}
	})

	t.Run("gateway mode: owner key (no global) reports READY with OWNER_KEY source", func(t *testing.T) {
		resolver := &fakeKeyResolver{has: map[string]bool{"user:alice/openai": true}}
		gw := &Gateway{DefaultProvider: "anthropic", GlobalProviders: map[string]bool{"anthropic": true}, Keys: resolver}
		rows := Statuses(ctx, "user:alice", gw, nil)
		cx := statusFor(rows, codex)
		if cx.GetReadiness() != pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_READY {
			t.Errorf("codex: readiness = %v, want READY", cx.GetReadiness())
		}
		if cx.GetSource() != pb.AgentCredentialSource_AGENT_CREDENTIAL_SOURCE_OWNER_KEY {
			t.Errorf("codex: source = %v, want OWNER_KEY", cx.GetSource())
		}
	})

	t.Run("admin view: empty keyOwner still reports the global set correctly", func(t *testing.T) {
		gw := &Gateway{DefaultProvider: "gemini", GlobalProviders: map[string]bool{"gemini": true}}
		rows := Statuses(ctx, "", gw, nil)
		g := statusFor(rows, gemini)
		if g.GetReadiness() != pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_READY || !g.GetIsDefault() {
			t.Errorf("gemini: got readiness=%v is_default=%v, want READY/true", g.GetReadiness(), g.GetIsDefault())
		}
		c := statusFor(rows, claude)
		if c.GetReadiness() != pb.AgentEngineReadiness_AGENT_ENGINE_READINESS_NOT_READY {
			t.Errorf("claude: readiness = %v, want NOT_READY (no key, no owner to check)", c.GetReadiness())
		}
	})
}
