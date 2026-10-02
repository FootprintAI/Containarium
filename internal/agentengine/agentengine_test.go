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
