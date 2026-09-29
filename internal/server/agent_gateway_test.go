package server

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/modelgateway"
)

func TestGatewayEnvScript_Anthropic(t *testing.T) {
	s, err := gatewayEnvScript("anthropic", 8080, "tok-abc", "/etc/containarium/agent")
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	// Resolves the host from the default route in-box (not baked at provision).
	if !strings.Contains(s, "ip route show default") {
		t.Errorf("expected default-route resolution:\n%s", s)
	}
	for _, want := range []string{
		"ANTHROPIC_BASE_URL",
		"http://$__ctn_host:8080/v1/model/anthropic",
		"ANTHROPIC_AUTH_TOKEN",
		"tok-abc",
		"> /etc/containarium/agent/gateway.env",
		"chmod 600 /etc/containarium/agent/gateway.env",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q\n%s", want, s)
		}
	}
}

func TestGatewayEnvScript_GeminiBareBase(t *testing.T) {
	// Gemini's engine appends /v1/model/gemini itself, so the env var is the
	// BARE daemon base — no path suffix.
	s, err := gatewayEnvScript("gemini", 8080, "g-tok", "/seed")
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	if !strings.Contains(s, "CONTAINARIUM_MODEL_GATEWAY_URL") || !strings.Contains(s, "CONTAINARIUM_GATEWAY_TOKEN") {
		t.Errorf("gemini env vars missing:\n%s", s)
	}
	if strings.Contains(s, "/v1/model/gemini") {
		t.Errorf("gemini base must be bare (no /v1/model/gemini suffix):\n%s", s)
	}
	if !strings.Contains(s, "http://$__ctn_host:8080\\n") && !strings.Contains(s, "http://$__ctn_host:8080\"") {
		t.Errorf("gemini base should be the bare host:port:\n%s", s)
	}
}

func TestGatewayEnvScript_UnknownProvider(t *testing.T) {
	if _, err := gatewayEnvScript("bedrock", 8080, "t", "/seed"); err == nil {
		t.Error("unknown provider must error")
	}
}

func TestGatewayPrimaryProvider_Precedence(t *testing.T) {
	cases := []struct {
		keys map[string]string
		want string
	}{
		{map[string]string{"anthropic": "a", "openai": "o", "gemini": "g"}, "anthropic"},
		{map[string]string{"openai": "o", "gemini": "g"}, "openai"},
		{map[string]string{"gemini": "g"}, "gemini"},
		{map[string]string{}, ""},
	}
	for _, c := range cases {
		if got := gatewayPrimaryProvider(c.keys); got != c.want {
			t.Errorf("gatewayPrimaryProvider(%v) = %q, want %q", c.keys, got, c.want)
		}
	}
}

func TestGatewayProviderKeysFromEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "g-key") // gemini falls back to GOOGLE_API_KEY
	keys := gatewayProviderKeysFromEnv()
	if keys["anthropic"] != "sk-ant" {
		t.Errorf("anthropic key = %q", keys["anthropic"])
	}
	if _, ok := keys["openai"]; ok {
		t.Errorf("openai should be absent (empty env): %v", keys)
	}
	if keys["gemini"] != "g-key" {
		t.Errorf("gemini should fall back to GOOGLE_API_KEY, got %q", keys["gemini"])
	}
}

// TestGatewayRegistryFromEnv — the daemon's provider registry is the
// compiled-in set plus any OpenAI-compatible upstream an operator registered
// with <PROVIDER>_UPSTREAM_URL, and each registered provider's daemon-global
// fallback key comes from <PROVIDER>_API_KEY. Registration must not depend on
// that key: on a multi-owner deployment the keys arrive per owner instead.
func TestGatewayRegistryFromEnv(t *testing.T) {
	t.Run("built-ins only", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "sk-ant")
		t.Setenv("OPENAI_API_KEY", "")
		t.Setenv("GEMINI_API_KEY", "")
		t.Setenv("GOOGLE_API_KEY", "")
		provs, keys, registered, err := gatewayRegistryFromEnv()
		if err != nil {
			t.Fatalf("gatewayRegistryFromEnv: %v", err)
		}
		if len(registered) != 0 {
			t.Errorf("registered = %v, want none", registered)
		}
		if provs["anthropic"] == nil || provs["gemini-openai"] == nil {
			t.Error("the compiled-in providers must still be registered")
		}
		if keys["anthropic"] != "sk-ant" {
			t.Errorf("anthropic key = %q, want sk-ant", keys["anthropic"])
		}
	})

	t.Run("operator-registered upstream", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "")
		t.Setenv("OPENAI_API_KEY", "")
		t.Setenv("GEMINI_API_KEY", "")
		t.Setenv("GOOGLE_API_KEY", "")
		t.Setenv("ACMEAI_UPSTREAM_URL", "https://region-a.example.com")
		t.Setenv("ACMEAI_API_KEY", "sk-acme")
		provs, keys, registered, err := gatewayRegistryFromEnv()
		if err != nil {
			t.Fatalf("gatewayRegistryFromEnv: %v", err)
		}
		if !containsString(registered, "acmeai") {
			t.Fatalf("registered = %v, want it to contain acmeai", registered)
		}
		if provs["acmeai"] == nil || provs["acmeai"].UpstreamURL != "https://region-a.example.com" {
			t.Fatalf("acmeai provider = %+v", provs["acmeai"])
		}
		if keys["acmeai"] != "sk-acme" {
			t.Errorf("acmeai global key = %q, want sk-acme", keys["acmeai"])
		}
	})

	t.Run("registered with no key of its own", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "")
		t.Setenv("OPENAI_API_KEY", "")
		t.Setenv("GEMINI_API_KEY", "")
		t.Setenv("GOOGLE_API_KEY", "")
		t.Setenv("ACMEAI_UPSTREAM_URL", "https://region-a.example.com")
		t.Setenv("ACMEAI_API_KEY", "")
		_, keys, registered, err := gatewayRegistryFromEnv()
		if err != nil {
			t.Fatalf("gatewayRegistryFromEnv: %v", err)
		}
		if !containsString(registered, "acmeai") {
			t.Fatalf("registered = %v, want it to contain acmeai even with no global key", registered)
		}
		if _, ok := keys["acmeai"]; ok {
			t.Errorf("acmeai must have no daemon-global key: %v", keys)
		}
		// This is the multi-owner shape, and the gateway has to come up for it:
		// the keys arrive per owner over RPC, not from the environment.
		if !gatewayEnabled(keys, registered) {
			t.Error("gateway must be enabled for an operator-registered upstream with no global key")
		}
	})

	t.Run("disabled when nothing is configured", func(t *testing.T) {
		if gatewayEnabled(map[string]string{}, nil) {
			t.Error("gateway must stay inert when no key and no upstream is configured")
		}
		if !gatewayEnabled(map[string]string{"anthropic": "k"}, nil) {
			t.Error("gateway must be enabled when a daemon-global key is set")
		}
	})
}

func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func TestMintGatewayToken_RoundTrips(t *testing.T) {
	secret := []byte("test-shared-secret")
	g := &gatewayProvisioning{provider: "anthropic", httpPort: 8080, secret: secret}
	tok, minted, err := g.mintGatewayToken("agent-hello", "hello-agent", "run-42", "")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	claims, err := modelgateway.VerifyToken(secret, tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Tenant != "agent-hello" || claims.SkillID != "hello-agent" || claims.Provider != "anthropic" {
		t.Errorf("claims mismatch: %+v", claims)
	}
	// #1817: the token must say which run it belongs to, and the mint must hand
	// back the jti + expiry the daemon needs to revoke it at run exit.
	if claims.RunID != "run-42" {
		t.Errorf("run_id claim = %q, want run-42", claims.RunID)
	}
	if minted.JTI == "" || minted.JTI != claims.ID {
		t.Errorf("minted jti = %q, want the token's own jti %q", minted.JTI, claims.ID)
	}
	if minted.ExpiresAt.IsZero() {
		t.Error("minted expiry is zero — nothing to pass to Revoke(jti, expiresAt, reason)")
	}
}

func TestSourceGatewayEnvPrefix_NoopWhenAbsent(t *testing.T) {
	p := sourceGatewayEnvPrefix("/seed")
	// Must guard on file existence so direct-mode boxes (no gateway.env) are a no-op.
	if !strings.Contains(p, "[ -f /seed/gateway.env ]") || !strings.Contains(p, ". /seed/gateway.env") {
		t.Errorf("prefix must source-if-present: %q", p)
	}
}
