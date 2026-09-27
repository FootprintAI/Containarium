package modelgateway

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Provider describes one upstream model API the gateway brokers. The two
// engines the agent-runtime ships (Anthropic, OpenAI) plus Gemini (the cheap
// test engine) match the agent-runtime's three engines.
type Provider struct {
	Name        string
	UpstreamURL string // scheme://host, no trailing slash
	KeyEnv      string // env var the gateway reads the REAL provider key from

	// inject sets the upstream's auth header from the real provider key and
	// strips any inbound gateway credential, so the gateway token never leaks
	// upstream and the real key never came from the box.
	inject func(h http.Header, key string)
	// parseUsage extracts token usage + model from a decoded JSON response.
	// pathModel is the model id recovered from the request path (Gemini puts
	// the model in the URL, not the response body).
	parseUsage func(body map[string]any, pathModel string) Usage

	// openAIShaped marks a provider that speaks OpenAI's chat-completions
	// protocol: the model is in the request body, the usage block is
	// OpenAI-shaped, and `stream_options.include_usage` is what makes a
	// streamed response meterable. handleModel keys its request-body handling
	// off this instead of a hard-coded list of provider names, so a provider an
	// operator registers at runtime (ProvidersFromEnv) gets the same treatment
	// as the compiled-in ones.
	openAIShaped bool
}

// Usage is the metered token counts for one model call.
type Usage struct {
	Model        string
	InputTokens  int64
	OutputTokens int64
	CachedTokens int64
}

func stripGatewayAuth(h http.Header) {
	h.Del("Authorization")
	h.Del("X-Api-Key")
	h.Del("X-Goog-Api-Key")
}

func num(m map[string]any, k string) int64 {
	if v, ok := m[k].(float64); ok {
		return int64(v)
	}
	return 0
}

func subMap(m map[string]any, k string) map[string]any {
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	return nil
}

// DefaultProviders is the prototype's provider registry.
func DefaultProviders() map[string]*Provider {
	return map[string]*Provider{
		"anthropic": {
			Name:        "anthropic",
			UpstreamURL: "https://api.anthropic.com",
			KeyEnv:      "ANTHROPIC_API_KEY",
			inject: func(h http.Header, key string) {
				stripGatewayAuth(h)
				h.Set("x-api-key", key)
			},
			parseUsage: func(b map[string]any, _ string) Usage {
				u := subMap(b, "usage")
				model, _ := b["model"].(string)
				return Usage{
					Model:        model,
					InputTokens:  num(u, "input_tokens"),
					OutputTokens: num(u, "output_tokens"),
					CachedTokens: num(u, "cache_read_input_tokens"),
				}
			},
		},
		"openai": NewOpenAICompatibleProvider("openai", "https://api.openai.com"),
		"gemini": {
			Name:        "gemini",
			UpstreamURL: "https://generativelanguage.googleapis.com",
			KeyEnv:      "GEMINI_API_KEY",
			inject: func(h http.Header, key string) {
				stripGatewayAuth(h)
				h.Set("x-goog-api-key", key)
			},
			parseUsage: func(b map[string]any, pathModel string) Usage {
				u := subMap(b, "usageMetadata")
				return Usage{
					Model:        pathModel,
					InputTokens:  num(u, "promptTokenCount"),
					OutputTokens: num(u, "candidatesTokenCount"),
					CachedTokens: num(u, "cachedContentTokenCount"),
				}
			},
		},
		// gemini-openai brokers Gemini through Google's *OpenAI-compatible*
		// surface (/v1beta/openai/...), not the native generateContent API. It
		// exists for clients that speak OpenAI's chat-completions protocol and
		// authenticate with `Authorization: Bearer` — notably the hosted
		// OpenHands canvas (via LiteLLM's openai provider), which can't drive the
		// native gemini provider's `x-goog-api-key` path. Same real key
		// (GEMINI_API_KEY); a box still only ever holds the scoped gateway token.
		// The model is in the request body (not the path), so the token's
		// AllowedModels ceiling is not enforced here — a follow-up once
		// body-model parsing lands.
		//
		// It is now expressed through NewOpenAICompatibleProvider — it was a
		// hand-rolled copy of exactly that shape — with the one thing it does
		// not share overridden: it spends the NATIVE Gemini provider's key, not
		// a GEMINI_OPENAI_API_KEY of its own.
		"gemini-openai": geminiOpenAIProvider(),
	}
}

// geminiOpenAIProvider is the OpenAI-compatible view of Gemini, keyed on the
// native Gemini key.
func geminiOpenAIProvider() *Provider {
	p := NewOpenAICompatibleProvider("gemini-openai", "https://generativelanguage.googleapis.com")
	p.KeyEnv = "GEMINI_API_KEY"
	return p
}

// NewOpenAICompatibleProvider builds a provider for an upstream that speaks
// OpenAI's chat-completions protocol at upstreamURL: the real key goes up as
// `Authorization: Bearer`, every inbound gateway credential shape is stripped,
// and usage is read from the OpenAI-shaped `usage` block on both the
// non-streaming and the streamed (SSE, via sse.go) path.
//
// The upstream is a parameter rather than a compiled-in constant precisely so a
// deployment can point the gateway at ANY OpenAI-compatible endpoint — the
// vendor's hostname belongs in that deployment's configuration, not in this
// repo (see ProvidersFromEnv).
//
// KeyEnv follows the convention <NAME>_API_KEY for the daemon-global fallback
// key; a provider that shares another's key overrides the field after
// construction (see geminiOpenAIProvider). Per-owner keys never come from the
// environment at all — they arrive through Config.KeyResolver.
func NewOpenAICompatibleProvider(name, upstreamURL string) *Provider {
	return &Provider{
		Name:        name,
		UpstreamURL: strings.TrimRight(upstreamURL, "/"),
		KeyEnv:      providerEnvPrefix(name) + envAPIKeySuffix,
		inject: func(h http.Header, key string) {
			stripGatewayAuth(h)
			h.Set("Authorization", "Bearer "+key)
		},
		parseUsage: func(b map[string]any, _ string) Usage {
			u := subMap(b, "usage")
			model, _ := b["model"].(string)
			return Usage{
				Model:        model,
				InputTokens:  num(u, "prompt_tokens"),
				OutputTokens: num(u, "completion_tokens"),
			}
		},
		openAIShaped: true,
	}
}

// Env-var convention for registering an OpenAI-compatible provider at runtime.
const (
	// envUpstreamURLSuffix: setting <NAME>_UPSTREAM_URL registers a provider
	// named <name>.
	envUpstreamURLSuffix = "_UPSTREAM_URL"
	// envAPIKeySuffix: <NAME>_API_KEY is that provider's daemon-global
	// fallback key, read by the daemon (not by this package).
	envAPIKeySuffix = "_API_KEY"
)

// ProvidersFromEnv returns the OpenAI-compatible providers an operator
// registered by setting <NAME>_UPSTREAM_URL in the daemon's environment, e.g.
// ACMEAI_UPSTREAM_URL=https://region-a.example.com registers the provider
// "acmeai" at that upstream, keyed globally from ACMEAI_API_KEY and per owner
// through the gateway's KeyResolver.
//
// Why env-registered rather than compiled in: the endpoint a deployment brokers
// is deployment configuration. Nothing here is registered unless an operator
// names it, so this repo carries no vendor hostname and an existing daemon's
// provider registry is unchanged by the upgrade.
//
// environ takes os.Environ()'s "K=V" shape so the scan is testable without
// touching the process environment. A malformed entry is an error rather than a
// silently missing provider: a boxed agent pointed at a provider that didn't
// register would fail with a confusing 404 from the gateway instead.
func ProvidersFromEnv(environ []string) (map[string]*Provider, error) {
	out := map[string]*Provider{}
	builtin := DefaultProviders()
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasSuffix(k, envUpstreamURLSuffix) {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue // set-but-empty reads as "not configured", not as an error
		}
		name, err := providerNameFromEnvKey(k)
		if err != nil {
			return nil, err
		}
		if builtin[name] != nil {
			return nil, fmt.Errorf("modelgateway: %s would re-register the built-in provider %q; pick another name", k, name)
		}
		u, err := url.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("modelgateway: %s=%q is not a URL: %w", k, v, err)
		}
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("modelgateway: %s=%q must be an http(s) URL with a host", k, v)
		}
		out[name] = NewOpenAICompatibleProvider(name, v)
	}
	return out, nil
}

// providerNameFromEnvKey maps ACMEAI_UPSTREAM_URL -> "acmeai" and
// MY_VENDOR_UPSTREAM_URL -> "my-vendor": lower-cased, underscores as hyphens.
// The inverse of providerEnvPrefix.
func providerNameFromEnvKey(key string) (string, error) {
	prefix := strings.TrimSuffix(key, envUpstreamURLSuffix)
	name := strings.ToLower(strings.ReplaceAll(prefix, "_", "-"))
	if name == "" {
		return "", fmt.Errorf("modelgateway: %q names no provider (expected <NAME>%s)", key, envUpstreamURLSuffix)
	}
	if !providerNameRE.MatchString(name) {
		return "", fmt.Errorf("modelgateway: %q yields the invalid provider name %q (want %s)", key, name, providerNameRE)
	}
	return name, nil
}

// providerEnvPrefix maps "my-vendor" -> "MY_VENDOR", the env-var spelling of a
// provider name.
func providerEnvPrefix(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// providerNameRE is the provider-name shape: it has to survive being a URL path
// segment (/v1/model/<provider>/...) and an env-var prefix.
var providerNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// geminiModelFromPath pulls the model id out of a Gemini path like
// /v1beta/models/gemini-2.5-flash:generateContent.
func geminiModelFromPath(p string) string {
	i := strings.Index(p, "/models/")
	if i < 0 {
		return ""
	}
	rest := p[i+len("/models/"):]
	if c := strings.IndexAny(rest, ":/"); c >= 0 {
		rest = rest[:c]
	}
	return rest
}
