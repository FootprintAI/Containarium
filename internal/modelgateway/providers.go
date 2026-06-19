package modelgateway

import (
	"net/http"
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
		"openai": {
			Name:        "openai",
			UpstreamURL: "https://api.openai.com",
			KeyEnv:      "OPENAI_API_KEY",
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
		},
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
	}
}

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
