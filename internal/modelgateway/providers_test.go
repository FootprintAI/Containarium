package modelgateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestNewOpenAICompatibleProvider_Fields pins what the constructor builds: an
// OpenAI-shaped provider at the given upstream, with the conventional key env
// derived from its name, and marked as OpenAI-shaped so the gateway's
// body-buffering / streaming-usage path applies to it.
func TestNewOpenAICompatibleProvider_Fields(t *testing.T) {
	tests := []struct {
		name        string
		provider    string
		upstream    string
		wantKeyEnv  string
		wantUpsteam string
	}{
		{name: "single word", provider: "acmeai", upstream: "https://region-a.example.com", wantKeyEnv: "ACMEAI_API_KEY", wantUpsteam: "https://region-a.example.com"},
		{name: "hyphenated", provider: "my-vendor", upstream: "https://region-a.example.com/", wantKeyEnv: "MY_VENDOR_API_KEY", wantUpsteam: "https://region-a.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewOpenAICompatibleProvider(tc.provider, tc.upstream)
			if p.Name != tc.provider {
				t.Errorf("Name = %q, want %q", p.Name, tc.provider)
			}
			if p.UpstreamURL != tc.wantUpsteam {
				t.Errorf("UpstreamURL = %q, want %q (trailing slash must be trimmed)", p.UpstreamURL, tc.wantUpsteam)
			}
			if p.KeyEnv != tc.wantKeyEnv {
				t.Errorf("KeyEnv = %q, want %q", p.KeyEnv, tc.wantKeyEnv)
			}
			if !p.openAIShaped {
				t.Error("provider is not marked OpenAI-shaped; the gateway's streaming-usage path would skip it")
			}
		})
	}
}

// TestNewOpenAICompatibleProvider_Injection — the real key goes upstream as a
// bearer token and every inbound gateway credential shape is stripped, so
// neither the gateway token nor a client-supplied key ever reaches the
// upstream.
func TestNewOpenAICompatibleProvider_Injection(t *testing.T) {
	secret := []byte("s")
	var gotAuth, gotXAPIKey, gotXGoog, gotPath string
	up := fakeUpstream(t, func(r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotXAPIKey = r.Header.Get("X-Api-Key")
		gotXGoog = r.Header.Get("X-Goog-Api-Key")
		gotPath = r.URL.Path
	}, `{"model":"vendor-small","usage":{"prompt_tokens":11,"completion_tokens":5}}`)
	defer up.Close()

	providers := DefaultProviders()
	providers["acmeai"] = NewOpenAICompatibleProvider("acmeai", up.URL)
	srv := newTestServer(t, New(Config{
		Secret:       secret,
		Providers:    providers,
		ProviderKeys: map[string]string{"acmeai": "REAL-KEY"},
	}))

	tok, err := MintToken(secret, GatewayClaims{Tenant: "acme", Provider: "acmeai"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/model/acmeai/v1/chat/completions",
		strings.NewReader(`{"model":"vendor-small"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Api-Key", "client-supplied")
	req.Header.Set("X-Goog-Api-Key", "client-supplied-too")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}

	if gotAuth != "Bearer REAL-KEY" {
		t.Errorf("upstream Authorization = %q, want %q", gotAuth, "Bearer REAL-KEY")
	}
	if gotXAPIKey != "" || gotXGoog != "" {
		t.Errorf("inbound gateway credentials leaked upstream: x-api-key=%q x-goog-api-key=%q", gotXAPIKey, gotXGoog)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("upstream path = %q, want /v1/chat/completions", gotPath)
	}
}

// TestNewOpenAICompatibleProvider_UsageNonStream — OpenAI-shaped usage is
// metered off a non-streaming JSON response.
func TestNewOpenAICompatibleProvider_UsageNonStream(t *testing.T) {
	secret := []byte("s")
	up := fakeUpstream(t, func(*http.Request) {},
		`{"model":"vendor-small","usage":{"prompt_tokens":11,"completion_tokens":5}}`)
	defer up.Close()

	providers := DefaultProviders()
	providers["acmeai"] = NewOpenAICompatibleProvider("acmeai", up.URL)
	gw := New(Config{Secret: secret, Providers: providers, ProviderKeys: map[string]string{"acmeai": "REAL-KEY"}})
	srv := newTestServer(t, gw)

	tok, _ := MintToken(secret, GatewayClaims{Tenant: "acme", Provider: "acmeai"}, time.Minute)
	resp := postModel(t, srv.URL+"/v1/model/acmeai/v1/chat/completions", tok, `{"model":"vendor-small"}`)
	_ = resp.Body.Close()

	rows := gw.Meter().Snapshot()
	if len(rows) != 1 {
		t.Fatalf("meter rows = %d, want 1: %+v", len(rows), rows)
	}
	if rows[0].Provider != "acmeai" || rows[0].Model != "vendor-small" {
		t.Errorf("attribution wrong: %+v", rows[0])
	}
	if rows[0].InputTokens != 11 || rows[0].OutputTokens != 5 {
		t.Errorf("token counts wrong: %+v", rows[0])
	}
}

// TestNewOpenAICompatibleProvider_UsageSSE — the streaming path is metered
// too: the gateway must inject stream_options.include_usage into the request
// (which only happens for providers it knows are OpenAI-shaped) and parse the
// final usage event out of the SSE stream.
func TestNewOpenAICompatibleProvider_UsageSSE(t *testing.T) {
	secret := []byte("s")
	var gotBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"choices":[{"delta":{"content":"hi"},"finish_reason":"stop"}]}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"choices":[],"usage":{"prompt_tokens":31,"completion_tokens":9}}`+"\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer up.Close()

	providers := DefaultProviders()
	providers["acmeai"] = NewOpenAICompatibleProvider("acmeai", up.URL)
	gw := New(Config{Secret: secret, Providers: providers, ProviderKeys: map[string]string{"acmeai": "REAL-KEY"}})
	srv := newTestServer(t, gw)

	tok, _ := MintToken(secret, GatewayClaims{Tenant: "acme", Provider: "acmeai"}, time.Minute)
	resp := postModel(t, srv.URL+"/v1/model/acmeai/v1/chat/completions", tok,
		`{"model":"vendor-small","stream":true}`)
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if !strings.Contains(gotBody, "include_usage") {
		t.Errorf("gateway did not ask the upstream for stream usage; body sent = %s", gotBody)
	}
	if !strings.Contains(string(out), "hi") {
		t.Errorf("stream content not passed through: %q", out)
	}
	waitFor(t, "streaming usage to be metered", func() bool { return len(gw.Meter().Snapshot()) == 1 })
	rows := gw.Meter().Snapshot()
	if rows[0].InputTokens != 31 || rows[0].OutputTokens != 9 {
		t.Errorf("streamed token counts wrong: %+v", rows[0])
	}
	if rows[0].Model != "vendor-small" {
		t.Errorf("streamed model attribution = %q, want vendor-small", rows[0].Model)
	}
}

// TestDefaultProviders_GeminiOpenAIIsCompatibleProvider — gemini-openai is now
// expressed through NewOpenAICompatibleProvider rather than its own hand-rolled
// copy, and keeps the key env and upstream it had (it shares the native Gemini
// provider's key).
func TestDefaultProviders_GeminiOpenAIIsCompatibleProvider(t *testing.T) {
	p := DefaultProviders()["gemini-openai"]
	if p == nil {
		t.Fatal("gemini-openai is no longer registered")
	}
	if p.KeyEnv != "GEMINI_API_KEY" {
		t.Errorf("KeyEnv = %q, want GEMINI_API_KEY", p.KeyEnv)
	}
	if p.UpstreamURL != "https://generativelanguage.googleapis.com" {
		t.Errorf("UpstreamURL = %q changed", p.UpstreamURL)
	}
	if !p.openAIShaped {
		t.Error("gemini-openai must stay marked OpenAI-shaped")
	}
	if !DefaultProviders()["openai"].openAIShaped {
		t.Error("openai must be marked OpenAI-shaped")
	}
	if DefaultProviders()["anthropic"].openAIShaped || DefaultProviders()["gemini"].openAIShaped {
		t.Error("anthropic/gemini are not OpenAI-shaped and must not be marked so")
	}
}

// TestProvidersFromEnv covers the registration convention: an operator adds an
// OpenAI-compatible upstream by setting <PROVIDER>_UPSTREAM_URL. No upstream is
// compiled in, so this repo carries no vendor hostname and an unset env means
// no extra provider.
func TestProvidersFromEnv(t *testing.T) {
	tests := []struct {
		name      string
		environ   []string
		wantNames []string
		wantURLs  map[string]string
		wantErr   bool
	}{
		{
			name:      "nothing set registers nothing",
			environ:   []string{"PATH=/usr/bin", "OPENAI_API_KEY=x"},
			wantNames: nil,
		},
		{
			name:      "one upstream registers one provider",
			environ:   []string{"ACMEAI_UPSTREAM_URL=https://region-a.example.com"},
			wantNames: []string{"acmeai"},
			wantURLs:  map[string]string{"acmeai": "https://region-a.example.com"},
		},
		{
			name:      "underscores become hyphens in the provider name",
			environ:   []string{"MY_VENDOR_UPSTREAM_URL=https://region-a.example.com"},
			wantNames: []string{"my-vendor"},
			wantURLs:  map[string]string{"my-vendor": "https://region-a.example.com"},
		},
		{
			name:      "two upstreams register two providers",
			environ:   []string{"A_UPSTREAM_URL=https://a.example.com", "B_UPSTREAM_URL=http://b.example.com"},
			wantNames: []string{"a", "b"},
		},
		{
			name:      "empty value registers nothing",
			environ:   []string{"ACMEAI_UPSTREAM_URL="},
			wantNames: nil,
		},
		{
			name:      "whitespace is trimmed",
			environ:   []string{"ACMEAI_UPSTREAM_URL=  https://region-a.example.com  "},
			wantNames: []string{"acmeai"},
			wantURLs:  map[string]string{"acmeai": "https://region-a.example.com"},
		},
		{
			name:    "a non-http upstream is rejected",
			environ: []string{"ACMEAI_UPSTREAM_URL=ftp://region-a.example.com"},
			wantErr: true,
		},
		{
			name:    "an upstream with no host is rejected",
			environ: []string{"ACMEAI_UPSTREAM_URL=https:///v1"},
			wantErr: true,
		},
		{
			name:    "a name colliding with a built-in provider is rejected",
			environ: []string{"OPENAI_UPSTREAM_URL=https://region-a.example.com"},
			wantErr: true,
		},
		{
			name:    "a bare suffix has no provider name",
			environ: []string{"_UPSTREAM_URL=https://region-a.example.com"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ProvidersFromEnv(tc.environ)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ProvidersFromEnv = %v, want an error", keysOf(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("ProvidersFromEnv: %v", err)
			}
			if !equalStrings(keysOf(got), tc.wantNames) {
				t.Fatalf("provider names = %v, want %v", keysOf(got), tc.wantNames)
			}
			for name, wantURL := range tc.wantURLs {
				p := got[name]
				if p == nil {
					t.Fatalf("provider %q missing", name)
				}
				if p.UpstreamURL != wantURL {
					t.Errorf("%s upstream = %q, want %q", name, p.UpstreamURL, wantURL)
				}
				if !p.openAIShaped {
					t.Errorf("%s is not marked OpenAI-shaped", name)
				}
			}
		})
	}
}

// keysOf returns a provider registry's names, sorted, for stable comparison.
func keysOf(m map[string]*Provider) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
