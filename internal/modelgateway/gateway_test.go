package modelgateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeUpstream stands in for the real provider API; it records the auth headers
// it received and returns a canned usage body.
func fakeUpstream(t *testing.T, record func(r *http.Request), body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
}

func TestGateway_Anthropic_KeyInjected_TokenStripped_Metered(t *testing.T) {
	secret := []byte("shared-secret")
	var xKey, auth, gotPath string
	up := fakeUpstream(t, func(r *http.Request) {
		xKey = r.Header.Get("x-api-key")
		auth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
	}, `{"model":"claude-test","usage":{"input_tokens":12,"output_tokens":4,"cache_read_input_tokens":2}}`)
	defer up.Close()

	providers := DefaultProviders()
	providers["anthropic"].UpstreamURL = up.URL
	gw := New(Config{Secret: secret, Providers: providers, ProviderKeys: map[string]string{"anthropic": "REAL-KEY"}})
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()

	tok, err := MintToken(secret, GatewayClaims{Tenant: "acme", SkillID: "s1", Provider: "anthropic"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("POST", srv.URL+"/v1/model/anthropic/v1/messages", strings.NewReader(`{"model":"claude-test"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}

	if xKey != "REAL-KEY" {
		t.Errorf("real provider key not injected upstream: x-api-key=%q", xKey)
	}
	if auth != "" {
		t.Errorf("gateway token leaked upstream: Authorization=%q", auth)
	}
	if gotPath != "/v1/messages" {
		t.Errorf("upstream path = %q, want /v1/messages (prefix not stripped)", gotPath)
	}

	rows := gw.Meter().Snapshot()
	if len(rows) != 1 {
		t.Fatalf("want 1 meter row, got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Tenant != "acme" || r.Skill != "s1" || r.Provider != "anthropic" || r.Model != "claude-test" {
		t.Errorf("attribution wrong: %+v", r)
	}
	if r.InputTokens != 12 || r.OutputTokens != 4 || r.CachedTokens != 2 || r.Calls != 1 {
		t.Errorf("token counts wrong: %+v", r)
	}
}

// captureSink records the usage the gateway forwards to a UsageSink (#674
// increment 3 — the metering→billing writer).
type captureSink struct {
	tenant, skill, provider string
	u                       Usage
	calls                   int
}

func (c *captureSink) RecordUsage(tenant, skill, provider string, u Usage) {
	c.tenant, c.skill, c.provider, c.u = tenant, skill, provider, u
	c.calls++
}

func TestGateway_ForwardsUsageToSink(t *testing.T) {
	secret := []byte("shared-secret")
	up := fakeUpstream(t, func(*http.Request) {},
		`{"model":"claude-test","usage":{"input_tokens":12,"output_tokens":4,"cache_read_input_tokens":2}}`)
	defer up.Close()

	providers := DefaultProviders()
	providers["anthropic"].UpstreamURL = up.URL
	sink := &captureSink{}
	gw := New(Config{Secret: secret, Providers: providers, ProviderKeys: map[string]string{"anthropic": "REAL-KEY"}, Sink: sink})
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()

	tok, err := MintToken(secret, GatewayClaims{Tenant: "acme", SkillID: "s1", Provider: "anthropic"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/v1/model/anthropic/v1/messages", strings.NewReader(`{"model":"claude-test"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	// The sink receives the same attribution + token counts as the in-memory meter.
	if sink.calls != 1 {
		t.Fatalf("sink calls = %d, want 1", sink.calls)
	}
	if sink.tenant != "acme" || sink.skill != "s1" || sink.provider != "anthropic" || sink.u.Model != "claude-test" {
		t.Errorf("sink attribution wrong: %+v", sink)
	}
	if sink.u.InputTokens != 12 || sink.u.OutputTokens != 4 || sink.u.CachedTokens != 2 {
		t.Errorf("sink token counts wrong: %+v", sink.u)
	}
}

func TestGateway_NilSinkIsSafe(t *testing.T) {
	// No sink configured (standalone / OSS default) — metering still works,
	// nothing panics.
	secret := []byte("s")
	up := fakeUpstream(t, func(*http.Request) {}, `{"model":"m","usage":{"input_tokens":1}}`)
	defer up.Close()
	providers := DefaultProviders()
	providers["anthropic"].UpstreamURL = up.URL
	gw := New(Config{Secret: secret, Providers: providers, ProviderKeys: map[string]string{"anthropic": "K"}}) // Sink nil
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()
	tok, _ := MintToken(secret, GatewayClaims{Tenant: "t", Provider: "anthropic"}, time.Minute)
	req, _ := http.NewRequest("POST", srv.URL+"/v1/model/anthropic/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(gw.Meter().Snapshot()) != 1 {
		t.Error("in-memory meter should still record with a nil sink")
	}
}

func TestGateway_Gemini_PathModel_AllowedModelsEnforced(t *testing.T) {
	secret := []byte("s")
	var gKey string
	up := fakeUpstream(t, func(r *http.Request) {
		gKey = r.Header.Get("x-goog-api-key")
	}, `{"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":20,"cachedContentTokenCount":50}}`)
	defer up.Close()

	providers := DefaultProviders()
	providers["gemini"].UpstreamURL = up.URL
	gw := New(Config{Secret: secret, Providers: providers, ProviderKeys: map[string]string{"gemini": "GKEY"}})
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()

	// token allows only gemini-2.5-flash
	tok, _ := MintToken(secret, GatewayClaims{Tenant: "t", Provider: "gemini", AllowedModels: []string{"gemini-2.5-flash"}}, time.Minute)

	do := func(model string) int {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/model/gemini/v1beta/models/"+model+":generateContent", strings.NewReader("{}"))
		req.Header.Set("x-goog-api-key", tok) // how @google/genai sends the key
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if c := do("gemini-2.5-flash"); c != 200 {
		t.Fatalf("allowed model: status %d, want 200", c)
	}
	if gKey != "GKEY" {
		t.Errorf("gemini key not injected: x-goog-api-key=%q", gKey)
	}
	if c := do("gemini-2.5-pro"); c != 403 {
		t.Fatalf("disallowed model: status %d, want 403", c)
	}

	rows := gw.Meter().Snapshot()
	if len(rows) != 1 || rows[0].Model != "gemini-2.5-flash" {
		t.Fatalf("gemini metering/attribution wrong: %+v", rows)
	}
	if rows[0].InputTokens != 100 || rows[0].OutputTokens != 20 || rows[0].CachedTokens != 50 {
		t.Errorf("gemini token counts wrong: %+v", rows[0])
	}
}

// gemini-openai is the OpenAI-compatible Gemini route the hosted OpenHands
// canvas uses: a Bearer-authenticated /chat/completions call, proxied to
// Google's compat endpoint with the real key injected as Bearer and metered
// from the OpenAI-shaped usage block.
func TestGateway_GeminiOpenAI_BearerInjected_Metered(t *testing.T) {
	secret := []byte("s")
	var auth, upstreamPath string
	up := fakeUpstream(t, func(r *http.Request) {
		auth = r.Header.Get("Authorization")
		upstreamPath = r.URL.Path
	}, `{"model":"gemini-2.5-flash","usage":{"prompt_tokens":100,"completion_tokens":20}}`)
	defer up.Close()

	providers := DefaultProviders()
	providers["gemini-openai"].UpstreamURL = up.URL
	gw := New(Config{Secret: secret, Providers: providers, ProviderKeys: map[string]string{"gemini-openai": "GKEY"}})
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()

	tok, err := MintToken(secret, GatewayClaims{Tenant: "acme", SkillID: "ws", Provider: "gemini-openai"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// LiteLLM's openai provider posts /chat/completions relative to the profile
	// base URL (…/v1/model/gemini-openai/v1beta/openai), Bearer-authenticated.
	req, _ := http.NewRequest("POST", srv.URL+"/v1/model/gemini-openai/v1beta/openai/chat/completions", strings.NewReader(`{"model":"gemini-2.5-flash"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()

	if auth != "Bearer GKEY" {
		t.Errorf("real gemini key not injected as Bearer upstream: Authorization=%q", auth)
	}
	if upstreamPath != "/v1beta/openai/chat/completions" {
		t.Errorf("upstream path not preserved: got %q", upstreamPath)
	}
	rows := gw.Meter().Snapshot()
	if len(rows) != 1 || rows[0].Provider != "gemini-openai" || rows[0].Model != "gemini-2.5-flash" {
		t.Fatalf("metering/attribution wrong: %+v", rows)
	}
	if rows[0].InputTokens != 100 || rows[0].OutputTokens != 20 {
		t.Errorf("token counts wrong: %+v", rows[0])
	}
}

func TestGateway_RejectsBadTokens(t *testing.T) {
	secret := []byte("s")
	gw := New(Config{Secret: secret, Providers: DefaultProviders(), ProviderKeys: map[string]string{"anthropic": "k"}})
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()

	post := func(hdr, val string) int {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/model/anthropic/v1/messages", strings.NewReader("{}"))
		if hdr != "" {
			req.Header.Set(hdr, val)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if c := post("", ""); c != 401 {
		t.Errorf("missing token: want 401, got %d", c)
	}

	badSig, _ := MintToken([]byte("other-secret"), GatewayClaims{Tenant: "t", Provider: "anthropic"}, time.Minute)
	if c := post("Authorization", "Bearer "+badSig); c != 401 {
		t.Errorf("wrong-signature token: want 401, got %d", c)
	}

	expired, _ := MintToken(secret, GatewayClaims{Tenant: "t", Provider: "anthropic"}, -time.Minute)
	if c := post("Authorization", "Bearer "+expired); c != 401 {
		t.Errorf("expired token: want 401, got %d", c)
	}

	wrongProv, _ := MintToken(secret, GatewayClaims{Tenant: "t", Provider: "gemini"}, time.Minute)
	if c := post("Authorization", "Bearer "+wrongProv); c != 403 {
		t.Errorf("provider-mismatch token: want 403, got %d", c)
	}
}

func TestMintVerify_RoundTrip(t *testing.T) {
	secret := []byte("s")
	tok, err := MintToken(secret, GatewayClaims{Tenant: "acme", Provider: "gemini", AllowedModels: []string{"gemini-2.5-flash"}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyToken(secret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tenant != "acme" || c.Provider != "gemini" || len(c.AllowedModels) != 1 {
		t.Fatalf("claims round-trip wrong: %+v", c)
	}
	if _, err := VerifyToken([]byte("nope"), tok); err == nil {
		t.Error("verify with wrong secret should fail")
	}
}
