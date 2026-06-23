package modelgateway

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a concurrency-safe io.Writer for capturing logger output: the
// gateway writes the END line from its handler goroutine while the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor polls cond up to ~1s. The END log + lifecycle counters are written
// AFTER the response is flushed to the client (correct: END marks the server
// finishing), so a test that inspects them right after the HTTP call must wait.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func gatewayStatus(t *testing.T, base string) (inflight, completed, failed int64) {
	t.Helper()
	resp, err := http.Get(base + "/__gateway/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st struct{ Inflight, Completed, Failed int64 }
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	return st.Inflight, st.Completed, st.Failed
}

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

// TestGateway_RequestLifecycleObservability pins the "did it finish?" signal:
// every accepted request emits a START + matching END log, and the live
// /__gateway/status gauge returns to inflight=0 with completed incremented.
func TestGateway_RequestLifecycleObservability(t *testing.T) {
	secret := []byte("s")
	up := fakeUpstream(t, func(*http.Request) {},
		`{"model":"gemini-2.5-flash","usage":{"prompt_tokens":7,"completion_tokens":3}}`)
	defer up.Close()

	providers := DefaultProviders()
	providers["gemini-openai"].UpstreamURL = up.URL
	logbuf := &syncBuffer{}
	gw := New(Config{
		Secret: secret, Providers: providers,
		ProviderKeys: map[string]string{"gemini-openai": "GKEY"},
		Logger:       log.New(logbuf, "", 0),
	})
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()

	tok, _ := MintToken(secret, GatewayClaims{Tenant: "acme", SkillID: "ws", Provider: "gemini-openai"}, time.Minute)
	req, _ := http.NewRequest("POST", srv.URL+"/v1/model/gemini-openai/v1beta/openai/chat/completions", strings.NewReader(`{"model":"gemini-2.5-flash"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	waitFor(t, "END lifecycle log", func() bool { return strings.Contains(logbuf.String(), "req=1 END") })
	logs := logbuf.String()
	if !strings.Contains(logs, "req=1 START") {
		t.Errorf("missing START lifecycle log:\n%s", logs)
	}
	if !strings.Contains(logs, "req=1 END status=ok") {
		t.Errorf("missing END status=ok lifecycle log:\n%s", logs)
	}
	if !strings.Contains(logs, "out=3") {
		t.Errorf("END log should carry token usage (out=3):\n%s", logs)
	}

	waitFor(t, "completed=1", func() bool {
		inflight, completed, _ := gatewayStatus(t, srv.URL)
		return inflight == 0 && completed == 1
	})
	if _, _, failed := gatewayStatus(t, srv.URL); failed != 0 {
		t.Errorf("failed = %d, want 0", failed)
	}
}

// TestGateway_LifecycleFailedCounter asserts an upstream error response is
// counted as failed (not completed) and clears in-flight.
func TestGateway_LifecycleFailedCounter(t *testing.T) {
	secret := []byte("s")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer up.Close()

	providers := DefaultProviders()
	providers["gemini-openai"].UpstreamURL = up.URL
	gw := New(Config{Secret: secret, Providers: providers, ProviderKeys: map[string]string{"gemini-openai": "K"}})
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()

	tok, _ := MintToken(secret, GatewayClaims{Tenant: "t", Provider: "gemini-openai"}, time.Minute)
	req, _ := http.NewRequest("POST", srv.URL+"/v1/model/gemini-openai/v1beta/openai/chat/completions", strings.NewReader(`{"model":"m"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	waitFor(t, "failed=1", func() bool {
		inflight, _, failed := gatewayStatus(t, srv.URL)
		return inflight == 0 && failed == 1
	})
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
