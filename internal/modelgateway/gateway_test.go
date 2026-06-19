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
