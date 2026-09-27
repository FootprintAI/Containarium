package modelgateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// recordingResolver is a KeyResolver over a fixed (keyOwner, provider) table
// that also records every lookup, so a test can assert both the key that came
// back AND that a legacy token (no key_owner claim) never reaches the resolver
// at all.
type recordingResolver struct {
	keys  map[string]string // "<keyOwner>|<provider>" -> real key
	calls []string
}

func (r *recordingResolver) KeyFor(_ context.Context, keyOwner, provider string) (string, bool) {
	r.calls = append(r.calls, keyOwner+"|"+provider)
	k, ok := r.keys[keyOwner+"|"+provider]
	return k, ok
}

// newTestServer serves the gateway's handler and closes it with the test.
func newTestServer(t *testing.T, gw *Gateway) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// postModel POSTs one model call through the gateway with tok as the gateway
// credential. The caller closes the response body.
func postModel(t *testing.T, url, tok, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestKeyResolution is the per-owner resolution matrix: (key_owner claim
// present / absent) x (owner key / global key / neither). The claim-absent
// rows are the compatibility golden — a token minted before key_owner existed
// must resolve exactly as it does today, through Config.ProviderKeys, without
// the resolver being consulted at all.
func TestKeyResolution(t *testing.T) {
	tests := []struct {
		name       string
		keyOwner   string            // "" = legacy token, no key_owner claim
		ownerKeys  map[string]string // the KeyResolver's table
		globalKeys map[string]string // Config.ProviderKeys
		noResolver bool
		wantStatus int
		wantAuth   string   // Authorization the upstream saw
		wantCalls  []string // resolver lookups
	}{
		{
			name:       "legacy token resolves through the global key",
			globalKeys: map[string]string{"openai": "GLOBAL"},
			wantStatus: http.StatusOK,
			wantAuth:   "Bearer GLOBAL",
			wantCalls:  nil,
		},
		{
			name:       "legacy token with no global key is refused",
			wantStatus: http.StatusBadGateway,
			wantCalls:  nil,
		},
		{
			name:       "owner key is used when the claim is present",
			keyOwner:   "org:acme",
			ownerKeys:  map[string]string{"org:acme|openai": "OWNER"},
			wantStatus: http.StatusOK,
			wantAuth:   "Bearer OWNER",
			wantCalls:  []string{"org:acme|openai"},
		},
		{
			name:       "owner key wins over the global key",
			keyOwner:   "org:acme",
			ownerKeys:  map[string]string{"org:acme|openai": "OWNER"},
			globalKeys: map[string]string{"openai": "GLOBAL"},
			wantStatus: http.StatusOK,
			wantAuth:   "Bearer OWNER",
			wantCalls:  []string{"org:acme|openai"},
		},
		{
			name:       "owner with no key falls back to the global key",
			keyOwner:   "org:acme",
			globalKeys: map[string]string{"openai": "GLOBAL"},
			wantStatus: http.StatusOK,
			wantAuth:   "Bearer GLOBAL",
			wantCalls:  []string{"org:acme|openai"},
		},
		{
			name:       "owner with no key and no global key is refused",
			keyOwner:   "org:acme",
			wantStatus: http.StatusBadGateway,
			wantCalls:  []string{"org:acme|openai"},
		},
		{
			name:       "another owner's key is never used",
			keyOwner:   "org:a",
			ownerKeys:  map[string]string{"org:b|openai": "B-KEY"},
			wantStatus: http.StatusBadGateway,
			wantCalls:  []string{"org:a|openai"},
		},
		{
			name:       "claim present but no resolver wired falls back to the global key",
			keyOwner:   "org:acme",
			noResolver: true,
			globalKeys: map[string]string{"openai": "GLOBAL"},
			wantStatus: http.StatusOK,
			wantAuth:   "Bearer GLOBAL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secret := []byte("s")
			var gotAuth string
			up := fakeUpstream(t, func(r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
			}, `{"model":"m","usage":{"prompt_tokens":1,"completion_tokens":1}}`)
			defer up.Close()

			providers := DefaultProviders()
			providers["openai"].UpstreamURL = up.URL
			res := &recordingResolver{keys: tc.ownerKeys}
			cfg := Config{Secret: secret, Providers: providers, ProviderKeys: tc.globalKeys}
			if !tc.noResolver {
				cfg.KeyResolver = res
			}
			srv := newTestServer(t, New(cfg))

			tok, err := MintToken(secret, GatewayClaims{
				Tenant:   "box1",
				Provider: "openai",
				KeyOwner: tc.keyOwner,
			}, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			resp := postModel(t, srv.URL+"/v1/model/openai/v1/chat/completions", tok, `{"model":"m"}`)
			if resp.StatusCode != tc.wantStatus {
				b, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, tc.wantStatus, strings.TrimSpace(string(b)))
			}
			_ = resp.Body.Close()
			if gotAuth != tc.wantAuth {
				t.Errorf("upstream Authorization = %q, want %q", gotAuth, tc.wantAuth)
			}
			if !equalStrings(res.calls, tc.wantCalls) {
				t.Errorf("resolver lookups = %v, want %v", res.calls, tc.wantCalls)
			}
		})
	}
}

// TestKeyResolution_OwnerAlwaysAskedFirst pins that the resolver is asked
// before Config.ProviderKeys is read, so a per-owner key can never be skipped
// because the daemon-global one happens to be set.
func TestKeyResolution_OwnerAlwaysAskedFirst(t *testing.T) {
	secret := []byte("s")
	var gotAuth string
	up := fakeUpstream(t, func(r *http.Request) { gotAuth = r.Header.Get("Authorization") },
		`{"model":"m","usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	defer up.Close()

	providers := DefaultProviders()
	providers["openai"].UpstreamURL = up.URL
	srv := newTestServer(t, New(Config{
		Secret:       secret,
		Providers:    providers,
		ProviderKeys: map[string]string{"openai": "GLOBAL"},
		KeyResolver:  &recordingResolver{keys: map[string]string{"user:bob|openai": "BOB"}},
	}))

	tok, _ := MintToken(secret, GatewayClaims{Tenant: "box1", Provider: "openai", KeyOwner: "user:bob"}, time.Minute)
	resp := postModel(t, srv.URL+"/v1/model/openai/v1/chat/completions", tok, `{"model":"m"}`)
	_ = resp.Body.Close()
	if gotAuth != "Bearer BOB" {
		t.Fatalf("upstream Authorization = %q, want %q (the global key must not shadow the owner's)", gotAuth, "Bearer BOB")
	}
}

// TestKeyOwnerNamespaces pins the namespaced key_owner discipline: a
// self-hosted username and a cloud org id live in disjoint namespaces, so a
// username crafted to look like an org id cannot resolve to that org's key.
func TestKeyOwnerNamespaces(t *testing.T) {
	const orgID = "3f2b1c4d-0000-4000-8000-000000000001"

	if got := UserKeyOwner("bob"); got != "user:bob" {
		t.Errorf("UserKeyOwner = %q, want user:bob", got)
	}
	if got := OrgKeyOwner(orgID); got != "org:"+orgID {
		t.Errorf("OrgKeyOwner = %q, want org:%s", got, orgID)
	}
	if UserKeyOwner(orgID) == OrgKeyOwner(orgID) {
		t.Errorf("a username equal to an org id collided with that org: %q", UserKeyOwner(orgID))
	}

	valid := []string{"user:bob", "org:" + orgID, "user:b", "user:bob-1_2.3"}
	for _, v := range valid {
		if err := ValidateKeyOwner(v); err != nil {
			t.Errorf("ValidateKeyOwner(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{"", "bob", "org:", "user:", "tenant:bob", "user:bo b", "user:bob/x", "USER:bob", "user:bob\n"}
	for _, v := range invalid {
		if err := ValidateKeyOwner(v); err == nil {
			t.Errorf("ValidateKeyOwner(%q) = nil, want an error", v)
		}
	}
}

// TestGateway_RevokeByKeyOwner is the "customer removed their key" kill
// switch: every live token for that owner stops on its next call, the other
// owner is untouched, and a legacy token with no key_owner is unaffected.
func TestGateway_RevokeByKeyOwner(t *testing.T) {
	secret := []byte("s")
	up := fakeUpstream(t, func(*http.Request) {}, `{"model":"m","usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	defer up.Close()

	providers := DefaultProviders()
	providers["openai"].UpstreamURL = up.URL
	owners := NewMemOwnerRevocations()
	gw := New(Config{
		Secret:           secret,
		Providers:        providers,
		ProviderKeys:     map[string]string{"openai": "GLOBAL"},
		KeyResolver:      &recordingResolver{keys: map[string]string{"org:a|openai": "A", "org:b|openai": "B"}},
		OwnerRevocations: owners,
	})
	srv := newTestServer(t, gw)

	mint := func(owner string) string {
		t.Helper()
		tok, err := MintToken(secret, GatewayClaims{Tenant: "box", Provider: "openai", KeyOwner: owner}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	call := func(tok string) int {
		t.Helper()
		resp := postModel(t, srv.URL+"/v1/model/openai/v1/chat/completions", tok, `{"model":"m"}`)
		defer resp.Body.Close()
		return resp.StatusCode
	}

	tokA, tokB, tokLegacy := mint("org:a"), mint("org:b"), mint("")
	for name, tok := range map[string]string{"org:a": tokA, "org:b": tokB, "legacy": tokLegacy} {
		if got := call(tok); got != http.StatusOK {
			t.Fatalf("before revocation: %s token got %d, want 200", name, got)
		}
	}

	if err := gw.RevokeByKeyOwner(context.Background(), "org:a", "key removed"); err != nil {
		t.Fatalf("RevokeByKeyOwner: %v", err)
	}
	if got := call(tokA); got != http.StatusUnauthorized {
		t.Errorf("revoked owner's token got %d, want 401", got)
	}
	if got := call(tokB); got != http.StatusOK {
		t.Errorf("other owner's token got %d, want 200 (revocation leaked across owners)", got)
	}
	if got := call(tokLegacy); got != http.StatusOK {
		t.Errorf("legacy token (no key_owner) got %d, want 200", got)
	}
}

// TestGateway_OwnerRevocationCutoff pins the cutoff semantics: a revocation
// kills every token issued at or before the instant it records, and nothing
// after it. That is what lets an owner re-add a key and have freshly minted
// tokens work without an un-revoke verb.
func TestGateway_OwnerRevocationCutoff(t *testing.T) {
	secret := []byte("s")
	up := fakeUpstream(t, func(*http.Request) {}, `{"model":"m","usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	defer up.Close()
	providers := DefaultProviders()
	providers["openai"].UpstreamURL = up.URL

	tests := []struct {
		name       string
		cutoffFrom time.Duration // relative to the token's mint time
		wantStatus int
	}{
		{name: "cutoff after the token was issued kills it", cutoffFrom: 2 * time.Second, wantStatus: http.StatusUnauthorized},
		{name: "cutoff before the token was issued leaves it alone", cutoffFrom: -2 * time.Second, wantStatus: http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			owners := NewMemOwnerRevocations()
			srv := newTestServer(t, New(Config{
				Secret:           secret,
				Providers:        providers,
				ProviderKeys:     map[string]string{"openai": "GLOBAL"},
				OwnerRevocations: owners,
			}))

			minted := time.Now()
			tok, err := MintToken(secret, GatewayClaims{Tenant: "box", Provider: "openai", KeyOwner: "org:a"}, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if err := owners.RevokeOwner(context.Background(), "org:a", minted.Add(tc.cutoffFrom), "test"); err != nil {
				t.Fatal(err)
			}
			resp := postModel(t, srv.URL+"/v1/model/openai/v1/chat/completions", tok, `{"model":"m"}`)
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
		})
	}
}

// erroringOwnerRevocations always fails, standing in for a database outage.
type erroringOwnerRevocations struct{}

func (erroringOwnerRevocations) RevokedBefore(context.Context, string) (time.Time, error) {
	return time.Time{}, errors.New("store down")
}

// TestGateway_OwnerRevocationFailsOpen — an owner-revocation lookup failure
// degrades to the protection that existed before the check, exactly like the
// per-jti list (revocation.go), instead of taking every tenant's model
// traffic down with the database.
func TestGateway_OwnerRevocationFailsOpen(t *testing.T) {
	secret := []byte("s")
	up := fakeUpstream(t, func(*http.Request) {}, `{"model":"m","usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	defer up.Close()
	providers := DefaultProviders()
	providers["openai"].UpstreamURL = up.URL
	srv := newTestServer(t, New(Config{
		Secret:           secret,
		Providers:        providers,
		ProviderKeys:     map[string]string{"openai": "GLOBAL"},
		OwnerRevocations: erroringOwnerRevocations{},
	}))

	tok, _ := MintToken(secret, GatewayClaims{Tenant: "box", Provider: "openai", KeyOwner: "org:a"}, time.Hour)
	resp := postModel(t, srv.URL+"/v1/model/openai/v1/chat/completions", tok, `{"model":"m"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the owner-revocation check must fail open)", resp.StatusCode)
	}
}

// TestGateway_RevokeByKeyOwner_NoStore — an operator who wired no
// owner-revocation store gets a named error, not a silently ignored revoke.
func TestGateway_RevokeByKeyOwner_NoStore(t *testing.T) {
	gw := New(Config{Secret: []byte("s"), Providers: DefaultProviders()})
	if err := gw.RevokeByKeyOwner(context.Background(), "org:a", "x"); err == nil {
		t.Fatal("RevokeByKeyOwner with no store returned nil; want an error")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
