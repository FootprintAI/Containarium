package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #1739 — a credential can be present, non-empty, and correctly propagated
// to Caddy (#1738) and still be revoked, expired, or simply wrong. These
// tests exercise the verifier against a fake Cloudflare server, never the
// real API.

func TestResolvedProviderField(t *testing.T) {
	t.Run("nil challenge → empty", func(t *testing.T) {
		if got := resolvedProviderField(nil, "api_token", nil); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("placeholder resolved from envVars", func(t *testing.T) {
		dns := &CaddyACMEChallenges{DNS: &CaddyDNSChallenge{Provider: map[string]interface{}{
			"name": "cloudflare", "api_token": "{env.CF_API_TOKEN}",
		}}}
		got := resolvedProviderField(dns, "api_token", map[string]string{"CF_API_TOKEN": "real-token"})
		if got != "real-token" {
			t.Errorf("got %q, want real-token", got)
		}
	})

	t.Run("placeholder with nothing resolved → empty", func(t *testing.T) {
		dns := &CaddyACMEChallenges{DNS: &CaddyDNSChallenge{Provider: map[string]interface{}{
			"api_token": "{env.CF_API_TOKEN}",
		}}}
		got := resolvedProviderField(dns, "api_token", map[string]string{})
		if got != "" {
			t.Errorf("got %q, want empty — CF_API_TOKEN never resolved", got)
		}
	})

	t.Run("literal (non-placeholder) value returned as-is", func(t *testing.T) {
		dns := &CaddyACMEChallenges{DNS: &CaddyDNSChallenge{Provider: map[string]interface{}{
			"api_token": "literal-token-set-via-json-config",
		}}}
		got := resolvedProviderField(dns, "api_token", nil)
		if got != "literal-token-set-via-json-config" {
			t.Errorf("got %q, want the literal value unchanged", got)
		}
	})

	t.Run("field not present → empty", func(t *testing.T) {
		dns := &CaddyACMEChallenges{DNS: &CaddyDNSChallenge{Provider: map[string]interface{}{"name": "cloudflare"}}}
		if got := resolvedProviderField(dns, "api_token", nil); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

// fakeCloudflareVerify returns an httptest.Server standing in for
// Cloudflare's /user/tokens/verify — asserts the Bearer header carries
// exactly the token under test and responds with the given success/error
// shape.
func fakeCloudflareVerify(t *testing.T, wantToken string, success bool, errCode int, errMsg string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if got != "Bearer "+wantToken {
			t.Errorf("Authorization header = %q, want Bearer %s", got, wantToken)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := struct {
			Success bool `json:"success"`
			Errors  []struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		}{Success: success}
		if !success {
			resp.Errors = append(resp.Errors, struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}{Code: errCode, Message: errMsg})
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func withFakeCloudflareURL(t *testing.T, url string) {
	t.Helper()
	original := cloudflareTokenVerifyURL
	cloudflareTokenVerifyURL = url
	t.Cleanup(func() { cloudflareTokenVerifyURL = original })
}

func TestVerifyDNSProviderCredential_CloudflareAccepted(t *testing.T) {
	srv := fakeCloudflareVerify(t, "good-token", true, 0, "")
	withFakeCloudflareURL(t, srv.URL)
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")

	attempted, err := VerifyDNSProviderCredential(context.Background(), "cloudflare",
		map[string]string{"CF_API_TOKEN": "good-token"})
	if !attempted {
		t.Fatal("attempted = false, want true — a cloudflare verifier exists")
	}
	if err != nil {
		t.Errorf("err = %v, want nil for an accepted token", err)
	}
}

func TestVerifyDNSProviderCredential_CloudflareRejected(t *testing.T) {
	srv := fakeCloudflareVerify(t, "bad-token", false, 1000, "Invalid API Token")
	withFakeCloudflareURL(t, srv.URL)
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")

	attempted, err := VerifyDNSProviderCredential(context.Background(), "cloudflare",
		map[string]string{"CF_API_TOKEN": "bad-token"})
	if !attempted {
		t.Fatal("attempted = false, want true")
	}
	if err == nil {
		t.Fatal("err = nil, want a rejection error")
	}
	if !strings.Contains(err.Error(), "Invalid API Token") {
		t.Errorf("err = %v, want it to carry cloudflare's own message", err)
	}
}

func TestVerifyDNSProviderCredential_NothingResolvedIsNotAttempted(t *testing.T) {
	// #1738 already reports this case (missing credential) — the verifier
	// must not ALSO fire a network call against an empty token.
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")

	attempted, err := VerifyDNSProviderCredential(context.Background(), "cloudflare", map[string]string{})
	if attempted {
		t.Error("attempted = true, want false — nothing resolved to verify")
	}
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestVerifyDNSProviderCredential_UnknownProviderIsNotAttempted(t *testing.T) {
	// route53 (and every other caddy-dns provider without a built-in
	// verifier) degrades gracefully — not attempted, not an error.
	attempted, err := VerifyDNSProviderCredential(context.Background(), "route53",
		map[string]string{"AWS_ACCESS_KEY_ID": "whatever"})
	if attempted {
		t.Error("attempted = true, want false — no verifier registered for route53")
	}
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}
