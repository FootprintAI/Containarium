package app

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestUncoveredSubjects(t *testing.T) {
	zones := []string{"example.com", "other.org"}
	tests := []struct {
		name     string
		subjects []string
		want     []string
	}{
		{"exact zone match is covered", []string{"example.com"}, nil},
		{"subdomain is covered", []string{"app.example.com"}, nil},
		{"wildcard subject is covered by its base zone", []string{"*.example.com"}, nil},
		{"second zone is covered too", []string{"api.other.org"}, nil},
		{"a domain outside every zone is uncovered", []string{"app.unrelated.net"}, []string{"app.unrelated.net"}},
		{"a lookalike suffix is not a real subdomain match", []string{"notexample.com"}, []string{"notexample.com"}},
		{"mixed covered and uncovered", []string{"app.example.com", "app.unrelated.net"}, []string{"app.unrelated.net"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uncoveredSubjects(tt.subjects, zones)
			if len(got) != len(tt.want) {
				t.Fatalf("uncoveredSubjects(%v, %v) = %v, want %v", tt.subjects, zones, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("uncoveredSubjects(%v, %v) = %v, want %v", tt.subjects, zones, got, tt.want)
				}
			}
		})
	}
}

// fakeCloudflareZones returns an httptest.Server standing in for
// Cloudflare's /zones — serves `zones` split across pages of at most
// `pageSize` each (page/per_page query params), so pagination is exercised
// the same way it would be against a real multi-zone account.
func fakeCloudflareZones(t *testing.T, wantToken string, zones []string, pageSize int) *httptest.Server {
	t.Helper()
	totalPages := (len(zones) + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+wantToken {
			t.Errorf("Authorization header = %q, want Bearer %s", got, wantToken)
		}
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			_, _ = fmt.Sscanf(p, "%d", &page)
		}
		start := (page - 1) * pageSize
		end := start + pageSize
		if start > len(zones) {
			start = len(zones)
		}
		if end > len(zones) {
			end = len(zones)
		}
		type zoneObj struct {
			Name string `json:"name"`
		}
		resp := struct {
			Success    bool      `json:"success"`
			Result     []zoneObj `json:"result"`
			ResultInfo struct {
				Page       int `json:"page"`
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}{Success: true}
		for _, z := range zones[start:end] {
			resp.Result = append(resp.Result, zoneObj{Name: z})
		}
		resp.ResultInfo.Page = page
		resp.ResultInfo.TotalPages = totalPages
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func withFakeCloudflareZonesURL(t *testing.T, url string) {
	t.Helper()
	original := cloudflareZonesListURL
	cloudflareZonesListURL = url
	t.Cleanup(func() { cloudflareZonesListURL = original })
}

func TestVerifyDNSProviderZoneCoverage_FullyCovered(t *testing.T) {
	srv := fakeCloudflareZones(t, "good-token", []string{"example.com"}, 50)
	withFakeCloudflareZonesURL(t, srv.URL)
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")

	attempted, uncovered, err := VerifyDNSProviderZoneCoverage(context.Background(), "cloudflare",
		map[string]string{"CF_API_TOKEN": "good-token"}, []string{"app.example.com", "*.example.com"})
	if !attempted {
		t.Fatal("attempted = false, want true")
	}
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(uncovered) != 0 {
		t.Errorf("uncovered = %v, want none — both subjects fall under the returned zone", uncovered)
	}
}

func TestVerifyDNSProviderZoneCoverage_UncoveredSubjectWarns(t *testing.T) {
	srv := fakeCloudflareZones(t, "good-token", []string{"example.com"}, 50)
	withFakeCloudflareZonesURL(t, srv.URL)
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")

	attempted, uncovered, err := VerifyDNSProviderZoneCoverage(context.Background(), "cloudflare",
		map[string]string{"CF_API_TOKEN": "good-token"}, []string{"app.other-domain.net"})
	if !attempted {
		t.Fatal("attempted = false, want true")
	}
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(uncovered) != 1 || uncovered[0] != "app.other-domain.net" {
		t.Errorf("uncovered = %v, want [app.other-domain.net]", uncovered)
	}
}

func TestVerifyDNSProviderZoneCoverage_Paginates(t *testing.T) {
	zones := []string{"a.com", "b.com", "c.com", "d.com", "e.com"}
	srv := fakeCloudflareZones(t, "good-token", zones, 2) // forces 3 pages
	withFakeCloudflareZonesURL(t, srv.URL)
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")

	attempted, uncovered, err := VerifyDNSProviderZoneCoverage(context.Background(), "cloudflare",
		map[string]string{"CF_API_TOKEN": "good-token"}, []string{"app.e.com"})
	if !attempted {
		t.Fatal("attempted = false, want true")
	}
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(uncovered) != 0 {
		t.Errorf("uncovered = %v, want none — e.com is on the last page and pagination must reach it", uncovered)
	}
}

func TestVerifyDNSProviderZoneCoverage_NothingResolvedIsNotAttempted(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")

	attempted, uncovered, err := VerifyDNSProviderZoneCoverage(context.Background(), "cloudflare",
		map[string]string{}, []string{"app.example.com"})
	if attempted {
		t.Error("attempted = true, want false — nothing resolved to check with")
	}
	if uncovered != nil || err != nil {
		t.Errorf("uncovered = %v, err = %v, want nil, nil", uncovered, err)
	}
}

func TestVerifyDNSProviderZoneCoverage_NoSubjectsIsNotAttempted(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")

	attempted, uncovered, err := VerifyDNSProviderZoneCoverage(context.Background(), "cloudflare",
		map[string]string{"CF_API_TOKEN": "good-token"}, nil)
	if attempted {
		t.Error("attempted = true, want false — no subjects to check")
	}
	if uncovered != nil || err != nil {
		t.Errorf("uncovered = %v, err = %v, want nil, nil", uncovered, err)
	}
}

func TestVerifyDNSProviderZoneCoverage_UnknownProviderIsNotAttempted(t *testing.T) {
	attempted, uncovered, err := VerifyDNSProviderZoneCoverage(context.Background(), "route53",
		map[string]string{"AWS_ACCESS_KEY_ID": "whatever"}, []string{"app.example.com"})
	if attempted {
		t.Error("attempted = true, want false — no zone-listing call registered for route53")
	}
	if uncovered != nil || err != nil {
		t.Errorf("uncovered = %v, err = %v, want nil, nil", uncovered, err)
	}
}
