package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func dnsChallengeForTest() *CaddyACMEChallenges {
	return &CaddyACMEChallenges{DNS: &CaddyDNSChallenge{Provider: map[string]interface{}{"name": "cloudflare"}}}
}

func TestHasDNSChallenge(t *testing.T) {
	pm := NewProxyManager("http://127.0.0.1:2019", "example.com")
	if pm.HasDNSChallenge() {
		t.Error("expected HasDNSChallenge=false before WithDNSChallenge")
	}
	pm.WithDNSChallenge(dnsChallengeForTest())
	if !pm.HasDNSChallenge() {
		t.Error("expected HasDNSChallenge=true after WithDNSChallenge")
	}
	pm.WithDNSChallenge(nil)
	if pm.HasDNSChallenge() {
		t.Error("expected HasDNSChallenge=false after WithDNSChallenge(nil)")
	}
}

func TestProvisionWildcardTLS_RequiresDNS01(t *testing.T) {
	// No DNS-01 → error, and no HTTP call is made (fails before any request).
	pm := NewProxyManager("http://127.0.0.1:1", "example.com") // unroutable; must not be dialed
	err := pm.ProvisionWildcardTLS()
	if err == nil || !strings.Contains(err.Error(), "DNS-01") {
		t.Fatalf("expected a DNS-01-required error, got %v", err)
	}
}

func TestProvisionWildcardTLS_RequiresBaseDomain(t *testing.T) {
	pm := NewProxyManager("http://127.0.0.1:1", "").WithDNSChallenge(dnsChallengeForTest())
	err := pm.ProvisionWildcardTLS()
	if err == nil || !strings.Contains(err.Error(), "base domain") {
		t.Fatalf("expected a base-domain-required error, got %v", err)
	}
}

func TestProvisionWildcardTLS_AddsWildcardSubjectViaDNS01(t *testing.T) {
	var postedPolicies []CaddyTLSAutomationPolicy
	posted := false

	mux := http.NewServeMux()
	// ensureTLSApp probes the tls app — return a present (non-null) app so it
	// doesn't try to create one.
	mux.HandleFunc("/config/apps/tls", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"automation":{"policies":[]}}`)
	})
	// ProvisionTLS reads then writes the automation policies.
	mux.HandleFunc("/config/apps/tls/automation/policies", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `[]`) // no existing policies → POST a new one
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &postedPolicies); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			posted = true
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	pm := NewProxyManager(srv.URL, "example.com").WithDNSChallenge(dnsChallengeForTest())
	if err := pm.ProvisionWildcardTLS(); err != nil {
		t.Fatalf("ProvisionWildcardTLS: %v", err)
	}

	if !posted || len(postedPolicies) != 1 {
		t.Fatalf("expected one policy POSTed, got posted=%v policies=%d", posted, len(postedPolicies))
	}
	// The subject must be the wildcard for the base domain.
	subjects := postedPolicies[0].Subjects
	if len(subjects) != 1 || subjects[0] != "*.example.com" {
		t.Errorf("expected subjects [*.example.com], got %v", subjects)
	}
	// And the issuers must carry the DNS-01 challenge (not plain HTTP-01).
	foundDNS := false
	for _, iss := range postedPolicies[0].Issuers {
		if iss.Challenges != nil && iss.Challenges.DNS != nil {
			foundDNS = true
		}
	}
	if !foundDNS {
		t.Error("expected the wildcard policy's issuers to carry a DNS-01 challenge")
	}
}
