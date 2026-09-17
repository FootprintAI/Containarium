package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// #1739 — split out of #1597 once #1738 fixed the more foundational half (the
// credential never reaching Caddy's process environment at all). A
// credential can be present, non-empty, and correctly propagated (#1738) and
// still be revoked, expired, or simply wrong — this authenticates it against
// the provider's own API before any DNS-01 challenge is ever attempted.
//
// Only cloudflare has a verifier today, matching DNSChallengeFromEnv's own
// cloudflare-specific defaulting. Any other provider name is a deliberate
// no-op (see VerifyDNSProviderCredential) rather than a hard requirement —
// verification is a nice-to-have layered on top of #1738's propagation fix,
// not something every caddy-dns provider needs before this is useful.

// cloudflareTokenVerifyURL is Cloudflare's token-introspection endpoint — the
// credential's own issuer confirms whether it's even accepted. A var, not a
// const, so tests can point it at a fake server instead of the real API.
var cloudflareTokenVerifyURL = "https://api.cloudflare.com/client/v4/user/tokens/verify" // #nosec G101 -- a public API endpoint URL, not a credential value

// resolvedProviderField returns the DNS-01 provider config's `field` value
// with a `{env.VAR}` placeholder substituted from envVars (empty if that
// variable didn't resolve — already reported by caddyDNSProviderEnv's
// missing-credential check). A literal, non-placeholder value — an operator
// can set an explicit token via CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG
// instead of a placeholder — is returned as-is.
func resolvedProviderField(dns *CaddyACMEChallenges, field string, envVars map[string]string) string {
	if dns == nil || dns.DNS == nil {
		return ""
	}
	v, ok := dns.DNS.Provider[field]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	if m := envPlaceholderPattern.FindStringSubmatch(s); m != nil {
		return envVars[m[1]]
	}
	return s
}

// VerifyDNSProviderCredential authenticates the resolved DNS-01 credential
// for `provider` against the provider's own API, using `envVars` (as
// resolved by caddyDNSProviderEnv in internal/server) to fill in any
// `{env.VAR}` placeholder.
//
// attempted is false when there's no built-in verifier for this provider
// name, or nothing resolved to check — distinct from a verified-but-invalid
// credential (attempted=true, err!=nil): "not verified" isn't "rejected".
func VerifyDNSProviderCredential(ctx context.Context, provider string, envVars map[string]string) (attempted bool, err error) {
	switch provider {
	case "cloudflare":
		token := resolvedProviderField(DNSChallengeFromEnv(), "api_token", envVars)
		if token == "" {
			return false, nil
		}
		return true, verifyCloudflareToken(ctx, token)
	default:
		return false, nil
	}
}

// verifyCloudflareToken calls Cloudflare's token-verify endpoint. Returns
// nil only when Cloudflare itself confirms the token is active.
func verifyCloudflareToken(ctx context.Context, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudflareTokenVerifyURL, nil)
	if err != nil {
		return fmt.Errorf("building token-verify request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("token-verify request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding token-verify response (status %d): %w", resp.StatusCode, err)
	}
	if result.Success {
		return nil
	}
	if len(result.Errors) > 0 {
		return fmt.Errorf("token rejected: %s (code %d)", result.Errors[0].Message, result.Errors[0].Code)
	}
	return fmt.Errorf("token rejected (HTTP %d)", resp.StatusCode)
}

// cloudflareZonesListURL is Cloudflare's zone-listing endpoint — a var (not a
// const) so tests can point it at a fake server instead of the real API.
var cloudflareZonesListURL = "https://api.cloudflare.com/client/v4/zones"

// VerifyDNSProviderZoneCoverage checks that every domain in `subjects` falls
// under a zone the resolved credential can actually see, for providers with a
// built-in zone-listing call (#1739's remaining "zones sufficient" half — the
// check that distinguishes "token has the wrong scope for this zone" from
// "there is no token at all", which a bare presence/validity check cannot
// tell apart: a credential can be present, non-empty, and even confirmed
// active by VerifyDNSProviderCredential, and still be scoped to zones that
// don't include the one a subject actually needs).
//
// attempted follows VerifyDNSProviderCredential's convention: false when
// there's no built-in zone check for this provider, or nothing resolved to
// check against. uncovered lists exactly the subjects (verbatim, including
// any leading "*.") that no returned zone covers.
func VerifyDNSProviderZoneCoverage(ctx context.Context, provider string, envVars map[string]string, subjects []string) (attempted bool, uncovered []string, err error) {
	switch provider {
	case "cloudflare":
		token := resolvedProviderField(DNSChallengeFromEnv(), "api_token", envVars)
		if token == "" || len(subjects) == 0 {
			return false, nil, nil
		}
		zones, err := listCloudflareZones(ctx, token)
		if err != nil {
			return true, nil, err
		}
		return true, uncoveredSubjects(subjects, zones), nil
	default:
		return false, nil, nil
	}
}

// uncoveredSubjects returns the subjects that no zone name covers. A zone
// covers a subject when the subject equals the zone or is one or more labels
// under it — the same suffix relation as a Cloudflare zone's actual DNS
// authority, so "app.example.com" and the wildcard "*.example.com" are both
// covered by the zone "example.com".
func uncoveredSubjects(subjects, zones []string) []string {
	var uncovered []string
	for _, s := range subjects {
		covered := false
		for _, z := range zones {
			if s == z || strings.HasSuffix(s, "."+z) {
				covered = true
				break
			}
		}
		if !covered {
			uncovered = append(uncovered, s)
		}
	}
	return uncovered
}

// listCloudflareZones returns every zone name visible to token, paginating
// through Cloudflare's /zones endpoint (default page size caps at 20; an
// account with more zones than that would otherwise silently see coverage
// checked against only the first page).
func listCloudflareZones(ctx context.Context, token string) ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	var zones []string
	for page := 1; ; page++ {
		url := fmt.Sprintf("%s?page=%d&per_page=50", cloudflareZonesListURL, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("building zones-list request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("zones-list request failed: %w", err)
		}
		var result struct {
			Success bool `json:"success"`
			Result  []struct {
				Name string `json:"name"`
			} `json:"result"`
			ResultInfo struct {
				Page       int `json:"page"`
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
			Errors []struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&result)
		statusCode := resp.StatusCode
		_ = resp.Body.Close()
		if decErr != nil {
			return nil, fmt.Errorf("decoding zones-list response (status %d): %w", statusCode, decErr)
		}
		if !result.Success {
			if len(result.Errors) > 0 {
				return nil, fmt.Errorf("zones list rejected: %s (code %d)", result.Errors[0].Message, result.Errors[0].Code)
			}
			return nil, fmt.Errorf("zones list rejected (HTTP %d)", statusCode)
		}
		for _, z := range result.Result {
			zones = append(zones, z.Name)
		}
		if len(result.Result) == 0 || result.ResultInfo.TotalPages <= page {
			break
		}
	}
	return zones, nil
}

// warnUncoveredDNSZones checks `subjects` against the configured DNS-01
// provider's own zone list and logs one WARNING per subject no zone covers
// (#1739's zone-coverage half — the check that distinguishes "token has the
// wrong scope for this zone" from "there is no token at all").
//
// Reads the provider config fresh from the daemon's own environment via
// DNSChallengeFromEnv/DNSProviderFromEnv, the same convention
// verifyDNSProviderCredential (internal/server/core_services.go) already
// uses for the sibling credential-validity check — rather than trust a
// *CaddyACMEChallenges the caller happens to be holding, which could be a
// stale snapshot from before the daemon's environment or config changed.
//
// Called only from EnsureTLSSubjects's already-reconciling-something branch
// (subjects newly missing from Caddy's TLS policies), not on every
// steady-state tick — a live provider API call is too costly to run on
// EnsureTLSSubjects's 5-second-default no-op path, and the whole point of
// this check is to catch a scope problem before Caddy ever attempts the new
// subject, not to continuously re-poll ones that already resolved fine.
func warnUncoveredDNSZones(subjects []string) {
	if len(subjects) == 0 {
		return
	}
	dns := DNSChallengeFromEnv()
	provider := DNSProviderFromEnv()
	if dns == nil || provider == "" {
		return
	}
	envVars := make(map[string]string)
	for _, name := range EnvPlaceholdersInDNSProvider(dns) {
		if v := os.Getenv(name); v != "" {
			envVars[name] = v
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	attempted, uncovered, err := VerifyDNSProviderZoneCoverage(ctx, provider, envVars, subjects)
	if !attempted {
		return // no built-in zone check for this provider, or nothing resolved to check with
	}
	if err != nil {
		log.Printf("WARNING: could not check DNS-01 provider %q's zone coverage for %v: %v (#1739)",
			provider, subjects, err)
		return
	}
	for _, s := range uncovered {
		log.Printf("WARNING: DNS-01 provider %q's credential has no zone covering %q — DNS-01 issuance "+
			"for this subject will fail, reading like a token-scope problem, until the token's zone "+
			"permissions include it (#1739)", provider, s)
	}
}
