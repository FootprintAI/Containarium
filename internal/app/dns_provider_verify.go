package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
