package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Phase 4.1 Phase-C — Google Cloud KMS implementation of
// KMSClient. Audit C-HIGH-6.
//
// Cloud KMS exposes per-key encrypt / decrypt REST
// endpoints; the named CryptoKey is the KEK. The key
// material never leaves Google's HSM-backed boundary —
// the daemon submits the plaintext DEK (base64) and gets
// back an opaque ciphertext blob.
//
// We follow the Vault pattern and talk to the JSON REST
// API directly rather than pulling in the cloud.google.com/
// go/kms SDK. Reasons:
//
//   - The SDK transitive tree is large (gax, grpc, oauth2,
//     metadata, …); govulncheck has to track it all.
//   - Our usage is two endpoints — ~40 lines of HTTP.
//   - Auth is a bearer access token, supplied by the
//     operator the same way the Vault token is. Daemons
//     on GKE/GCE can use a tiny token-refresh sidecar
//     against the metadata server (workload identity);
//     bare-metal can use a static service-account token
//     refreshed by gcloud out-of-band. Either way the
//     daemon only needs the file path.
//
// Wire shape:
//
//   POST <endpoint>/v1/<KEY_NAME>:encrypt
//     Authorization: Bearer <access_token>
//     {"plaintext": "<base64(DEK)>"}
//   →  {"name": "<KEY_NAME>/cryptoKeyVersions/<N>",
//       "ciphertext": "<base64>",
//       "ciphertextCrc32c": "..."}
//
//   POST <endpoint>/v1/<KEY_NAME>:decrypt
//     Authorization: Bearer <access_token>
//     {"ciphertext": "<base64>"}
//   →  {"plaintext": "<base64(DEK)>",
//       "plaintextCrc32c": "..."}
//
// kek_id encodes the full resource name so a row migrated
// under one project / key can't be unwrapped by a daemon
// reconfigured against a different one. GCP's own key
// version is opaque to us (baked into the ciphertext); on
// rotation, decrypt requests for old ciphertext continue
// to succeed automatically.

// GCPConfig configures the GCP Cloud KMS backend.
type GCPConfig struct {
	// KeyName is the full Cloud KMS resource name of the
	// CryptoKey, e.g.
	// "projects/my-proj/locations/us-west1/keyRings/cont/cryptoKeys/secrets".
	// Use the bare CryptoKey (not a CryptoKeyVersion) —
	// encrypt always uses the key's primary version.
	KeyName string

	// Token is the OAuth2 access token used as
	// `Authorization: Bearer`. Operators refresh this
	// out-of-band (workload identity sidecar / gcloud
	// auth print-access-token tee'd to a file / Vault
	// Agent with the gcp secret engine).
	Token string

	// TokenFile, when set, is a path the backend RE-READS before each Cloud
	// KMS call (cached briefly) so an out-of-band refresh sidecar's rotations
	// are honored without restarting the daemon. Takes precedence over Token.
	// Without it, Token is frozen at startup and expires within the hour. #300.
	TokenFile string

	// Endpoint is the Cloud KMS API base URL. Defaults to
	// the public production endpoint; the field exists so
	// tests can point at a httptest.Server and so
	// air-gapped private-endpoint deployments can override.
	Endpoint string

	// Timeout caps every Cloud KMS HTTP call. Default 5s.
	Timeout time.Duration
}

// GCPKMS implements KMSClient against Google Cloud KMS.
type GCPKMS struct {
	cfg    GCPConfig
	client *http.Client
	kekID  string // cached, set in NewGCPKMS

	// tokMu guards the brief token cache used when cfg.TokenFile is set.
	tokMu     sync.Mutex
	cachedTok string
	cachedAt  time.Time
}

// gcpKEKPrefix labels a kek_id as "wrap was done by GCP
// Cloud KMS." Future readers (an operator who migrated
// from GCP to Vault, for instance) refuse rows that don't
// match their backend's prefix.
const gcpKEKPrefix = "gcp:"

// gcpDefaultEndpoint is the public Cloud KMS endpoint.
// Override via GCPConfig.Endpoint for private endpoints
// or test doubles.
const gcpDefaultEndpoint = "https://cloudkms.googleapis.com"

// NewGCPKMS constructs the backend. Validates config shape
// but does NOT call Cloud KMS — the first Wrap / Unwrap
// surfaces a bad token / missing key / network outage as a
// normal Wrap / Unwrap error. Lazy connection mirrors the
// Vault backend so daemon startup can't be blocked by a
// momentarily-unreachable KMS endpoint.
func NewGCPKMS(cfg GCPConfig) (*GCPKMS, error) {
	cfg.KeyName = strings.TrimSpace(cfg.KeyName)
	if cfg.KeyName == "" {
		return nil, errors.New("gcp KMS: key name required")
	}
	// Cheap sanity-check the resource path so a typo
	// surfaces at construction time instead of being
	// surfaced as a generic 400 from Cloud KMS on the
	// first Wrap. The full Google resource grammar is
	// stricter than this — we just want the leading
	// shape to match.
	if !strings.HasPrefix(cfg.KeyName, "projects/") ||
		!strings.Contains(cfg.KeyName, "/cryptoKeys/") {
		return nil, fmt.Errorf("gcp KMS: key name %q is not a CryptoKey resource path (want projects/.../cryptoKeys/...)", cfg.KeyName)
	}
	if cfg.Token == "" && cfg.TokenFile == "" {
		return nil, errors.New("gcp KMS: access token or token file required")
	}
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if cfg.Endpoint == "" {
		cfg.Endpoint = gcpDefaultEndpoint
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	// kek_id is fully determined by the key resource path.
	// Rows wrapped under different keys (or different
	// projects) get distinct kek_ids; cross-deployment
	// confusion is structurally impossible.
	kekID := gcpKEKPrefix + cfg.KeyName
	return &GCPKMS{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		kekID:  kekID,
	}, nil
}

// Wrap encrypts the DEK against the configured CryptoKey.
// Cloud KMS returns an opaque base64 ciphertext we store
// verbatim — like Vault's "vault:v<n>:..." blob it carries
// enough self-description (within the bytes) for decrypt
// to figure out which key version produced it.
func (g *GCPKMS) Wrap(ctx context.Context, plaintextDEK []byte) ([]byte, string, error) {
	if len(plaintextDEK) != DEKSize {
		return nil, "", fmt.Errorf("DEK must be %d bytes; got %d", DEKSize, len(plaintextDEK))
	}
	body := map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(plaintextDEK),
	}
	var resp struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := g.do(ctx, "encrypt", body, &resp); err != nil {
		return nil, "", fmt.Errorf("gcp kms encrypt: %w", err)
	}
	if resp.Ciphertext == "" {
		return nil, "", errors.New("gcp kms encrypt: empty ciphertext in response")
	}
	// We store the base64 ciphertext string verbatim;
	// Unwrap just passes it back to Cloud KMS as the
	// decrypt-request payload. No re-encoding round-trip
	// in the hot path.
	return []byte(resp.Ciphertext), g.kekID, nil
}

// Unwrap reverses Wrap. The kek_id must start with the
// gcp:-prefix; otherwise the row was wrapped by a
// different backend (Vault, InProc, …) and we refuse
// rather than spending a Cloud KMS call on a guaranteed
// mismatch.
func (g *GCPKMS) Unwrap(ctx context.Context, wrappedDEK []byte, kekID string) ([]byte, error) {
	if !strings.HasPrefix(kekID, gcpKEKPrefix) {
		return nil, fmt.Errorf("GCPKMS: refusing to unwrap row whose kek_id=%q (no %q prefix)", kekID, gcpKEKPrefix)
	}
	body := map[string]string{
		"ciphertext": string(wrappedDEK),
	}
	var resp struct {
		Plaintext string `json:"plaintext"`
	}
	if err := g.do(ctx, "decrypt", body, &resp); err != nil {
		return nil, fmt.Errorf("gcp kms decrypt: %w", err)
	}
	dek, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("gcp kms decrypt: base64: %w", err)
	}
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("gcp kms decrypt: DEK has %d bytes; want %d", len(dek), DEKSize)
	}
	return dek, nil
}

// gcpTokenCacheTTL bounds how long a token read from TokenFile is reused before
// re-reading — short enough to pick up a sidecar refresh promptly, long enough
// to avoid a file read on every Cloud KMS call.
const gcpTokenCacheTTL = 30 * time.Second

// token returns the current bearer token. With TokenFile set it re-reads the
// file (cached for gcpTokenCacheTTL) so a refresh sidecar's rotations are
// honored without a daemon restart; otherwise it returns the static Token.
// On a transient read error it serves the last-good token rather than failing.
func (g *GCPKMS) token() (string, error) {
	if g.cfg.TokenFile == "" {
		return g.cfg.Token, nil
	}
	g.tokMu.Lock()
	defer g.tokMu.Unlock()
	if g.cachedTok != "" && time.Since(g.cachedAt) < gcpTokenCacheTTL {
		return g.cachedTok, nil
	}
	// readBearerLikeFile enforces 0600-ish perms + trims + rejects empty —
	// the same defense-in-depth the Vault/AWS token-file paths use.
	tok, err := readBearerLikeFile(g.cfg.TokenFile)
	if err != nil {
		if g.cachedTok != "" {
			return g.cachedTok, nil // serve last-good through a transient read error
		}
		return "", err
	}
	g.cachedTok = tok
	g.cachedAt = time.Now()
	return tok, nil
}

// do POSTs to the encrypt/decrypt endpoint and decodes
// the JSON response. Centralized so error mapping and
// future telemetry sit in one place.
//
// op is "encrypt" or "decrypt"; we suffix it onto the
// CryptoKey resource path with Cloud KMS's `:verb` style.
func (g *GCPKMS) do(ctx context.Context, op string, body, out any) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	url := fmt.Sprintf("%s/v1/%s:%s", g.cfg.Endpoint, g.cfg.KeyName, op)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	tok, err := g.token()
	if err != nil {
		return fmt.Errorf("gcp kms token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		// GCP returns {"error":{"code":N,"message":"..."}}
		// on failure.
		var errResp struct {
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
				Status  string `json:"status"`
			} `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		if errResp.Error.Message != "" {
			return fmt.Errorf("status %d: %s", resp.StatusCode, errResp.Error.Message)
		}
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}
