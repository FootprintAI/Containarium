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
	"time"
)

// Phase 4.1 Phase-F — Vault Transit implementation of
// KMSClient. Audit C-HIGH-6.
//
// Vault's Transit secret engine is a textbook envelope-
// encryption backend: each named transit key is a
// KMS-resident Key Encryption Key (KEK), and the engine
// exposes encrypt / decrypt endpoints that take a base64
// plaintext (our DEK) and return ciphertext (the wrapped
// DEK). The bare KEK never leaves Vault.
//
// We deliberately avoid the Vault Go SDK and talk to the
// HTTP API directly. Reasons:
//
//   - The SDK transitive tree is large (sdk, logical
//     backends, etc.). Our usage is two endpoints.
//   - The HTTP shape is stable and small; rolling our
//     own is ~50 lines.
//   - One fewer dependency to track in govulncheck.
//
// Wire shape:
//
//   POST <addr>/v1/<mount>/encrypt/<key>
//     {"plaintext": "<base64(DEK)>"}
//   →  {"data": {"ciphertext": "vault:v<n>:<base64-blob>"}}
//
//   POST <addr>/v1/<mount>/decrypt/<key>
//     {"ciphertext": "vault:v<n>:<base64-blob>"}
//   →  {"data": {"plaintext": "<base64(DEK)>"}}
//
// kek_id encodes the address + mount + key so a row
// migrated under one Vault deployment can't accidentally
// be unwrapped by a different one. Vault's own key
// versioning rides in the ciphertext prefix ("v<n>"), so
// rotation at the Vault end is transparent.

// VaultConfig configures the Vault Transit backend.
type VaultConfig struct {
	// Address is the Vault API base URL, e.g.
	// "https://vault.internal:8200".
	Address string

	// Token is the static auth token used on every
	// request. For long-lived daemons, prefer a token
	// from Vault Agent (which auto-renews); for short
	// CLI invocations a one-shot operator token is
	// fine.
	Token string

	// Mount is the Transit engine mount path, default
	// "transit".
	Mount string

	// KeyName is the named Transit key the daemon wraps
	// against. Must already exist in Vault — the
	// operator creates it with `vault write -f
	// transit/keys/<name>` as part of deployment setup.
	KeyName string

	// Timeout caps every Vault HTTP call. Default 5s.
	Timeout time.Duration
}

// VaultKMS implements KMSClient against Vault Transit.
type VaultKMS struct {
	cfg    VaultConfig
	client *http.Client
	kekID  string // cached, set in NewVaultKMS
}

// vaultKEKPrefix labels a kek_id as "wrap was done by
// Vault Transit." Future readers (a daemon swapped to GCP
// KMS, for instance) can match this prefix and refuse to
// even attempt decryption.
const vaultKEKPrefix = "vault:"

// NewVaultKMS constructs the backend. Validates the config
// shape but does NOT call Vault yet — the first Wrap /
// Unwrap surfaces a misconfigured server, network outage,
// missing key, or bad token as a normal Wrap / Unwrap
// error. Lazy connection means daemon startup can't be
// blocked by a momentarily-unreachable Vault.
func NewVaultKMS(cfg VaultConfig) (*VaultKMS, error) {
	cfg.Address = strings.TrimRight(strings.TrimSpace(cfg.Address), "/")
	if cfg.Address == "" {
		return nil, errors.New("vault KMS: address required")
	}
	if cfg.Token == "" {
		return nil, errors.New("vault KMS: token required")
	}
	if cfg.Mount == "" {
		cfg.Mount = "transit"
	}
	if cfg.KeyName == "" {
		return nil, errors.New("vault KMS: key name required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	// kek_id is fully determined by config — encoding
	// address + mount + key. A row's kek_id ties it to a
	// specific Vault deployment + key so a daemon
	// reconfigured against a different cluster can't
	// silently mis-decrypt.
	kekID := fmt.Sprintf("%s%s|%s|%s", vaultKEKPrefix, cfg.Address, cfg.Mount, cfg.KeyName)
	return &VaultKMS{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		kekID:  kekID,
	}, nil
}

// Wrap encrypts the DEK against the named Transit key.
// Vault returns a self-describing ciphertext blob
// ("vault:v1:..."); we store it directly as wrapped_dek.
// kek_id reflects the deployment + key for cross-cluster
// safety.
func (v *VaultKMS) Wrap(ctx context.Context, plaintextDEK []byte) ([]byte, string, error) {
	if len(plaintextDEK) != DEKSize {
		return nil, "", fmt.Errorf("DEK must be %d bytes; got %d", DEKSize, len(plaintextDEK))
	}
	body := map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(plaintextDEK),
	}
	var resp struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := v.do(ctx, "encrypt", body, &resp); err != nil {
		return nil, "", fmt.Errorf("vault encrypt: %w", err)
	}
	if !strings.HasPrefix(resp.Data.Ciphertext, "vault:v") {
		return nil, "", fmt.Errorf("vault encrypt: unexpected ciphertext shape %q", resp.Data.Ciphertext)
	}
	return []byte(resp.Data.Ciphertext), v.kekID, nil
}

// Unwrap reverses Wrap. The kek_id must start with the
// vault:-prefix; otherwise the row was wrapped by a
// different backend (InProc, GCP KMS, …) and we refuse.
func (v *VaultKMS) Unwrap(ctx context.Context, wrappedDEK []byte, kekID string) ([]byte, error) {
	if !strings.HasPrefix(kekID, vaultKEKPrefix) {
		return nil, fmt.Errorf("VaultKMS: refusing to unwrap row whose kek_id=%q (no %q prefix)", kekID, vaultKEKPrefix)
	}
	// Vault rotation tolerance: a row wrapped against an
	// older key version still has the version baked into
	// its ciphertext prefix ("vault:v<n>:..."), and Vault
	// transparently decrypts. We only require the kek_id
	// prefix to match; the version isn't compared.
	body := map[string]string{
		"ciphertext": string(wrappedDEK),
	}
	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := v.do(ctx, "decrypt", body, &resp); err != nil {
		return nil, fmt.Errorf("vault decrypt: %w", err)
	}
	dek, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("vault decrypt: base64: %w", err)
	}
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("vault decrypt: DEK has %d bytes; want %d", len(dek), DEKSize)
	}
	return dek, nil
}

// do POSTs to the encrypt/decrypt endpoint and decodes the
// JSON response. Centralized so retry, error mapping, and
// future telemetry sit in one place.
func (v *VaultKMS) do(ctx context.Context, op string, body, out any) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	url := fmt.Sprintf("%s/v1/%s/%s/%s",
		v.cfg.Address, v.cfg.Mount, op, v.cfg.KeyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", v.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		// Vault returns an "errors" array on failure.
		var errResp struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		if len(errResp.Errors) > 0 {
			return fmt.Errorf("status %d: %s", resp.StatusCode, strings.Join(errResp.Errors, "; "))
		}
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}
