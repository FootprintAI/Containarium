package secrets

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Phase 4.1 Phase-C — AWS KMS implementation of KMSClient.
// Audit C-HIGH-6.
//
// AWS KMS exposes Encrypt / Decrypt JSON actions on a
// single regional endpoint; the named key (id, ARN, or
// alias) is the KEK. The key material never leaves AWS's
// HSM-backed boundary — the daemon submits the plaintext
// DEK (base64) and gets back an opaque CiphertextBlob.
//
// We follow the Vault / GCP pattern and talk to the JSON
// REST API directly rather than pulling in aws-sdk-go-v2.
// Reasons:
//
//   - The SDK transitive tree is large (smithy, the whole
//     service-client codegen, the credential-provider
//     chain, …); govulncheck has to track it all, and it
//     dwarfs the rest of this repo's dependency surface.
//   - Our usage is two actions — Encrypt and Decrypt.
//   - The one thing the SDK really buys you is SigV4
//     request signing and the credential chain. SigV4 is
//     ~60 lines of HMAC-SHA256 (below); credentials are
//     supplied by the operator the same way the Vault
//     token and the GCP access token are. Daemons on EC2 /
//     EKS can run a tiny sidecar that refreshes IMDS /
//     IRSA credentials into the env or a file; bare-metal
//     uses a static IAM user. Either way the daemon only
//     needs the access-key / secret pair (+ optional
//     session token for STS temp creds).
//
// Wire shape (AWS JSON 1.1, "TrentService" is KMS's
// internal name):
//
//   POST https://kms.<region>.amazonaws.com/
//     X-Amz-Target: TrentService.Encrypt
//     Authorization: AWS4-HMAC-SHA256 Credential=... Signature=...
//     {"KeyId": "<key>", "Plaintext": "<base64(DEK)>"}
//   →  {"KeyId": "<arn>", "CiphertextBlob": "<base64>"}
//
//   POST https://kms.<region>.amazonaws.com/
//     X-Amz-Target: TrentService.Decrypt
//     {"KeyId": "<key>", "CiphertextBlob": "<base64>"}
//   →  {"KeyId": "<arn>", "Plaintext": "<base64(DEK)>"}
//
// kek_id encodes the region + configured key id so a row
// migrated under one account / key / region can't be
// unwrapped by a daemon reconfigured against a different
// one. AWS's own key rotation is transparent: the key
// version that produced a CiphertextBlob is baked into the
// blob, so Decrypt for old ciphertext keeps succeeding.

// AWSConfig configures the AWS KMS backend.
type AWSConfig struct {
	// Region is the AWS region of the KMS key, e.g.
	// "us-west-2". Used for the endpoint host and the
	// SigV4 credential scope.
	Region string

	// KeyID identifies the KMS key used as the KEK. Accepts
	// any form AWS accepts on Encrypt: a key id
	// ("1234abcd-..."), a full ARN
	// ("arn:aws:kms:us-west-2:111122223333:key/..."), an
	// alias name ("alias/containarium-secrets"), or an
	// alias ARN. Encrypt always uses the key's current
	// rotation; the daemon never pins a version.
	KeyID string

	// AccessKeyID is the AWS access key id (not secret).
	AccessKeyID string

	// SecretAccessKey is the AWS secret access key. Operators
	// refresh this out-of-band (IRSA / IMDS sidecar tee'd to
	// a file, a static IAM user, or Vault's aws secret
	// engine).
	SecretAccessKey string

	// SessionToken is the STS session token, set only when
	// the credentials are temporary (assume-role / IRSA /
	// IMDS). Empty for a static IAM user. When present it is
	// sent as X-Amz-Security-Token and folded into the
	// SigV4 signed headers.
	SessionToken string

	// Endpoint is the KMS API base URL. Defaults to the
	// public regional endpoint; the field exists so tests
	// can point at a httptest.Server and so VPC-endpoint /
	// air-gapped deployments can override.
	Endpoint string

	// Timeout caps every KMS HTTP call. Default 5s.
	Timeout time.Duration
}

// AWSKMS implements KMSClient against AWS KMS.
type AWSKMS struct {
	cfg    AWSConfig
	client *http.Client
	kekID  string // cached, set in NewAWSKMS
}

// awsKEKPrefix labels a kek_id as "wrap was done by AWS
// KMS." Future readers (a daemon swapped to Vault or GCP,
// for instance) match this prefix and refuse to even
// attempt decryption of a non-matching row.
const awsKEKPrefix = "aws:"

// awsKMSService is the SigV4 service name for KMS. Used in
// both the endpoint host and the credential scope.
const awsKMSService = "kms"

// awsJSONContentType is the AWS JSON 1.1 protocol content
// type KMS expects.
const awsJSONContentType = "application/x-amz-json-1.1"

// NewAWSKMS constructs the backend. Validates config shape
// but does NOT call AWS — the first Wrap / Unwrap surfaces a
// bad credential / missing key / network outage as a normal
// Wrap / Unwrap error. Lazy connection mirrors the Vault and
// GCP backends so daemon startup can't be blocked by a
// momentarily-unreachable endpoint.
func NewAWSKMS(cfg AWSConfig) (*AWSKMS, error) {
	cfg.Region = strings.TrimSpace(cfg.Region)
	if cfg.Region == "" {
		return nil, errors.New("aws KMS: region required")
	}
	cfg.KeyID = strings.TrimSpace(cfg.KeyID)
	if cfg.KeyID == "" {
		return nil, errors.New("aws KMS: key id required")
	}
	cfg.AccessKeyID = strings.TrimSpace(cfg.AccessKeyID)
	if cfg.AccessKeyID == "" {
		return nil, errors.New("aws KMS: access key id required")
	}
	if cfg.SecretAccessKey == "" {
		return nil, errors.New("aws KMS: secret access key required")
	}
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if cfg.Endpoint == "" {
		cfg.Endpoint = fmt.Sprintf("https://kms.%s.amazonaws.com", cfg.Region)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	// kek_id is fully determined by region + configured key
	// id. Rows wrapped under different keys / regions get
	// distinct kek_ids; cross-deployment confusion is
	// structurally impossible. We encode the configured key
	// id (not the ARN echoed back by AWS) so the value is
	// deterministic from config alone — matching how Vault
	// and GCP encode their kek_ids.
	kekID := fmt.Sprintf("%s%s|%s", awsKEKPrefix, cfg.Region, cfg.KeyID)
	return &AWSKMS{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		kekID:  kekID,
	}, nil
}

// Wrap encrypts the DEK against the configured KMS key.
// AWS returns an opaque base64 CiphertextBlob we store
// verbatim as wrapped_dek; it self-describes the key version
// for Decrypt. kek_id reflects the region + key for
// cross-deployment safety.
func (a *AWSKMS) Wrap(ctx context.Context, plaintextDEK []byte) ([]byte, string, error) {
	if len(plaintextDEK) != DEKSize {
		return nil, "", fmt.Errorf("DEK must be %d bytes; got %d", DEKSize, len(plaintextDEK))
	}
	body := map[string]string{
		"KeyId":     a.cfg.KeyID,
		"Plaintext": base64.StdEncoding.EncodeToString(plaintextDEK),
	}
	var resp struct {
		CiphertextBlob string `json:"CiphertextBlob"`
	}
	if err := a.do(ctx, "TrentService.Encrypt", body, &resp); err != nil {
		return nil, "", fmt.Errorf("aws kms encrypt: %w", err)
	}
	if resp.CiphertextBlob == "" {
		return nil, "", errors.New("aws kms encrypt: empty CiphertextBlob in response")
	}
	// Store the base64 blob verbatim; Unwrap passes it
	// straight back to KMS as the Decrypt payload. No
	// re-encoding round-trip in the hot path.
	return []byte(resp.CiphertextBlob), a.kekID, nil
}

// Unwrap reverses Wrap. The kek_id must start with the
// aws:-prefix; otherwise the row was wrapped by a different
// backend (Vault, GCP, InProc, …) and we refuse rather than
// spending a KMS call on a guaranteed mismatch. We also pin
// the Decrypt to the configured KeyId so a forged blob can't
// coax a decrypt under a key we didn't intend.
func (a *AWSKMS) Unwrap(ctx context.Context, wrappedDEK []byte, kekID string) ([]byte, error) {
	if !strings.HasPrefix(kekID, awsKEKPrefix) {
		return nil, fmt.Errorf("AWSKMS: refusing to unwrap row whose kek_id=%q (no %q prefix)", kekID, awsKEKPrefix)
	}
	body := map[string]string{
		"KeyId":          a.cfg.KeyID,
		"CiphertextBlob": string(wrappedDEK),
	}
	var resp struct {
		Plaintext string `json:"Plaintext"`
	}
	if err := a.do(ctx, "TrentService.Decrypt", body, &resp); err != nil {
		return nil, fmt.Errorf("aws kms decrypt: %w", err)
	}
	dek, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("aws kms decrypt: base64: %w", err)
	}
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("aws kms decrypt: DEK has %d bytes; want %d", len(dek), DEKSize)
	}
	return dek, nil
}

// do POSTs a KMS action and decodes the JSON response.
// Centralized so SigV4 signing, error mapping, and future
// telemetry sit in one place.
//
// target is the X-Amz-Target value ("TrentService.Encrypt"
// / "TrentService.Decrypt").
func (a *AWSKMS) do(ctx context.Context, target string, body, out any) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", awsJSONContentType)
	req.Header.Set("X-Amz-Target", target)
	if err := a.signV4(req, jsonBody); err != nil {
		return fmt.Errorf("sigv4: %w", err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		// KMS returns {"__type":"...","message":"..."} on
		// failure (some actions capitalize "Message").
		var errResp struct {
			Type     string `json:"__type"`
			Message  string `json:"message"`
			MessageU string `json:"Message"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		msg := errResp.Message
		if msg == "" {
			msg = errResp.MessageU
		}
		if msg != "" {
			return fmt.Errorf("status %d: %s: %s", resp.StatusCode, errResp.Type, msg)
		}
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// signV4 signs req in place with AWS Signature Version 4.
// It sets X-Amz-Date (and X-Amz-Security-Token when the
// config carries a session token) and the Authorization
// header. body is the exact request payload — it must match
// what was attached to req, since its SHA-256 is part of
// the signature.
//
// Spec:
// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
func (a *AWSKMS) signV4(req *http.Request, body []byte) error {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if a.cfg.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", a.cfg.SessionToken)
	}

	host := req.URL.Host
	if host == "" {
		return errors.New("endpoint has no host")
	}

	// Headers we sign. Host + the x-amz-* headers; AWS
	// requires host and x-amz-date at minimum. We include
	// content-type and x-amz-target so a proxy can't strip /
	// swap them, and x-amz-security-token when present.
	signedValues := map[string]string{
		"content-type": req.Header.Get("Content-Type"),
		"host":         host,
		"x-amz-date":   amzDate,
		"x-amz-target": req.Header.Get("X-Amz-Target"),
	}
	if a.cfg.SessionToken != "" {
		signedValues["x-amz-security-token"] = a.cfg.SessionToken
	}
	names := make([]string, 0, len(signedValues))
	for n := range signedValues {
		names = append(names, n)
	}
	sort.Strings(names)

	var canonicalHeaders strings.Builder
	for _, n := range names {
		canonicalHeaders.WriteString(n)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(signedValues[n]))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	payloadHash := sha256.Sum256(body)
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		canonicalURI,
		"", // canonical query string (none)
		canonicalHeaders.String(),
		signedHeaders,
		hex.EncodeToString(payloadHash[:]),
	}, "\n")

	scope := strings.Join([]string{dateStamp, a.cfg.Region, awsKMSService, "aws4_request"}, "/")
	crHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(crHash[:]),
	}, "\n")

	signature := hex.EncodeToString(hmacSHA256(a.signingKey(dateStamp), []byte(stringToSign)))
	authz := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		a.cfg.AccessKeyID, scope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", authz)
	return nil
}

// signingKey derives the SigV4 signing key for the day via
// the standard HMAC chain: AWS4+secret → date → region →
// service → "aws4_request".
func (a *AWSKMS) signingKey(dateStamp string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+a.cfg.SecretAccessKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(a.cfg.Region))
	kService := hmacSHA256(kRegion, []byte(awsKMSService))
	return hmacSHA256(kService, []byte("aws4_request"))
}

// hmacSHA256 is the HMAC primitive SigV4's key-derivation
// chain and final signature both use.
func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}
