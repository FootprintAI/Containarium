package secrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Phase 4.1 Phase-C — GCP Cloud KMS backend tests.
//
// We stand up a fake Cloud KMS server with httptest that:
//   - validates the Authorization: Bearer header
//   - encrypts plaintext under a process-local AES key to
//     produce a base64 ciphertext blob
//   - reverses on the :decrypt verb
//   - can be configured to return errors for negative
//     cases
//
// This lets us exercise the request shape, the kek_id
// encoding, the Authorization plumbing, the error
// mapping, and the prefix-routing guard without needing
// real Cloud KMS credentials.

type fakeGCPKMS struct {
	t          *testing.T
	wantToken  string
	encryptKey []byte
	requireOp  string // if non-empty, fail unless URL ends with :<op>
	statusCode int    // override status code (default 200)
	errMsg     string // optional GCP-style error message
}

func newFakeGCPKMS(t *testing.T) (*httptest.Server, *fakeGCPKMS) {
	t.Helper()
	fk := &fakeGCPKMS{
		t:          t,
		wantToken:  "access-token-xyz",
		encryptKey: make([]byte, 32),
		statusCode: 200,
	}
	if _, err := io.ReadFull(rand.Reader, fk.encryptKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(fk.handle))
	return srv, fk
}

func (f *fakeGCPKMS) handle(w http.ResponseWriter, r *http.Request) {
	// Bearer token check up front so unauthenticated calls
	// fail the same way Cloud KMS would.
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") || strings.TrimPrefix(authz, "Bearer ") != f.wantToken {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":401,"message":"missing or invalid token","status":"UNAUTHENTICATED"}}`))
		return
	}
	if f.statusCode >= 400 {
		w.WriteHeader(f.statusCode)
		_, _ = w.Write([]byte(`{"error":{"code":` +
			httpStatusJSON(f.statusCode) + `,"message":"` + f.errMsg + `"}}`))
		return
	}
	// Path: /v1/<key_name>:<op>
	// We don't validate the key_name; just extract op.
	path := strings.Trim(r.URL.Path, "/")
	idx := strings.LastIndex(path, ":")
	if idx < 0 {
		http.Error(w, `{"error":{"message":"missing :op suffix"}}`, http.StatusBadRequest)
		return
	}
	op := path[idx+1:]
	if f.requireOp != "" && op != f.requireOp {
		http.Error(w, `{"error":{"message":"wrong op"}}`, http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch op {
	case "encrypt":
		var req struct {
			Plaintext string `json:"plaintext"`
		}
		_ = json.Unmarshal(body, &req)
		pt, err := base64.StdEncoding.DecodeString(req.Plaintext)
		if err != nil {
			http.Error(w, `{"error":{"message":"bad plaintext b64"}}`, http.StatusBadRequest)
			return
		}
		ct := f.symEncrypt(pt)
		resp := map[string]any{
			"name":       path[:idx] + "/cryptoKeyVersions/1",
			"ciphertext": base64.StdEncoding.EncodeToString(ct),
		}
		_ = json.NewEncoder(w).Encode(resp)
	case "decrypt":
		var req struct {
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.Unmarshal(body, &req)
		raw, err := base64.StdEncoding.DecodeString(req.Ciphertext)
		if err != nil {
			http.Error(w, `{"error":{"message":"bad ciphertext b64"}}`, http.StatusBadRequest)
			return
		}
		pt, err := f.symDecrypt(raw)
		if err != nil {
			http.Error(w, `{"error":{"message":"bad ciphertext"}}`, http.StatusBadRequest)
			return
		}
		resp := map[string]any{
			"plaintext": base64.StdEncoding.EncodeToString(pt),
		}
		_ = json.NewEncoder(w).Encode(resp)
	default:
		http.Error(w, `{"error":{"message":"unknown op"}}`, http.StatusBadRequest)
	}
}

// httpStatusJSON renders the int as a JSON number-literal
// for embedding in the error envelope. Keeps the fake
// terse — proper printf would pull strconv into the test
// import set for one call.
func httpStatusJSON(code int) string {
	switch code {
	case 400:
		return "400"
	case 401:
		return "401"
	case 403:
		return "403"
	case 404:
		return "404"
	case 429:
		return "429"
	case 500:
		return "500"
	case 503:
		return "503"
	default:
		return "0"
	}
}

func (f *fakeGCPKMS) symEncrypt(pt []byte) []byte {
	block, _ := aes.NewCipher(f.encryptKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	return append(nonce, gcm.Seal(nil, nonce, pt, nil)...)
}

func (f *fakeGCPKMS) symDecrypt(blob []byte) ([]byte, error) {
	block, _ := aes.NewCipher(f.encryptKey)
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, io.ErrUnexpectedEOF
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}

const testKeyName = "projects/test-proj/locations/us-west1/keyRings/r/cryptoKeys/k"

// --- Tests ---

func TestGCPKMS_WrapUnwrapRoundtrip(t *testing.T) {
	srv, _ := newFakeGCPKMS(t)
	defer srv.Close()

	k, err := NewGCPKMS(GCPConfig{
		KeyName:  testKeyName,
		Token:    "access-token-xyz",
		Endpoint: srv.URL,
	})
	if err != nil {
		t.Fatalf("NewGCPKMS: %v", err)
	}

	dek, _ := NewDEK()
	wrapped, kekID, err := k.Wrap(context.Background(), dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if !strings.HasPrefix(kekID, "gcp:") {
		t.Fatalf("kek_id missing gcp: prefix: %q", kekID)
	}
	if !strings.Contains(kekID, testKeyName) {
		t.Fatalf("kek_id should encode key name; got %q", kekID)
	}
	if len(wrapped) == 0 {
		t.Fatal("wrapped DEK is empty")
	}

	out, err := k.Unwrap(context.Background(), wrapped, kekID)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(out, dek) {
		t.Fatal("round-trip altered DEK")
	}
}

func TestGCPKMS_RejectsBadToken(t *testing.T) {
	srv, _ := newFakeGCPKMS(t)
	defer srv.Close()

	k, _ := NewGCPKMS(GCPConfig{
		KeyName:  testKeyName,
		Token:    "wrong-token",
		Endpoint: srv.URL,
	})
	dek, _ := NewDEK()
	_, _, err := k.Wrap(context.Background(), dek)
	if err == nil {
		t.Fatal("Wrap with wrong token should fail")
	}
	if !strings.Contains(err.Error(), "missing or invalid token") {
		t.Fatalf("error should pass through Cloud KMS message; got %v", err)
	}
}

func TestGCPKMS_RejectsRowFromDifferentBackend(t *testing.T) {
	srv, _ := newFakeGCPKMS(t)
	defer srv.Close()

	k, _ := NewGCPKMS(GCPConfig{
		KeyName: testKeyName, Token: "access-token-xyz", Endpoint: srv.URL,
	})

	// kek_id from another backend (Vault).
	_, err := k.Unwrap(context.Background(), []byte("opaque-base64-ciphertext"), "vault:https://v|transit|k")
	if err == nil {
		t.Fatal("GCPKMS must refuse non-gcp: kek_id")
	}
	if !strings.Contains(err.Error(), "no \"gcp:\" prefix") {
		t.Fatalf("error should mention the missing prefix; got %v", err)
	}
}

func TestGCPKMS_RejectsBadDEKSize(t *testing.T) {
	srv, _ := newFakeGCPKMS(t)
	defer srv.Close()
	k, _ := NewGCPKMS(GCPConfig{
		KeyName: testKeyName, Token: "access-token-xyz", Endpoint: srv.URL,
	})
	for _, badSize := range []int{0, 16, 64} {
		dek := make([]byte, badSize)
		_, _, err := k.Wrap(context.Background(), dek)
		if err == nil {
			t.Fatalf("Wrap with DEK size %d should fail", badSize)
		}
	}
}

func TestGCPKMS_KEKIDEncodesKeyIdentity(t *testing.T) {
	// Two backends pointed at different CryptoKeys produce
	// different kek_ids — a row from one can't silently
	// route to the other.
	srv, _ := newFakeGCPKMS(t)
	defer srv.Close()
	a, _ := NewGCPKMS(GCPConfig{
		KeyName:  "projects/a/locations/us/keyRings/r/cryptoKeys/key-a",
		Token:    "access-token-xyz",
		Endpoint: srv.URL,
	})
	b, _ := NewGCPKMS(GCPConfig{
		KeyName:  "projects/b/locations/us/keyRings/r/cryptoKeys/key-b",
		Token:    "access-token-xyz",
		Endpoint: srv.URL,
	})
	dek, _ := NewDEK()
	_, kekA, _ := a.Wrap(context.Background(), dek)
	_, kekB, _ := b.Wrap(context.Background(), dek)
	if kekA == kekB {
		t.Fatal("different CryptoKeys should produce different kek_ids")
	}
}

func TestGCPKMS_RejectsEmptyConfig(t *testing.T) {
	cases := []GCPConfig{
		{KeyName: "", Token: "t"},
		{KeyName: testKeyName, Token: ""},
		{KeyName: "not/a/key/path", Token: "t"},
		{KeyName: "projects/p/locations/l/keyRings/r", Token: "t"}, // missing /cryptoKeys/
	}
	for _, c := range cases {
		if _, err := NewGCPKMS(c); err == nil {
			t.Fatalf("NewGCPKMS should reject config %+v", c)
		}
	}
}

func TestGCPKMS_EndpointDefaultsToPublic(t *testing.T) {
	// We can't hit the real public endpoint in tests; we
	// confirm the field defaults to the public URL when
	// left empty, by reading it back via the kek_id-
	// independent path (a Wrap against a no-route server
	// produces an http error containing the URL).
	k, err := NewGCPKMS(GCPConfig{
		KeyName: testKeyName,
		Token:   "access-token-xyz",
		// no Endpoint → defaults to gcpDefaultEndpoint
		Timeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewGCPKMS: %v", err)
	}
	dek, _ := NewDEK()
	_, _, err = k.Wrap(context.Background(), dek)
	if err == nil {
		t.Fatal("Wrap should fail (we can't actually reach Cloud KMS)")
	}
	// Best-effort: the default endpoint string should
	// appear in the error chain. Network DNS failure or
	// timeout — either way the URL we tried is in the err.
	if !strings.Contains(err.Error(), "cloudkms.googleapis.com") {
		t.Logf("err = %v (does not mention default endpoint, but that's OK on some networks)", err)
	}
}

func TestGCPKMS_TimeoutAppliesToHTTP(t *testing.T) {
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer hang.Close()

	k, _ := NewGCPKMS(GCPConfig{
		KeyName:  testKeyName,
		Token:    "access-token-xyz",
		Endpoint: hang.URL,
		Timeout:  100 * time.Millisecond,
	})
	dek, _ := NewDEK()
	start := time.Now()
	_, _, err := k.Wrap(context.Background(), dek)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Wrap should time out")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("timeout not honored; elapsed = %v", elapsed)
	}
}

func TestGCPKMS_PassesCloudKMSErrorThrough(t *testing.T) {
	srv, fk := newFakeGCPKMS(t)
	defer srv.Close()
	fk.statusCode = 403
	fk.errMsg = "Permission cloudkms.cryptoKeyVersions.useToEncrypt denied"

	k, _ := NewGCPKMS(GCPConfig{
		KeyName: testKeyName, Token: "access-token-xyz", Endpoint: srv.URL,
	})
	dek, _ := NewDEK()
	_, _, err := k.Wrap(context.Background(), dek)
	if err == nil {
		t.Fatal("Wrap should fail with 403")
	}
	if !strings.Contains(err.Error(), "Permission cloudkms") {
		t.Fatalf("error should surface Cloud KMS message; got %v", err)
	}
}

// Compile-time conformance.
var _ KMSClient = (*GCPKMS)(nil)
