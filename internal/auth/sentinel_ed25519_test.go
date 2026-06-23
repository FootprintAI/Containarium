package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func newSignedReq(t *testing.T, priv ed25519.PrivateKey, method, path string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, "http://daemon"+path, nil)
	SignSentinelRequestEd25519(req, priv)
	return req
}

// validHMACSecret is a deterministic >=32-byte secret for the legacy path.
var validHMACSecret = []byte("0123456789abcdef0123456789abcdef")

func TestParseSentinelKeys(t *testing.T) {
	pub, priv := mustKeypair(t)

	pubB64 := base64.StdEncoding.EncodeToString(pub)
	gotPub, err := ParseSentinelPublicKey("  " + pubB64 + "\n")
	if err != nil || !bytes.Equal(gotPub, pub) {
		t.Fatalf("ParseSentinelPublicKey round-trip failed: err=%v equal=%v", err, bytes.Equal(gotPub, pub))
	}

	// Full 64-byte private key round-trips.
	gotPriv, err := ParseSentinelSigningKey(base64.StdEncoding.EncodeToString(priv))
	if err != nil || !bytes.Equal(gotPriv, priv) {
		t.Fatalf("ParseSentinelSigningKey (full) failed: err=%v", err)
	}

	// 32-byte seed expands to the same key.
	seedPriv, err := ParseSentinelSigningKey(base64.StdEncoding.EncodeToString(priv.Seed()))
	if err != nil || !bytes.Equal(seedPriv, priv) {
		t.Fatalf("ParseSentinelSigningKey (seed) failed: err=%v", err)
	}

	// Failure cases.
	if _, err := ParseSentinelPublicKey("not-base64!!"); err == nil {
		t.Error("expected error on non-base64 public key")
	}
	if _, err := ParseSentinelPublicKey(base64.StdEncoding.EncodeToString([]byte("too short"))); err == nil {
		t.Error("expected error on wrong-length public key")
	}
	if _, err := ParseSentinelSigningKey(base64.StdEncoding.EncodeToString([]byte("nope"))); err == nil {
		t.Error("expected error on wrong-length signing key")
	}
}

func TestVerifyRequest_Ed25519_RoundTrip(t *testing.T) {
	pub, priv := mustKeypair(t)
	v := NewSentinelVerifier(pub, nil)

	if err := v.VerifyRequest(newSignedReq(t, priv, "GET", "/authorized-keys"), time.Now()); err != nil {
		t.Fatalf("valid ed25519 request rejected: %v", err)
	}
}

func TestVerifyRequest_Ed25519_Tampering(t *testing.T) {
	pub, priv := mustKeypair(t)
	v := NewSentinelVerifier(pub, nil)

	// Tampered path: signature was over /authorized-keys, request now hits a
	// different path → reject.
	req := newSignedReq(t, priv, "GET", "/authorized-keys")
	req.URL.Path = "/certs"
	if err := v.VerifyRequest(req, time.Now()); err == nil {
		t.Error("tampered path accepted")
	}

	// Wrong signing key → reject.
	_, otherPriv := mustKeypair(t)
	if err := v.VerifyRequest(newSignedReq(t, otherPriv, "GET", "/authorized-keys"), time.Now()); err == nil {
		t.Error("signature from wrong key accepted")
	}

	// Stale timestamp (outside skew) → reject.
	old := newSignedReq(t, priv, "GET", "/authorized-keys")
	if err := v.VerifyRequest(old, time.Now().Add(2*SentinelMaxClockSkew)); err == nil {
		t.Error("stale timestamp accepted")
	}

	// Missing headers → reject.
	bare := httptest.NewRequest("GET", "http://daemon/authorized-keys", nil)
	if err := v.VerifyRequest(bare, time.Now()); err == nil {
		t.Error("unsigned request accepted")
	}

	// Garbage signature → reject.
	bad := newSignedReq(t, priv, "GET", "/authorized-keys")
	bad.Header.Set(SentinelHeaderSignature, sentinelEd25519SigPrefix+"!!notbase64")
	if err := v.VerifyRequest(bad, time.Now()); err == nil {
		t.Error("malformed ed25519 signature accepted")
	}
}

// TestVerifier_AlgorithmIsolation is the core security property: a verifier
// accepts ONLY an algorithm it has a key for, and a verifier that holds only
// the ed25519 public key cannot be used to forge anything.
func TestVerifier_AlgorithmIsolation(t *testing.T) {
	pub, priv := mustKeypair(t)

	ed25519Only := NewSentinelVerifier(pub, nil)
	hmacOnly := NewSentinelVerifier(nil, validHMACSecret)
	both := NewSentinelVerifier(pub, validHMACSecret)

	edReq := func() *http.Request { return newSignedReq(t, priv, "GET", "/authorized-keys") }
	hmacReq := func() *http.Request {
		req := httptest.NewRequest("GET", "http://daemon/authorized-keys", nil)
		SignSentinelRequest(req, validHMACSecret)
		return req
	}

	// ed25519-only verifier: accepts ed25519, rejects HMAC.
	if err := ed25519Only.VerifyRequest(edReq(), time.Now()); err != nil {
		t.Errorf("ed25519-only should accept ed25519: %v", err)
	}
	if err := ed25519Only.VerifyRequest(hmacReq(), time.Now()); err == nil {
		t.Error("ed25519-only MUST reject HMAC (no secret to verify, and must not forge)")
	}

	// HMAC-only verifier: accepts HMAC, rejects ed25519.
	if err := hmacOnly.VerifyRequest(hmacReq(), time.Now()); err != nil {
		t.Errorf("hmac-only should accept HMAC: %v", err)
	}
	if err := hmacOnly.VerifyRequest(edReq(), time.Now()); err == nil {
		t.Error("hmac-only MUST reject ed25519")
	}

	// Dual verifier (migration window): accepts both.
	if err := both.VerifyRequest(edReq(), time.Now()); err != nil {
		t.Errorf("dual should accept ed25519: %v", err)
	}
	if err := both.VerifyRequest(hmacReq(), time.Now()); err != nil {
		t.Errorf("dual should accept HMAC: %v", err)
	}
}

func TestVerifyResponse_Ed25519_RoundTrip(t *testing.T) {
	pub, priv := mustKeypair(t)
	v := NewSentinelVerifier(pub, nil)
	body := []byte(`{"peers":[{"id":"x"}]}`)

	rec := httptest.NewRecorder()
	SignSentinelResponseEd25519(rec, priv, body)
	resp := &http.Response{Header: rec.Header()}

	if err := v.VerifyResponse(resp, body, time.Now()); err != nil {
		t.Fatalf("valid ed25519 response rejected: %v", err)
	}

	// Tampered body → reject.
	if err := v.VerifyResponse(resp, append(body, '!'), time.Now()); err == nil {
		t.Error("tampered response body accepted")
	}

	// nil private key → no headers → fail closed.
	rec2 := httptest.NewRecorder()
	SignSentinelResponseEd25519(rec2, nil, body)
	if rec2.Header().Get(SentinelHeaderSignature) != "" {
		t.Error("nil key must not write a signature header")
	}
	if err := v.VerifyResponse(&http.Response{Header: rec2.Header()}, body, time.Now()); err == nil {
		t.Error("unsigned response accepted")
	}
}

func TestSentinelVerifier_Middleware(t *testing.T) {
	pub, priv := mustKeypair(t)

	call := func(v SentinelVerifier, req *http.Request) int {
		rec := httptest.NewRecorder()
		v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		})).ServeHTTP(rec, req)
		return rec.Code
	}

	// Unconfigured → fail closed 401.
	if code := call(NewSentinelVerifier(nil, nil), newSignedReq(t, priv, "GET", "/x")); code != http.StatusUnauthorized {
		t.Errorf("unconfigured verifier: want 401, got %d", code)
	}
	// Valid ed25519 → 200.
	if code := call(NewSentinelVerifier(pub, nil), newSignedReq(t, priv, "GET", "/x")); code != http.StatusOK {
		t.Errorf("valid request: want 200, got %d", code)
	}
	// Invalid (unsigned) → 401.
	if code := call(NewSentinelVerifier(pub, nil), httptest.NewRequest("GET", "http://d/x", nil)); code != http.StatusUnauthorized {
		t.Errorf("unsigned request: want 401, got %d", code)
	}
}

func TestConfigured(t *testing.T) {
	pub, _ := mustKeypair(t)
	if NewSentinelVerifier(nil, nil).Configured() {
		t.Error("empty verifier must report unconfigured")
	}
	if !NewSentinelVerifier(pub, nil).Configured() {
		t.Error("ed25519 verifier must report configured")
	}
	if !NewSentinelVerifier(nil, validHMACSecret).Configured() {
		t.Error("hmac verifier must report configured")
	}
	// A too-short HMAC secret is treated as absent.
	if NewSentinelVerifier(nil, []byte("short")).Configured() {
		t.Error("sub-minimum HMAC secret must be treated as unconfigured")
	}
}

// TestEd25519InteropTimestampShared confirms the ed25519 path reuses the same
// timestamp header + canonical message as HMAC (so a mixed fleet agrees on what
// is signed). Sign with ed25519, verify the timestamp parses and the message
// matches the HMAC canonical builder.
func TestEd25519InteropTimestampShared(t *testing.T) {
	_, priv := mustKeypair(t)
	req := newSignedReq(t, priv, "POST", "/authorized-keys/sentinel")

	tsStr := req.Header.Get(SentinelHeaderTimestamp)
	if _, err := strconv.ParseInt(tsStr, 10, 64); err != nil {
		t.Fatalf("timestamp header not a unix-seconds int: %q", tsStr)
	}
	if !strings.HasPrefix(req.Header.Get(SentinelHeaderSignature), sentinelEd25519SigPrefix) {
		t.Error("ed25519 signature missing algorithm tag")
	}
	// The canonical message must be identical across schemes.
	got := string(sentinelRequestMessage("POST", "/authorized-keys/sentinel", tsStr))
	want := "POST\n/authorized-keys/sentinel\n" + tsStr
	if got != want {
		t.Errorf("canonical request message = %q, want %q", got, want)
	}
}
