package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var sigSecret = []byte("0123456789abcdef0123456789abcdef-secret")

func postReq(t *testing.T, path, query, body string) *http.Request {
	t.Helper()
	u := "http://sentinel.invalid" + path
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func requireV2(t *testing.T, on bool) {
	t.Helper()
	prev := sentinelRequireV2.Load()
	SetSentinelRequireV2(on)
	t.Cleanup(func() { SetSentinelRequireV2(prev) })
}

// swapBody replaces the body of a signed request, keeping every header.
func swapBody(req *http.Request, body string) {
	req.Body = io.NopCloser(strings.NewReader(body))
	req.GetBody = nil
}

func TestSentinelV2_HMAC_RoundTrip_AndTamper(t *testing.T) {
	requireV2(t, true)
	req := postReq(t, "/sentinel/tunnel-tokens", "a=1", `{"key":"ssh-ed25519 AAAA"}`)
	SignSentinelRequest(req, sigSecret)
	if req.Header.Get(SentinelHeaderSignatureV2) == "" {
		t.Fatal("v2 header missing")
	}
	// The handler must still be able to read the body after verification.
	if err := VerifySentinelRequest(req, sigSecret, time.Now()); err != nil {
		t.Fatalf("valid v2: %v", err)
	}
	got, _ := io.ReadAll(req.Body)
	if string(got) != `{"key":"ssh-ed25519 AAAA"}` {
		t.Fatalf("body not restored: %q", got)
	}

	// Body swap, query swap, path swap must all fail.
	b := postReq(t, "/sentinel/tunnel-tokens", "a=1", `{"key":"attacker"}`)
	b.Header = req.Header.Clone()
	if VerifySentinelRequest(b, sigSecret, time.Now()) == nil {
		t.Error("body swap accepted")
	}
	q := postReq(t, "/sentinel/tunnel-tokens", "a=2", `{"key":"ssh-ed25519 AAAA"}`)
	q.Header = req.Header.Clone()
	if VerifySentinelRequest(q, sigSecret, time.Now()) == nil {
		t.Error("query swap accepted")
	}
	p := postReq(t, "/sentinel/other", "a=1", `{"key":"ssh-ed25519 AAAA"}`)
	p.Header = req.Header.Clone()
	if VerifySentinelRequest(p, sigSecret, time.Now()) == nil {
		t.Error("path swap accepted")
	}
}

// The attack this fixes: a captured v1-only request replayed with another body.
func TestSentinelV1_BodySwapAccepted_WhenV2NotRequired_AndRejectedWhenRequired(t *testing.T) {
	req := postReq(t, "/sentinel/tunnel-tokens", "", `{"key":"good"}`)
	SignSentinelRequest(req, sigSecret)
	req.Header.Del(SentinelHeaderSignatureV2) // a v1-only sender / stripped by an attacker
	swapBody(req, `{"key":"attacker"}`)

	requireV2(t, false)
	if VerifySentinelRequest(req, sigSecret, time.Now()) != nil {
		t.Fatal("transition mode must still accept a valid v1 request")
	}
	requireV2(t, true)
	if VerifySentinelRequest(req, sigSecret, time.Now()) == nil {
		t.Fatal("require-v2 must reject a v1-only request")
	}
}

func TestSentinelV2_BadV2NeverFallsBackToV1(t *testing.T) {
	requireV2(t, false)
	req := postReq(t, "/x", "", `{"a":1}`)
	SignSentinelRequest(req, sigSecret)
	req.Header.Set(SentinelHeaderSignatureV2, strings.Repeat("0", 64))
	if VerifySentinelRequest(req, sigSecret, time.Now()) == nil {
		t.Fatal("a present but invalid v2 header must be rejected even though v1 is valid")
	}
}

func TestSentinelV2_V1HeaderStillVerifiesForOldReceivers(t *testing.T) {
	req := postReq(t, "/x", "", `{"a":1}`)
	SignSentinelRequest(req, sigSecret)
	ts := req.Header.Get(SentinelHeaderTimestamp)
	want := computeSentinelSignature(sigSecret, req.Method, req.URL.Path, ts)
	if req.Header.Get(SentinelHeaderSignature) != want {
		t.Fatal("v1 signature changed; old receivers would reject this sender")
	}
}

func TestSentinelV2_OversizeBody(t *testing.T) {
	requireV2(t, true)
	big := strings.Repeat("a", SentinelMaxSignedBody+1)
	req := postReq(t, "/x", "", big)
	SignSentinelRequest(req, sigSecret)
	if req.Header.Get(SentinelHeaderSignatureV2) != "" {
		t.Fatal("oversize body must not get a v2 signature")
	}
	if VerifySentinelRequest(req, sigSecret, time.Now()) == nil {
		t.Fatal("require-v2 must refuse a request that could not be v2-signed")
	}
}

func TestSentinelV2_EmptyBodyGET(t *testing.T) {
	requireV2(t, true)
	req, _ := http.NewRequest(http.MethodGet, "http://s.invalid/sentinel/peers?x=1", nil)
	SignSentinelRequest(req, sigSecret)
	if err := VerifySentinelRequest(req, sigSecret, time.Now()); err != nil {
		t.Fatalf("GET with no body: %v", err)
	}
}

func TestSentinelV2_Ed25519_Verifier(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v := NewSentinelVerifier(pub, nil)
	requireV2(t, true)

	req := postReq(t, "/sentinel/x", "", `{"k":"v"}`)
	SignSentinelRequestEd25519(req, priv)
	if err := v.VerifyRequest(req, time.Now()); err != nil {
		t.Fatalf("valid ed25519 v2: %v", err)
	}
	tampered := postReq(t, "/sentinel/x", "", `{"k":"EVIL"}`)
	tampered.Header = req.Header.Clone()
	if v.VerifyRequest(tampered, time.Now()) == nil {
		t.Fatal("ed25519 body swap accepted")
	}

	// Transition mode still accepts v1-only and counts it.
	requireV2(t, false)
	old := postReq(t, "/sentinel/x", "", `{"k":"v"}`)
	SignSentinelRequestEd25519(old, priv)
	old.Header.Del(SentinelHeaderSignatureV2)
	before := SentinelV1Accepted()
	if err := v.VerifyRequest(old, time.Now()); err != nil {
		t.Fatalf("v1-only in transition: %v", err)
	}
	if SentinelV1Accepted() != before+1 {
		t.Fatal("v1 acceptance not counted")
	}
}

func TestSentinelV2_MiddlewareHandlerSeesBody(t *testing.T) {
	requireV2(t, true)
	var seen string
	h := SentinelHMACMiddleware(sigSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = string(b)
	}))
	req := postReq(t, "/sentinel/tunnel-tokens", "", "payload")
	SignSentinelRequest(req, sigSecret)
	rec := httptest.NewRecorder()
	// Serve via a real round trip of the body bytes.
	r2 := httptest.NewRequest(http.MethodPost, "/sentinel/tunnel-tokens", bytes.NewReader([]byte("payload")))
	r2.Header = req.Header.Clone()
	h.ServeHTTP(rec, r2)
	if rec.Code != 200 || seen != "payload" {
		t.Fatalf("code=%d seen=%q", rec.Code, seen)
	}
}

// An oversize body must still reach the wire intact when v2 cannot cover it.
func TestSentinelV2_OversizeBodyIsNotDrained(t *testing.T) {
	big := strings.Repeat("a", SentinelMaxSignedBody+10)
	req := postReq(t, "/x", "", big)
	SignSentinelRequest(req, sigSecret)
	got, err := io.ReadAll(req.Body)
	if err != nil || len(got) != len(big) {
		t.Fatalf("body drained: len=%d err=%v want %d", len(got), err, len(big))
	}
}

// %2F and / are different paths and must sign differently.
func TestSentinelV2_EncodedPathDiffers(t *testing.T) {
	requireV2(t, true)
	req := postReq(t, "/a%2Fb", "", "x")
	SignSentinelRequest(req, sigSecret)
	other := postReq(t, "/a/b", "", "x")
	other.Header = req.Header.Clone()
	if VerifySentinelRequest(other, sigSecret, time.Now()) == nil {
		t.Fatal("/a%2Fb signature accepted for /a/b")
	}
	same := postReq(t, "/a%2Fb", "", "x")
	same.Header = req.Header.Clone()
	if err := VerifySentinelRequest(same, sigSecret, time.Now()); err != nil {
		t.Fatalf("same escaped path rejected: %v", err)
	}
}
