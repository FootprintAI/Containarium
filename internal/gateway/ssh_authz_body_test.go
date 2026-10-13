package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

func TestSSHAuthzSignatureBindsBody(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original := `{"login":"alice","credential":{"publicKey":{"fingerprintSha256":"SHA256:a"}},"clientIp":"192.0.2.1"}`
	for _, scheme := range []struct {
		name     string
		verifier auth.SentinelVerifier
		sign     func(*http.Request, []byte)
	}{
		{"HMAC", auth.NewSentinelVerifier(nil, secret), func(r *http.Request, b []byte) { auth.SignSentinelBodyRequest(r, secret, b) }},
		{"ed25519", auth.NewSentinelVerifier(pub, nil), func(r *http.Request, b []byte) { auth.SignSentinelBodyRequestEd25519(r, priv, b) }},
	} {
		for _, tc := range []struct {
			name, body string
			legacy     bool
			want       int
		}{
			{"unchanged body reaches generated gateway", original, false, 200},
			{"different login", strings.Replace(original, "alice", "bob", 1), false, 401},
			{"different fingerprint", strings.Replace(original, "SHA256:a", "SHA256:b", 1), false, 401},
			{"different client IP", strings.Replace(original, "192.0.2.1", "192.0.2.2", 1), false, 401},
			{"legacy signature rejected", original, true, 401},
			{"oversized body bounded", strings.Repeat("x", (1<<20)+1), false, 413},
		} {
			t.Run(scheme.name+"/"+tc.name, func(t *testing.T) {
				called := false
				inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					called = true
					body, err := io.ReadAll(r.Body)
					if err != nil || !bytes.Equal(body, []byte(original)) {
						t.Errorf("gateway body not preserved: %q %v", body, err)
					}
					if !auth.VerifiedSentinelSSHAuthz(r.Context()) {
						t.Error("verified marker missing")
					}
					w.WriteHeader(200)
				})
				req := httptest.NewRequest("POST", SSHAuthzPath, strings.NewReader(tc.body))
				if tc.legacy {
					if scheme.name == "HMAC" {
						auth.SignSentinelRequest(req, secret)
					} else {
						auth.SignSentinelRequestEd25519(req, priv)
					}
				} else {
					scheme.sign(req, []byte(original))
				}
				rr := httptest.NewRecorder()
				SSHAuthzHandler(scheme.verifier, inner, nil).ServeHTTP(rr, req)
				if rr.Code != tc.want || called != (tc.want == 200) {
					t.Fatalf("code=%d called=%v", rr.Code, called)
				}
			})
		}
	}
}
