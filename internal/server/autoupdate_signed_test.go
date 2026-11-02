package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

var goodSum = strings.Repeat("ab", 32)

func updaterAgainst(t *testing.T, h http.HandlerFunc) (*AutoUpdater, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	return NewAutoUpdater(srv.URL, "/nonexistent", time.Hour), srv.Close
}

func TestAutoUpdateChecksum_Authentication(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	verifier := auth.NewSentinelVerifier(pub, nil)

	serve := func(body string, key ed25519.PrivateKey) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if key != nil {
				auth.SignSentinelResponseEd25519(w, key, []byte(body))
			}
			_, _ = w.Write([]byte(body))
		}
	}
	cases := []struct {
		name    string
		h       http.HandlerFunc
		require bool
		wantErr bool
	}{
		{"signed by sentinel", serve(goodSum, priv), true, false},
		{"unsigned, verifier configured (header stripping)", serve(goodSum, nil), false, true},
		{"unsigned, required", serve(goodSum, nil), true, true},
		{"signed with another key (on-path attacker)", serve(goodSum, otherPriv), false, true},
		{"signature for different body", func(w http.ResponseWriter, r *http.Request) {
			auth.SignSentinelResponseEd25519(w, priv, []byte(strings.Repeat("cd", 32)))
			_, _ = w.Write([]byte(goodSum))
		}, false, true},
		{"malformed checksum, signed", serve("deadbeef", priv), true, true},
		{"empty checksum, unsigned", serve("", nil), false, true},
	}
	for _, c := range cases {
		u, closeSrv := updaterAgainst(t, c.h)
		u.SetVerifier(verifier, c.require)
		got, err := u.getRemoteChecksum(t.Context())
		closeSrv()
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
		}
		if err == nil && got != goodSum {
			t.Errorf("%s: got %q", c.name, got)
		}
	}
}

// With no sentinel key configured at all, a signed answer cannot be checked:
// warn-only allows it, required refuses it.
func TestAutoUpdateChecksum_NoKeyConfigured(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := func(w http.ResponseWriter, r *http.Request) {
		auth.SignSentinelResponseEd25519(w, priv, []byte(goodSum))
		_, _ = w.Write([]byte(goodSum))
	}
	for require, wantErr := range map[bool]bool{false: false, true: true} {
		u, closeSrv := updaterAgainst(t, h)
		u.SetVerifier(auth.NewSentinelVerifier(nil, nil), require)
		_, err := u.getRemoteChecksum(t.Context())
		closeSrv()
		if (err != nil) != wantErr {
			t.Errorf("require=%v: err=%v", require, err)
		}
	}
}

func TestAutoUpdateServedVersion_RejectsInvalidSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	body := `{"version":"9.9.9","checksum":"` + goodSum + `"}`
	u, closeSrv := updaterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		auth.SignSentinelResponseEd25519(w, otherPriv, []byte(body))
		_, _ = w.Write([]byte(body))
	})
	defer closeSrv()
	u.SetVerifier(auth.NewSentinelVerifier(pub, nil), false)
	if v, err := u.ServedVersion(t.Context()); err == nil {
		t.Fatalf("forged version %q accepted", v)
	}
}

// A host with no sentinel key at all stays in warn-only for unsigned answers.
func TestAutoUpdateChecksum_NoKeyUnsignedWarnOnly(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(goodSum)) }
	u, closeSrv := updaterAgainst(t, h)
	defer closeSrv()
	u.SetVerifier(auth.NewSentinelVerifier(nil, nil), false)
	if _, err := u.getRemoteChecksum(t.Context()); err != nil {
		t.Fatalf("keyless host, unsigned: %v", err)
	}
	u.SetVerifier(auth.NewSentinelVerifier(nil, nil), true)
	if _, err := u.getRemoteChecksum(t.Context()); err == nil {
		t.Fatal("require-signed must refuse unsigned")
	}
}

// ed25519-signed answer, host holds only the HMAC secret: unverifiable, not invalid.
func TestAutoUpdateChecksum_AlgorithmMismatchIsUnverifiable(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := func(w http.ResponseWriter, r *http.Request) {
		auth.SignSentinelResponseEd25519(w, priv, []byte(goodSum))
		_, _ = w.Write([]byte(goodSum))
	}
	hmacOnly := auth.NewSentinelVerifier(nil, []byte("0123456789abcdef0123456789abcdef-secret"))
	u, closeSrv := updaterAgainst(t, h)
	defer closeSrv()
	u.SetVerifier(hmacOnly, false)
	if _, err := u.getRemoteChecksum(t.Context()); err != nil {
		t.Fatalf("mismatch in warn-only should be allowed: %v", err)
	}
	u.SetVerifier(hmacOnly, true)
	if _, err := u.getRemoteChecksum(t.Context()); err == nil {
		t.Fatal("require-signed must refuse an unverifiable answer")
	}
}
