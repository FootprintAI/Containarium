package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Sentinel↔daemon HMAC authentication.
//
// Several daemon endpoints (`/authorized-keys`, `/authorized-keys/sentinel`,
// `/certs`) are called by the sentinel and were previously
// unauthenticated under the comment "VPC-only". That assumption fails
// closed badly: a single firewall misconfiguration or VPC-peering
// change exposes every container's SSH public-key inventory and the
// platform's TLS certificates.
//
// Until full sentinel-to-daemon mTLS lands (Phase 0.5), we gate these
// endpoints with a shared-secret HMAC over a canonical request
// string. The sentinel signs, the daemon verifies. Stronger than the
// "trust the LAN" model, weaker than mTLS — but a forward-compatible
// step.
//
// Wire format:
//
//	X-Containarium-Sentinel-Ts:  <unix-seconds>
//	X-Containarium-Sentinel-Sig: <hex(HMAC-SHA256(secret, method "\n" path "\n" ts))>
//
// Verification rejects:
//   - missing or malformed headers
//   - timestamp outside ±300s of server clock (replay-window cap)
//   - signature mismatch (constant-time compare)
//
// The secret comes from CONTAINARIUM_SENTINEL_AUTH_SECRET (mirrored on
// both ends). 32-byte minimum length is enforced at config-load time.

const (
	SentinelHeaderTimestamp = "X-Containarium-Sentinel-Ts"
	SentinelHeaderSignature = "X-Containarium-Sentinel-Sig"

	// SentinelMaxClockSkew bounds the timestamp tolerance for
	// replay protection. 5 minutes is wide enough for NTP drift and
	// laptop-time mistakes on operator boxes, tight enough that a
	// captured request stops working before an attacker can replay
	// it for any meaningful blast radius.
	SentinelMaxClockSkew = 5 * time.Minute

	// SentinelMinSecretLen is the smallest acceptable shared
	// secret. HMAC-SHA256 expects a key at least as long as its
	// block size for the security level it claims; 32 bytes is
	// also the floor most secret managers default to.
	SentinelMinSecretLen = 32
)

// SignSentinelRequest stamps the timestamp + signature headers onto
// `req`. Used by the sentinel-side HTTP client before sending. The
// secret must satisfy SentinelMinSecretLen (caller responsibility).
func SignSentinelRequest(req *http.Request, secret []byte) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := computeSentinelSignature(secret, req.Method, req.URL.Path, ts)
	req.Header.Set(SentinelHeaderTimestamp, ts)
	req.Header.Set(SentinelHeaderSignature, sig)
}

// VerifySentinelRequest returns nil if `req` carries a valid
// sentinel-HMAC signature for `secret`. The error is intentionally
// generic — callers should map it to a 401 without echoing the
// reason, the same way JWT validation does.
func VerifySentinelRequest(req *http.Request, secret []byte, now time.Time) error {
	tsStr := req.Header.Get(SentinelHeaderTimestamp)
	sig := req.Header.Get(SentinelHeaderSignature)
	if tsStr == "" || sig == "" {
		return errSentinelAuth
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return errSentinelAuth
	}
	if delta := now.Unix() - ts; delta > int64(SentinelMaxClockSkew/time.Second) || -delta > int64(SentinelMaxClockSkew/time.Second) {
		return errSentinelAuth
	}
	want := computeSentinelSignature(secret, req.Method, req.URL.Path, tsStr)
	// hex string compare via hmac.Equal for constant-time. Decoding
	// to bytes first would let a length mismatch leak via early
	// return; string-form Equal is fixed-width over the hex output.
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return errSentinelAuth
	}
	return nil
}

// SentinelHMACMiddleware wraps `next` such that incoming requests
// must carry a valid sentinel HMAC signature. If `secret` is nil or
// shorter than SentinelMinSecretLen, the middleware refuses ALL
// requests with 401 — fail-closed by default, no silent
// passthrough. Operators must configure
// CONTAINARIUM_SENTINEL_AUTH_SECRET to enable the wrapped endpoints.
func SentinelHMACMiddleware(secret []byte, next http.Handler) http.Handler {
	configured := len(secret) >= SentinelMinSecretLen
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !configured {
			http.Error(w, `{"error":"sentinel auth not configured","code":401}`, http.StatusUnauthorized)
			return
		}
		if err := VerifySentinelRequest(r, secret, time.Now()); err != nil {
			http.Error(w, `{"error":"sentinel auth failed","code":401}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func computeSentinelSignature(secret []byte, method, path, ts string) string {
	mac := hmac.New(sha256.New, secret)
	// "\n" separator is unambiguous because HTTP methods and URL
	// paths can't contain raw newlines.
	mac.Write([]byte(method))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(path))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(ts))
	return hex.EncodeToString(mac.Sum(nil))
}

var errSentinelAuth = fmt.Errorf("sentinel signature verification failed")
