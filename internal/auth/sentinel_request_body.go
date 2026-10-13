package auth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// sentinelBodyRequestMessage domain-separates body-bound requests from legacy
// request/response signatures and commits to the exact bytes being transmitted.
func sentinelBodyRequestMessage(req *http.Request, body []byte, ts string) []byte {
	digest := sha256.Sum256(body)
	return []byte("containarium-sentinel-body-v1\n" + req.Method + "\n" + req.URL.Path + "\n" + ts + "\n" + hex.EncodeToString(digest[:]))
}

// SignSentinelBodyRequest authenticates method, path, timestamp and body with
// HMAC. Body-bound endpoints must reject legacy method/path-only signatures.
func SignSentinelBodyRequest(req *http.Request, secret, body []byte) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write(sentinelBodyRequestMessage(req, body, ts))
	req.Header.Set(SentinelHeaderTimestamp, ts)
	req.Header.Set(SentinelHeaderSignature, hex.EncodeToString(mac.Sum(nil)))
}

// SignSentinelBodyRequestEd25519 is the asymmetric body-bound request signer.
func SignSentinelBodyRequestEd25519(req *http.Request, priv ed25519.PrivateKey, body []byte) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := ed25519.Sign(priv, sentinelBodyRequestMessage(req, body, ts))
	req.Header.Set(SentinelHeaderTimestamp, ts)
	req.Header.Set(SentinelHeaderSignature, sentinelEd25519SigPrefix+base64.StdEncoding.EncodeToString(sig))
}

// VerifyBodyRequest requires a signature over the exact received body as well
// as method/path/time. It does not fall back to legacy request authentication.
func (v SentinelVerifier) VerifyBodyRequest(req *http.Request, body []byte, now time.Time) error {
	ts := req.Header.Get(SentinelHeaderTimestamp)
	sig := req.Header.Get(SentinelHeaderSignature)
	if ts == "" || sig == "" || !sentinelTimestampWithinSkew(ts, now) {
		return errSentinelAuth
	}
	msg := sentinelBodyRequestMessage(req, body, ts)
	if strings.HasPrefix(sig, sentinelEd25519SigPrefix) {
		if !v.hasEd25519() {
			return errSentinelAuth
		}
		return v.verifyEd25519(msg, sig)
	}
	if !v.hasHMAC() {
		return errSentinelAuth
	}
	mac := hmac.New(sha256.New, v.secret)
	mac.Write(msg)
	if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig)) {
		return errSentinelAuth
	}
	return nil
}
