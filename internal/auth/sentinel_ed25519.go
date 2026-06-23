package auth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// hmacEqualStrings compares two signature strings in constant time. A length
// mismatch can't early-leak: hmac.Equal is fixed-width over the byte slices.
func hmacEqualStrings(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

// Asymmetric (ed25519) sentinel→daemon authentication — the #688 successor to
// the symmetric HMAC scheme in sentinel_hmac.go.
//
// WHY: the HMAC secret (CONTAINARIUM_SENTINEL_AUTH_SECRET) is deployment-wide
// and SYMMETRIC — every daemon that must *verify* a sentinel request also holds
// the key needed to *forge* one. On a multi-tenant deployment that is a
// cross-tenant escalation: a BYO-compute (BYOC) host, which only needs to
// accept the sentinel's keysync/certsync, could mint a request that the shared
// workhorse daemon accepts and push attacker-controlled SSH keys into other
// tenants' boxes (/authorized-keys/sentinel).
//
// FIX: the sentinel→daemon direction is always "sentinel signs, daemon
// verifies" (keysync, certsync, the /sentinel/peers response). That is exactly
// what asymmetric signing is for. The sentinel holds an ed25519 PRIVATE key;
// every daemon is given only the PUBLIC key. A daemon (BYOC or not) can verify
// but cannot forge, so distributing the public key everywhere — including to
// untrusted BYOC hosts — carries no escalation.
//
// Wire format reuses the existing timestamp header and overloads the signature
// header with an algorithm tag so a mixed fleet interoperates during migration:
//
//	X-Containarium-Sentinel-Ts:  <unix-seconds>
//	X-Containarium-Sentinel-Sig: ed25519:<base64(signature)>      (this scheme)
//	X-Containarium-Sentinel-Sig: <hex(HMAC-SHA256(...))>          (legacy, no tag)
//
// The canonical signed message is identical to the HMAC scheme — requests sign
// `method "\n" path "\n" ts`, responses sign `body "\n" ts` — so the only thing
// that changes is the primitive, not what is committed to.
//
// The daemon→sentinel PKI bootstrap (/sentinel/ca, /sentinel/peer-cert) is a
// different trust direction with its own threat model and is intentionally NOT
// changed here; it remains on the shared secret pending the mTLS work.

// sentinelEd25519SigPrefix tags an ed25519 signature in the signature header.
// A header value WITHOUT this prefix is treated as a legacy hex HMAC, which is
// how a verifier tells the two apart without a second header.
const sentinelEd25519SigPrefix = "ed25519:"

// ParseSentinelPublicKey decodes a base64 (standard encoding) ed25519 public
// key. This is the value distributed to daemons via
// CONTAINARIUM_SENTINEL_PUBLIC_KEY — safe to ship to any host, including BYOC.
func ParseSentinelPublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("sentinel public key: not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("sentinel public key: want %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// ParseSentinelSigningKey decodes a base64 (standard encoding) ed25519 private
// key. It accepts either a 64-byte full private key or a 32-byte seed. This is
// held ONLY by the sentinel (CONTAINARIUM_SENTINEL_SIGNING_KEY) and must never
// be distributed to daemons.
func ParseSentinelSigningKey(b64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("sentinel signing key: not valid base64: %w", err)
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	default:
		return nil, fmt.Errorf("sentinel signing key: want %d-byte key or %d-byte seed, got %d",
			ed25519.PrivateKeySize, ed25519.SeedSize, len(raw))
	}
}

// SignSentinelRequestEd25519 stamps the timestamp + ed25519 signature headers
// onto req. Counterpart of SignSentinelRequest (HMAC). Called by the sentinel
// before sending a keysync/certsync request to a daemon.
func SignSentinelRequestEd25519(req *http.Request, priv ed25519.PrivateKey) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := ed25519.Sign(priv, sentinelRequestMessage(req.Method, req.URL.Path, ts))
	req.Header.Set(SentinelHeaderTimestamp, ts)
	req.Header.Set(SentinelHeaderSignature, sentinelEd25519SigPrefix+base64.StdEncoding.EncodeToString(sig))
}

// SignSentinelResponseEd25519 stamps the timestamp + ed25519 signature headers
// for a response body. Counterpart of SignSentinelResponse (HMAC). Call BEFORE
// writing the body. When priv is nil the headers are omitted and the body ships
// unsigned — the verifier fails closed and logs it, surfacing misconfiguration
// loudly rather than shipping an unauthenticated peer list.
func SignSentinelResponseEd25519(w http.ResponseWriter, priv ed25519.PrivateKey, body []byte) {
	if len(priv) != ed25519.PrivateKeySize {
		return
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := ed25519.Sign(priv, sentinelBodyMessage(body, ts))
	w.Header().Set(SentinelHeaderTimestamp, ts)
	w.Header().Set(SentinelHeaderSignature, sentinelEd25519SigPrefix+base64.StdEncoding.EncodeToString(sig))
}

// sentinelRequestMessage builds the canonical bytes a request signature commits
// to. Shared by the HMAC and ed25519 schemes so the two never disagree on what
// is signed. "\n" is unambiguous: HTTP methods and URL paths cannot contain a
// raw newline.
func sentinelRequestMessage(method, path, ts string) []byte {
	return []byte(method + "\n" + path + "\n" + ts)
}

// sentinelBodyMessage builds the canonical bytes a response signature commits
// to (the body followed by the timestamp).
func sentinelBodyMessage(body []byte, ts string) []byte {
	msg := make([]byte, 0, len(body)+1+len(ts))
	msg = append(msg, body...)
	msg = append(msg, '\n')
	msg = append(msg, ts...)
	return msg
}

// sentinelTimestampWithinSkew parses the timestamp header and reports whether
// it is within ±SentinelMaxClockSkew of now (replay-window cap).
func sentinelTimestampWithinSkew(tsStr string, now time.Time) bool {
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	maxSkew := int64(SentinelMaxClockSkew / time.Second)
	delta := now.Unix() - ts
	return delta <= maxSkew && -delta <= maxSkew
}

// SentinelVerifier verifies sentinel→daemon request and response signatures,
// accepting ed25519 (preferred) and/or legacy HMAC depending on what is
// configured:
//
//   - ed25519 public key only  → accepts only ed25519. The end state: the host
//     holds NOTHING that can forge a request (the BYOC-safe configuration).
//   - HMAC secret only          → accepts only legacy HMAC (today's fleet).
//   - both                      → accepts either (the migration window).
//   - neither                   → Configured()==false; the middleware refuses
//     every request, fail-closed.
//
// A signature's algorithm is taken from its header tag, and a verifier only
// accepts an algorithm it actually has a key for — an ed25519-tagged signature
// is never checked against the HMAC secret, and vice versa.
type SentinelVerifier struct {
	pub    ed25519.PublicKey // nil when no ed25519 public key is configured
	secret []byte            // nil/short when no legacy HMAC secret is configured
}

// NewSentinelVerifier builds a verifier from an optional ed25519 public key and
// an optional legacy HMAC secret. Either may be nil; a too-short HMAC secret is
// treated as absent (matching SentinelMinSecretLen elsewhere).
func NewSentinelVerifier(pub ed25519.PublicKey, hmacSecret []byte) SentinelVerifier {
	v := SentinelVerifier{}
	if len(pub) == ed25519.PublicKeySize {
		v.pub = pub
	}
	if len(hmacSecret) >= SentinelMinSecretLen {
		v.secret = hmacSecret
	}
	return v
}

// hasEd25519 reports whether an ed25519 public key is configured.
func (v SentinelVerifier) hasEd25519() bool { return len(v.pub) == ed25519.PublicKeySize }

// hasHMAC reports whether a usable legacy HMAC secret is configured.
func (v SentinelVerifier) hasHMAC() bool { return len(v.secret) >= SentinelMinSecretLen }

// Configured reports whether the verifier can accept any signature at all. When
// false the middleware fails closed.
func (v SentinelVerifier) Configured() bool { return v.hasEd25519() || v.hasHMAC() }

// VerifyRequest returns nil if req carries a valid, in-window sentinel
// signature this verifier accepts. The error is intentionally generic so
// callers map it to a bare 401 without echoing the reason.
func (v SentinelVerifier) VerifyRequest(req *http.Request, now time.Time) error {
	tsStr := req.Header.Get(SentinelHeaderTimestamp)
	sig := req.Header.Get(SentinelHeaderSignature)
	if tsStr == "" || sig == "" || !sentinelTimestampWithinSkew(tsStr, now) {
		return errSentinelAuth
	}
	return v.verifySig(sentinelRequestMessage(req.Method, req.URL.Path, tsStr), sig, req.Method, req.URL.Path, tsStr)
}

// VerifyResponse returns nil if resp's headers form a valid, in-window
// signature over body that this verifier accepts.
func (v SentinelVerifier) VerifyResponse(resp *http.Response, body []byte, now time.Time) error {
	tsStr := resp.Header.Get(SentinelHeaderTimestamp)
	sig := resp.Header.Get(SentinelHeaderSignature)
	if tsStr == "" || sig == "" || !sentinelTimestampWithinSkew(tsStr, now) {
		return errSentinelAuth
	}
	// For the legacy HMAC body path we delegate to the existing helper so the
	// hex/constant-time handling stays in one place; ed25519 verifies directly.
	if strings.HasPrefix(sig, sentinelEd25519SigPrefix) {
		if !v.hasEd25519() {
			return errSentinelAuth
		}
		return v.verifyEd25519(sentinelBodyMessage(body, tsStr), sig)
	}
	if !v.hasHMAC() {
		return errSentinelAuth
	}
	want := computeBodySignature(v.secret, body, tsStr)
	if !hmacEqualStrings(want, sig) {
		return errSentinelAuth
	}
	return nil
}

// verifySig dispatches a request signature to the matching primitive. method/
// path/ts are passed so the HMAC branch can reuse computeSentinelSignature.
func (v SentinelVerifier) verifySig(msg []byte, sig, method, path, ts string) error {
	if strings.HasPrefix(sig, sentinelEd25519SigPrefix) {
		if !v.hasEd25519() {
			return errSentinelAuth
		}
		return v.verifyEd25519(msg, sig)
	}
	if !v.hasHMAC() {
		return errSentinelAuth
	}
	want := computeSentinelSignature(v.secret, method, path, ts)
	if !hmacEqualStrings(want, sig) {
		return errSentinelAuth
	}
	return nil
}

// verifyEd25519 checks an "ed25519:<base64>" signature over msg.
func (v SentinelVerifier) verifyEd25519(msg []byte, taggedSig string) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(taggedSig, sentinelEd25519SigPrefix))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errSentinelAuth
	}
	if !ed25519.Verify(v.pub, msg, raw) {
		return errSentinelAuth
	}
	return nil
}

// Middleware wraps next so incoming requests must carry a signature this
// verifier accepts. When unconfigured it refuses every request with 401
// (fail-closed) and logs the misconfiguration at most once per interval, the
// same contract as the legacy SentinelHMACMiddleware.
func (v SentinelVerifier) Middleware(next http.Handler) http.Handler {
	configured := v.Configured()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !configured {
			logDaemonSentinelMisconfigOncePerInterval(r)
			http.Error(w, `{"error":"sentinel auth not configured","code":401}`, http.StatusUnauthorized)
			return
		}
		if err := v.VerifyRequest(r, time.Now()); err != nil {
			http.Error(w, `{"error":"sentinel auth failed","code":401}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
