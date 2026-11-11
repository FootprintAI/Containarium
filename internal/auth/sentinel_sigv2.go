package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// Sentinel request signature v2.
//
// The v1 signature commits to method, path and timestamp only, so a captured
// signed request can be replayed inside the skew window with a different query
// or body (a different SSH key, unban target or release tag). v2 also commits
// to the raw query and to the SHA-256 of the request body:
//
//	"v2\n" method "\n" path "\n" rawQuery "\n" ts "\n" hex(sha256(body))
//
// v2 travels in its own header so a v1-only receiver ignores it and keeps
// verifying v1: senders always emit both, receivers prefer v2 when present.
// Rollout: release 1 receivers accept v1 or v2; release 2 receivers require v2
// (CONTAINARIUM_SENTINEL_REQUIRE_V2=1, default flipped).
const (
	// SentinelHeaderSignatureV2 carries the body-covering signature.
	SentinelHeaderSignatureV2 = "X-Containarium-Sentinel-Sig-V2"

	// SentinelMaxSignedBody caps the request body a signature will cover.
	// Sentinel control requests are small JSON documents.
	SentinelMaxSignedBody = 1 << 20
)

var (
	errSentinelBodyTooLarge = errors.New("sentinel: request body exceeds signing cap")

	sentinelRequireV2  atomic.Bool
	sentinelV1Accepted atomic.Int64
)

func init() {
	raw := strings.TrimSpace(os.Getenv("CONTAINARIUM_SENTINEL_REQUIRE_V2"))
	if raw == "" {
		return
	}
	on, err := strconv.ParseBool(raw)
	if err != nil {
		log.Printf("[sentinel-sig] CONTAINARIUM_SENTINEL_REQUIRE_V2=%q is not a boolean; v1 stays accepted", raw)
		return
	}
	sentinelRequireV2.Store(on)
	log.Printf("[sentinel-sig] require-v2 = %v", on)
}

// SetSentinelRequireV2 makes receivers reject requests that carry no valid v2
// signature. Release 2 of the rollout defaults this on.
func SetSentinelRequireV2(on bool) { sentinelRequireV2.Store(on) }

// SentinelV1Accepted counts requests accepted on the v1 signature alone. The
// fleet is ready for require-v2 when this stays zero.
func SentinelV1Accepted() int64 { return sentinelV1Accepted.Load() }

func noteSentinelV1(r *http.Request) {
	if n := sentinelV1Accepted.Add(1); n == 1 || n%100 == 0 {
		log.Printf("[sentinel-sig] accepted v1-only signature on %s %s (total %d); sender has not moved to v2", r.Method, r.URL.Path, n)
	}
}

// requestBodyDigest returns the SHA-256 of the request body and leaves
// req.Body readable for the handler (or the transport). It fails when the body
// is larger than SentinelMaxSignedBody.
func requestBodyDigest(req *http.Request) ([sha256.Size]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return sha256.Sum256(nil), nil
	}
	orig := req.Body
	b, err := io.ReadAll(io.LimitReader(orig, SentinelMaxSignedBody+1))
	if err != nil {
		_ = orig.Close()
		return [sha256.Size]byte{}, err
	}
	if len(b) > SentinelMaxSignedBody {
		// Too large to cover: hand back everything read plus the unread
		// remainder so the request still carries its full payload.
		req.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(b), orig), orig}
		return [sha256.Size]byte{}, errSentinelBodyTooLarge
	}
	_ = orig.Close()
	req.Body = io.NopCloser(bytes.NewReader(b))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	return sha256.Sum256(b), nil
}

func sentinelRequestMessageV2(method, path, rawQuery, ts string, bodySum [sha256.Size]byte) []byte {
	return []byte("v2\n" + method + "\n" + path + "\n" + rawQuery + "\n" + ts + "\n" + hex.EncodeToString(bodySum[:]))
}

// stampSentinelV2 adds the v2 header. sign produces the tagged signature for
// the canonical message. A body that cannot be covered (too large or
// unreadable) leaves the request v1-only; a require-v2 receiver then refuses it.
func stampSentinelV2(req *http.Request, ts string, sign func(msg []byte) string) {
	sum, err := requestBodyDigest(req)
	if err != nil {
		log.Printf("[sentinel-sig] not adding v2 signature to %s %s: %v", req.Method, req.URL.Path, err)
		return
	}
	req.Header.Set(SentinelHeaderSignatureV2, sign(sentinelRequestMessageV2(req.Method, req.URL.EscapedPath(), req.URL.RawQuery, ts, sum)))
}

func hmacHex(secret, msg []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))
}

func signV2HMAC(secret []byte) func([]byte) string {
	return func(msg []byte) string { return hmacHex(secret, msg) }
}

func signV2Ed25519(priv ed25519.PrivateKey) func([]byte) string {
	return func(msg []byte) string {
		return sentinelEd25519SigPrefix + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	}
}

// verifyRequestV2 checks the v2 header (HMAC hex, or tagged ed25519 when v has
// a key) against the canonical message. HMAC secret and/or v may be zero.
func verifyRequestV2(req *http.Request, tsStr string, secret []byte, v *SentinelVerifier) error {
	sig := req.Header.Get(SentinelHeaderSignatureV2)
	sum, err := requestBodyDigest(req)
	if err != nil {
		return errSentinelAuth
	}
	msg := sentinelRequestMessageV2(req.Method, req.URL.EscapedPath(), req.URL.RawQuery, tsStr, sum)
	if strings.HasPrefix(sig, sentinelEd25519SigPrefix) {
		if v == nil || !v.hasEd25519() {
			return errSentinelAuth
		}
		return v.verifyEd25519(msg, sig)
	}
	if len(secret) < SentinelMinSecretLen {
		return errSentinelAuth
	}
	if !hmacEqualStrings(hmacHex(secret, msg), sig) {
		return errSentinelAuth
	}
	return nil
}
