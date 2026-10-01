package anonbox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The claim token (design §Contracts "Claim token", #2199):
//
//	v1.<box_name>.<fp_hash>.<exp_unix>.<token_id>.<hmac>
//
// where hmac = HMAC-SHA256(secret, "v1.<box_name>.<fp_hash>.<exp_unix>.<token_id>")
// and secret = TokenManager.DeriveSharedSecret("anon-claim", box_name).
//
// The token is stored nowhere but inside the guest; everything needed to
// verify it is the box's own labels (fp_hash, claim_token_id, claimed_at)
// plus a secret the daemon re-derives from its signing key on demand. A
// '.' can occur in none of the fields (box names are [a-z0-9-], the rest
// hex/decimal), so the split is unambiguous.

// TokenVersion is the leading field.
const TokenVersion = "v1"

// ClaimToken is a parsed token, before or after verification.
type ClaimToken struct {
	BoxName   string
	FPHash    string
	ExpiresAt time.Time
	TokenID   string
}

var (
	// ErrTokenMalformed: not six fields, wrong version, or a field that
	// does not parse.
	ErrTokenMalformed = errors.New("anonbox: malformed claim token")
	// ErrTokenSignature: the HMAC does not verify under the box's secret.
	ErrTokenSignature = errors.New("anonbox: claim token signature invalid")
	// ErrTokenExpired: exp has passed.
	ErrTokenExpired = errors.New("anonbox: claim token expired")
)

// MintClaimToken signs t under secret. An empty secret is refused: a token
// signed with "" would verify under "" everywhere.
func MintClaimToken(secret string, t ClaimToken) (string, error) {
	if secret == "" {
		return "", errors.New("anonbox: mint claim token: empty secret")
	}
	if t.BoxName == "" || t.FPHash == "" || t.TokenID == "" || t.ExpiresAt.IsZero() {
		return "", errors.New("anonbox: mint claim token: box, fp_hash, token_id and expiry are required")
	}
	for _, f := range []string{t.BoxName, t.FPHash, t.TokenID} {
		if strings.Contains(f, ".") {
			return "", fmt.Errorf("anonbox: mint claim token: field %q may not contain '.'", f)
		}
	}
	payload := tokenPayload(t)
	return payload + "." + tokenMAC(secret, payload), nil
}

// ParseClaimToken splits a token into its fields WITHOUT verifying it —
// the caller needs BoxName first to look the box up and derive the secret.
func ParseClaimToken(s string) (ClaimToken, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 6 || parts[0] != TokenVersion {
		return ClaimToken{}, ErrTokenMalformed
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || exp <= 0 {
		return ClaimToken{}, ErrTokenMalformed
	}
	if parts[1] == "" || parts[2] == "" || parts[4] == "" || parts[5] == "" {
		return ClaimToken{}, ErrTokenMalformed
	}
	return ClaimToken{BoxName: parts[1], FPHash: parts[2], ExpiresAt: time.Unix(exp, 0).UTC(), TokenID: parts[4]}, nil
}

// VerifyClaimToken parses s and checks its signature under secret and its
// expiry against now. Signature is checked before expiry so an attacker
// learns nothing about a box's expiry from a forged token.
func VerifyClaimToken(secret, s string, now time.Time) (ClaimToken, error) {
	t, err := ParseClaimToken(s)
	if err != nil {
		return ClaimToken{}, err
	}
	if secret == "" {
		return ClaimToken{}, ErrTokenSignature
	}
	parts := strings.Split(strings.TrimSpace(s), ".")
	want := tokenMAC(secret, tokenPayload(t))
	if !hmac.Equal([]byte(want), []byte(parts[5])) {
		return ClaimToken{}, ErrTokenSignature
	}
	if !now.Before(t.ExpiresAt) {
		return ClaimToken{}, ErrTokenExpired
	}
	return t, nil
}

func tokenPayload(t ClaimToken) string {
	return strings.Join([]string{TokenVersion, t.BoxName, t.FPHash, strconv.FormatInt(t.ExpiresAt.Unix(), 10), t.TokenID}, ".")
}

func tokenMAC(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
