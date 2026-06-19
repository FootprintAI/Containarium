// Package modelgateway is a prototype of the agent model gateway
// (docs/AGENT-MODEL-GATEWAY-DESIGN.md): a single egress point that holds the
// provider API key and brokers every agent box's model calls, so the key never
// lives in a box. A box presents a short-lived, scoped *gateway token* instead
// of a raw provider key; the gateway validates it, injects the real key (held
// only here), proxies to the provider, and meters token usage per tenant.
//
// This implements Phase 0 (transparent proxy + key custody) and Phase 1
// (metering) of the design note. Caching, central tiering, rate-limiting, and
// persistent rollups are later phases. Mechanism-only — no named tenants,
// skills, or packs.
package modelgateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// gatewayIssuer scopes the JWT to this gateway so a platform JWT minted for
// another purpose can't be replayed against the model egress.
const gatewayIssuer = "containarium-model-gateway"

// GatewayClaims is the model-gateway token: a scoped, short-lived credential a
// box presents instead of a raw provider key. It is signed HS256 with the
// daemon's shared secret (the same trust root as the platform JWT — no new
// PKI), carries the attribution the gateway meters by, and the model ceiling it
// enforces.
//
// In production this is minted inside the daemon's provisionSkillBox alongside
// the platform JWT (the design's "no new mint verb" point); the prototype's
// `mint` subcommand calls MintToken directly for testing.
type GatewayClaims struct {
	Tenant        string   `json:"tenant"`
	SkillID       string   `json:"skill_id,omitempty"`
	RunID         string   `json:"run_id,omitempty"`
	Provider      string   `json:"provider"`
	AllowedModels []string `json:"allowed_models,omitempty"`
	jwt.RegisteredClaims
}

// MintToken signs a gateway token bound to one tenant/provider, expiring after
// ttl.
func MintToken(secret []byte, c GatewayClaims, ttl time.Duration) (string, error) {
	if c.Tenant == "" {
		return "", fmt.Errorf("tenant required")
	}
	if c.Provider == "" {
		return "", fmt.Errorf("provider required")
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := time.Now()
	c.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    gatewayIssuer,
		Subject:   c.Tenant,
		ID:        hex.EncodeToString(jti),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(secret)
}

// VerifyToken validates signature, issuer, and expiry, returning the claims.
func VerifyToken(secret []byte, tokenString string) (*GatewayClaims, error) {
	claims := &GatewayClaims{}
	tok, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	}, jwt.WithIssuer(gatewayIssuer), jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}
