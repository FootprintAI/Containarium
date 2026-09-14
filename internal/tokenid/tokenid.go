// Package tokenid is the shared leaf for what a token issuer must keep to
// revoke a token it issued: the jti and its expiry.
//
// It exists so this one small type is importable by both internal/auth and
// internal/modelgateway without either importing the other:
// internal/modelgateway must not gain a dependency on internal/auth (it
// needs to stay usable standalone), and internal/auth still needs the exact
// same type so the two packages' mint functions return an identical result
// shape. internal/auth re-exports it as auth.MintedID (a type alias, not a
// wrapper struct), so callers on either side of that boundary use one
// identical type.
package tokenid

import "time"

// MintedID is what an issuer must keep to revoke a token it issued: the jti
// the mint stamped into the token and the expiry it signed, so a caller can
// later call Revoke(jti, expiresAt, reason) without re-parsing the token.
type MintedID struct {
	JTI       string
	ExpiresAt time.Time
}
