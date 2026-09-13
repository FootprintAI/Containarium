// Package tokenid is the shared leaf for what a token issuer must keep to
// revoke a token it issued: the jti and its expiry. It exists so that
// internal/modelgateway — which imports no other internal/ package, to keep
// the model-gateway usable standalone (see internal/modelgateway's package
// doc) — can share this one small type with internal/auth without pulling in
// the rest of the auth package.
//
// internal/auth re-exports this as auth.MintedID (a type alias, not a
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
