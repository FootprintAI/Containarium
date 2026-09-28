package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Purpose-separated secret derivation.
//
// Some daemon-to-component channels need a *shared* secret rather than a
// bearer JWT: the component has to verify the caller, and handing it the JWT
// signing key would hand it the power to mint tokens (HS256 — the verification
// key IS the signing key). The in-box A2A server is the first such case
// (#2125): it must be able to tell "the daemon sent this task" from "a peer box
// sent this task", inside a container that is itself the untrusted party.
//
// DeriveSharedSecret answers that with an HKDF-shaped derivation from the
// daemon's existing JWT signing key, so:
//
//   - there is nothing new for an operator to configure, and nothing new to
//     persist — the daemon recomputes any component's secret on demand, which
//     survives a daemon restart;
//   - the derivation is one-way, so a component that holds its own derived
//     secret learns nothing about the signing key or about any other
//     component's secret;
//   - `purpose` domain-separates uses, so two channels that both derive from
//     the same key never end up with the same value.
//
// Rotating the JWT signing key rotates every derived secret with it. A
// component seeded before the rotation then fails closed (its secret no longer
// matches) until it is reseeded — the fail-closed direction.

// DeriveSharedSecret returns the secret shared with one component: a
// deterministic, one-way function of the daemon's signing key, a purpose label
// and the component's id, hex-encoded (64 characters).
//
// purpose must be a stable constant (e.g. "containarium/a2a-box/v1"), never
// caller-controlled input, and id names the one component the secret is for.
// Both are fed in length-independent order with a separator that cannot occur
// in either, so no two (purpose, id) pairs can collide.
func (tm *TokenManager) DeriveSharedSecret(purpose, id string) string {
	if tm == nil || len(tm.secretKey) == 0 || purpose == "" || id == "" {
		return ""
	}
	mac := hmac.New(sha256.New, tm.secretKey)
	// "\x00" cannot appear in a purpose constant or a component id, so
	// (a, bc) and (ab, c) cannot hash to the same input.
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(id))
	return hex.EncodeToString(mac.Sum(nil))
}
