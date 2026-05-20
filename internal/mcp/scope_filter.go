package mcp

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/footprintai/containarium/internal/auth"
)

// Phase 1.7 — MCP-side enforcement of least-privilege
// scopes on the JWT.
//
// We decode the JWT payload WITHOUT verifying its signature.
// Two reasons:
//   1. The signature secret isn't on the MCP-server side —
//      it lives on the daemon, which does the canonical
//      check on every API call. The MCP server can't forge
//      a token even if it lies about the scopes it sees.
//   2. The point of the MCP-side filter is to refuse a
//      tools/list / tools/call BEFORE we hit the network,
//      so an agent that asks for an out-of-scope tool gets
//      a clean rejection instead of a wire round-trip.
//
// Even if a malicious agent edited its JWT to claim broader
// scopes, the daemon's verified check still gates the real
// call. The MCP filter is defense in depth, not the
// canonical authoritative layer.
//
// If the token can't be parsed (e.g. an opaque token, or
// malformed JWT) we treat it as "no scope restriction" —
// the daemon's check is still authoritative. We don't want
// to lock operators out of MCP just because their token
// shape is unusual.

// scopesFromJWT decodes the payload segment of a JWT and
// returns the `scopes` claim. Returns (nil, true) when the
// claim is absent — caller should treat as "no restriction"
// (HasScope's policy). Returns (nil, false) when the token
// is unparseable (e.g. an opaque non-JWT bearer) — same
// upstream policy.
func scopesFromJWT(token string) (scopes []string, parsed bool) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		// Some JWT issuers pad; fall back.
		payload, err = base64.URLEncoding.DecodeString(segments[1])
		if err != nil {
			return nil, false
		}
	}
	var claims struct {
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	return claims.Scopes, true
}

// allowedScopes returns the effective scope set for the
// MCP server's current JWT. Errors / no-token cases return
// nil (== no restriction, matching HasScope semantics).
func (s *Server) allowedScopes() []string {
	if s == nil || s.client == nil {
		return nil
	}
	token, err := s.client.readToken()
	if err != nil || token == "" {
		return nil
	}
	scopes, _ := scopesFromJWT(token)
	return scopes
}

// toolAllowed returns true when the tool's required scope
// is satisfied by the JWT's granted scopes. Wraps
// auth.HasScope so the policy lives in one place.
func toolAllowed(grantedScopes []string, tool *Tool) bool {
	return auth.HasScope(grantedScopes, tool.RequiredScope)
}
