package auth

import (
	"net/http"
	"strings"
)

// Phase 1.5 — WebSocket subprotocol auth.
//
// Browsers can't attach arbitrary headers to a `new WebSocket(url)`
// call. The two workarounds are (a) put the token in `?token=`
// (audit A-MED-3: leaks to access logs, proxy logs, browser
// history) or (b) put it in the WebSocket subprotocol header
// `Sec-WebSocket-Protocol` (the only header the browser API
// exposes on connect). We standardize on (b).
//
// Wire shape: the browser opens the socket as
//
//   new WebSocket(url, ["containarium.bearer", "<jwt>"])
//
// which sets `Sec-WebSocket-Protocol: containarium.bearer, <jwt>`.
// The server reads the second token, validates the JWT, and
// **acks the subprotocol back as just "containarium.bearer"**
// (the JWT itself is not echoed — RFC 6455 requires the ack to
// match one of the client's offered subprotocols, but gorilla
// lets us pick which one).
//
// Backwards compatibility: Authorization header and `?token=`
// query are still accepted, but `?token=` use is logged with
// a deprecation WARNING so operators can find affected clients.
// Once telemetry shows no `?token=` traffic, the query path will
// be removed.

const (
	// WSSubprotocolBearer is the WebSocket subprotocol name
	// clients announce when they want to attach a JWT via the
	// Sec-WebSocket-Protocol header. The server echoes this
	// value back (without the token) to complete the upgrade.
	WSSubprotocolBearer = "containarium.bearer"
)

// TokenSource describes where a bearer token was extracted
// from, for logging / deprecation telemetry.
type TokenSource int

const (
	TokenSourceNone TokenSource = iota
	TokenSourceSubprotocol
	TokenSourceAuthorizationHeader
	TokenSourceQueryParam
)

func (s TokenSource) String() string {
	switch s {
	case TokenSourceSubprotocol:
		return "subprotocol"
	case TokenSourceAuthorizationHeader:
		return "authorization-header"
	case TokenSourceQueryParam:
		return "query-param"
	default:
		return "none"
	}
}

// ExtractBearerForUpgrade pulls a bearer token from an HTTP
// request that is about to be upgraded to WebSocket (or a
// streaming endpoint like SSE). Search order:
//
//  1. Sec-WebSocket-Protocol — first non-"containarium.bearer"
//     entry. This is the preferred form.
//  2. Authorization: Bearer <token>
//  3. ?token=<token> — deprecated, kept for backwards-compat.
//
// Returns the empty string + TokenSourceNone if no token is
// present. Callers MUST still validate the token before
// trusting it; this function only locates the bytes.
func ExtractBearerForUpgrade(r *http.Request) (token string, source TokenSource) {
	// 1. Sec-WebSocket-Protocol. http.Header normalizes the key.
	//
	// The value is a comma-separated list per RFC 6455 §4.1; the
	// browser sends every entry of the JS subprotocol array as
	// one comma-separated header. We look for the bearer marker
	// and treat the *next* non-marker entry as the token.
	if v := r.Header.Get("Sec-WebSocket-Protocol"); v != "" {
		entries := splitSubprotocols(v)
		sawMarker := false
		for _, e := range entries {
			if e == WSSubprotocolBearer {
				sawMarker = true
				continue
			}
			if sawMarker && e != "" {
				return e, TokenSourceSubprotocol
			}
		}
		// Some clients send the JWT as the only entry without
		// the marker. That's still better than ?token=; accept
		// it if it looks like a JWT (3 dot-separated b64 parts).
		for _, e := range entries {
			if looksLikeJWT(e) {
				return e, TokenSourceSubprotocol
			}
		}
	}

	// 2. Authorization header.
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
		return strings.TrimPrefix(v, "Bearer "), TokenSourceAuthorizationHeader
	}

	// 3. Legacy query param. Deprecated — callers log WARNING.
	if v := r.URL.Query().Get("token"); v != "" {
		return v, TokenSourceQueryParam
	}

	return "", TokenSourceNone
}

// AckSubprotocol returns the value the server should reply
// with in Sec-WebSocket-Protocol when the client used the
// bearer subprotocol. Echoing the marker (without the token)
// completes RFC 6455's subprotocol negotiation; the token
// itself never appears in the response.
//
// Returns the empty string if the request didn't use the
// subprotocol form — the server should then omit the response
// header entirely (gorilla does this when no subprotocol is
// selected).
func AckSubprotocol(r *http.Request) string {
	if v := r.Header.Get("Sec-WebSocket-Protocol"); v != "" {
		for _, e := range splitSubprotocols(v) {
			if e == WSSubprotocolBearer {
				return WSSubprotocolBearer
			}
		}
	}
	return ""
}

// splitSubprotocols parses a comma-separated subprotocol list,
// trimming whitespace and dropping empty entries.
func splitSubprotocols(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// looksLikeJWT is a cheap structural check — three
// non-empty dot-separated segments, all base64url-ish
// (alphanumeric + `-_=`). We don't verify the signature
// here; this is just a heuristic for the "subprotocol
// without marker" fallback path.
func looksLikeJWT(s string) bool {
	if len(s) < 16 {
		return false
	}
	segs := strings.Split(s, ".")
	if len(segs) != 3 {
		return false
	}
	for _, seg := range segs {
		if seg == "" {
			return false
		}
		for _, c := range seg {
			if !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' && c != '_' && c != '=' {
				return false
			}
		}
	}
	return true
}
