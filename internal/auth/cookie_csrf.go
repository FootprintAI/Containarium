package auth

import (
	"net/http"
	"net/url"
	"strings"
)

// Cookie-authenticated mutations are the one place a browser attaches the
// credential on its own, so they are the one place a cross-site (or
// same-site sibling host) page can forge a request. SameSite=Lax does not
// cover a sibling host, so the middleware also checks where the request
// came from (#3338). Bearer-header requests are unaffected: a page cannot
// attach that header to a forged request.

// cookieMutationBlockedReason is written into the 403 body so the refusal is
// not mistaken for a bad token.
const cookieMutationBlockedReason = "cross-origin request refused for cookie-authenticated mutation"

// SetCookieMutationOrigins sets the Origin allow-list for state-changing
// requests authenticated by the session cookie. It is the same list the CORS
// layer uses, so a UI served from an origin the operator already trusts keeps
// working. Call it before serving traffic.
func (am *AuthMiddleware) SetCookieMutationOrigins(origins []string) {
	am.cookieOrigins = origins
}

// isSafeMethod reports whether the method is read-only by definition and
// therefore not subject to the cookie origin check.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// cookieMutationAllowed decides whether a cookie-authenticated, state-changing
// request came from a page this daemon trusts.
//
// Sec-Fetch-Site is set by the browser and cannot be forged by a page, so
// "same-origin" is accepted outright: it is the embedded UI calling its own
// host. Any other value falls through to the Origin allow-list, which is what
// admits a separately served UI. A request carrying neither header (a
// non-browser client holding a cookie) is refused: browsers always send
// Origin on non-GET requests, so absence is not evidence of a trusted page.
func (am *AuthMiddleware) cookieMutationAllowed(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		return false
	}
	for _, allowed := range am.cookieOrigins {
		if origin == allowed {
			return true
		}
	}
	// No Sec-Fetch-Site (older browser): fall back to comparing the Origin's
	// host with the Host the request was sent to.
	if r.Header.Get("Sec-Fetch-Site") == "" {
		if u, err := url.Parse(origin); err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host) {
			return true
		}
	}
	return false
}
