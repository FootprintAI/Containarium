package sentinel

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Peer proxy — `/peer/<backend-id>/*` forwards to that tunnel backend's
// daemon on the health port, so the control plane can drive a
// tunnel-joined host without opening extra external ports (#1102).
//
// Two properties this handler is responsible for:
//
//  1. It is registered behind SentinelHMACMiddleware(adminSecret) in
//     binaryserver.go. Every neighbouring /sentinel/* route is gated;
//     this one was not, which made it an unauthenticated hop to every
//     backend the sentinel fronts. The backend-id namespace here is flat
//     and global — every tunnel-joined backend across all organizations
//     is addressable — so an ungated caller could enumerate and probe
//     other tenants' daemons. The daemon's own auth still stood behind
//     it, so this closes a lateral-movement surface rather than an open
//     door, but it is the layer that is supposed to stop the probing.
//
//  2. Every rejection is byte-identical. A caller must not be able to
//     tell "that backend is not on this sentinel" from "that path is
//     malformed", and the response must never echo the requested id
//     back. Distinguishable rejections turn an authenticated-but-curious
//     caller into a fleet enumerator, one id at a time.

// peerNotFoundBody is the single rejection this handler ever produces.
// Deliberately says nothing about WHY — not the id, not whether it
// parsed, not whether such a backend exists elsewhere.
const peerNotFoundBody = "not found"

// PeerProxyHandler reverse-proxies /peer/<backend-id>/<rest> to that
// backend's daemon. Named-method shape (rather than the previous inline
// closure) so the gating and the uniform-404 behaviour are testable
// without standing up the whole binary server — matching CAHandler,
// PeerCertHandler and TunnelTokenRegisterHandler on this same mux.
func (m *Manager) PeerProxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendID, remainingPath, ok := splitPeerPath(r.URL.Path)
		if !ok {
			peerNotFound(w)
			return
		}

		backend := m.backends.Get(backendID)
		if backend == nil {
			// Same response as a malformed path, on purpose — see the
			// file comment. Previously this was `backend %q not found`,
			// which both confirmed the id was well-formed and reflected
			// it back to the caller.
			peerNotFound(w)
			return
		}

		target := &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("%s:%d", backend.IP, m.config.HealthPort),
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		r.URL.Path = remainingPath
		r.Host = target.Host
		proxy.ServeHTTP(w, r)
	})
}

// splitPeerPath parses `/peer/<backend-id>/<rest>` into its id and the
// daemon-relative remainder. ok is false for anything that doesn't carry
// both parts.
//
// Note the caller must treat !ok and "unknown backend" identically; this
// function only reports which it was so the proxy path can be skipped.
func splitPeerPath(p string) (backendID, remaining string, ok bool) {
	rest := strings.TrimPrefix(p, "/peer/")
	slashIdx := strings.Index(rest, "/")
	if slashIdx <= 0 {
		// No slash at all (`/peer/abc`), or a leading one (`/peer//v1/x`,
		// i.e. an empty backend id). Neither addresses a backend.
		return "", "", false
	}
	return rest[:slashIdx], rest[slashIdx:], true
}

func peerNotFound(w http.ResponseWriter) {
	http.Error(w, peerNotFoundBody, http.StatusNotFound)
}
