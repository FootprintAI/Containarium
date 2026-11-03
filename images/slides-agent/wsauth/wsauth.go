// Command slides-wsauth is the slides-agent image's in-box login helper
// (#3486). It turns the zero-click workspace link into a single-use, short-lived
// login token that never travels in a URL query, and keeps the browser's
// session cookie separate from any login token.
//
// Two loopback listeners, both inside the container on the box's host network:
//
//   - mintAddr (127.0.0.1:9099), for the daemon only: GET /__mint returns a
//     fresh single-use token as {"token":"..."}. The daemon's
//     GetWorkspaceAccess runs `curl http://127.0.0.1:9099/__mint` inside the
//     box (the same probe and port the chat workspace's helper answers) and
//     composes /__ws_login#t=<token>. The proxy never routes to this listener.
//   - proxyAddr (127.0.0.1:9098), for the Caddy proxy only: GET /__ws_login
//     serves the bootstrap page that reads the token from the URL fragment and
//     POSTs it; POST /__ws_login redeems the token once and sets the session
//     cookie; /__session answers Caddy's forward_auth check of that cookie.
//
// Tokens and sessions live in memory only: a helper restart (the container is
// recreated whenever the box re-stages its auth material) invalidates every
// unredeemed token and every session.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"time"
)

const (
	mintAddr  = "127.0.0.1:9099"
	proxyAddr = "127.0.0.1:9098"

	// tokenTTL bounds how long a minted login token can wait to be redeemed.
	tokenTTL = 120 * time.Second
	// sessionTTL bounds a session server-side; the browser cookie itself is a
	// session cookie (no Max-Age).
	sessionTTL = 24 * time.Hour
	// maxPending and maxSessions bound memory. Minting is in-box only; past
	// maxPending, mint refuses. Past maxSessions the oldest session is evicted.
	maxPending  = 256
	maxSessions = 1024

	sessionCookie = "ws_session"

	// cookieSameSite is the session cookie's SameSite attribute. None, as the
	// proxy used before #3486, so the cookie is still sent when the workspace
	// is embedded in an iframe on another site (a console). It can be narrowed
	// to http.SameSiteLaxMode once no consumer embeds the preview cross-site;
	// Lax stops the cookie on cross-site subrequests, which is what breaks an
	// iframe embed.
	cookieSameSite = http.SameSiteNoneMode

	// basicRealm matches Caddy's basic_auth default realm, so a browser that
	// is refused a session falls back to the same basic-auth credentials.
	basicRealm = `Basic realm="restricted"`
)

// secretPattern is the shape of every token and session value: 32 random
// bytes, unpadded base64url.
var secretPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

var (
	errTooManyPending = errors.New("too many unredeemed login tokens")
)

// mintResponse is the body of GET /__mint. A JSON object (rather than the bare
// token the chat workspace's helper prints) tells the daemon this box takes
// the token in the URL fragment.
type mintResponse struct {
	Token string `json:"token"`
}

type digest [sha256.Size]byte

func hashOf(s string) digest { return sha256.Sum256([]byte(s)) }

// store holds pending login tokens and live sessions, keyed by the SHA-256 of
// the secret so the lookup never compares a secret byte by byte.
type store struct {
	mu       sync.Mutex
	now      func() time.Time
	random   func([]byte) (int, error)
	tokens   map[digest]time.Time // token -> expiry
	sessions map[digest]time.Time // session -> expiry
}

func newStore(now func() time.Time) *store {
	return &store{
		now:      now,
		random:   rand.Read,
		tokens:   map[digest]time.Time{},
		sessions: map[digest]time.Time{},
	}
}

func (s *store) secret() (string, error) {
	b := make([]byte, 32)
	if _, err := s.random(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// gc drops expired tokens and sessions. Callers hold s.mu.
func (s *store) gc(now time.Time) {
	for k, exp := range s.tokens {
		if !now.Before(exp) {
			delete(s.tokens, k)
		}
	}
	for k, exp := range s.sessions {
		if !now.Before(exp) {
			delete(s.sessions, k)
		}
	}
}

// mint issues a single-use login token valid for tokenTTL.
func (s *store) mint() (string, error) {
	t, err := s.secret()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.gc(now)
	if len(s.tokens) >= maxPending {
		return "", errTooManyPending
	}
	s.tokens[hashOf(t)] = now.Add(tokenTTL)
	return t, nil
}

// redeem consumes a login token and, if it was pending and unexpired, returns
// a new session value. A token redeems at most once.
func (s *store) redeem(token string) (string, bool) {
	if !secretPattern.MatchString(token) {
		return "", false
	}
	sess, err := s.secret()
	if err != nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	key := hashOf(token)
	exp, ok := s.tokens[key]
	delete(s.tokens, key)
	if !ok || !now.Before(exp) {
		return "", false
	}
	s.gc(now)
	if len(s.sessions) >= maxSessions {
		s.evictOldest()
	}
	s.sessions[hashOf(sess)] = now.Add(sessionTTL)
	return sess, true
}

// evictOldest drops the session closest to expiry. Callers hold s.mu.
func (s *store) evictOldest() {
	var oldest digest
	var at time.Time
	first := true
	for k, exp := range s.sessions {
		if first || exp.Before(at) {
			oldest, at, first = k, exp, false
		}
	}
	if !first {
		delete(s.sessions, oldest)
	}
}

// burn invalidates a token without redeeming it.
func (s *store) burn(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, hashOf(token))
}

// valid reports whether a session value is live.
func (s *store) valid(session string) bool {
	if !secretPattern.MatchString(session) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[hashOf(session)]
	return ok && s.now().Before(exp)
}

// mintHandler serves the daemon-facing listener.
func mintHandler(s *store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /__mint", func(w http.ResponseWriter, r *http.Request) {
		// Defence in depth: the proxy never routes here, and a request that
		// came through any proxy carries X-Forwarded-For.
		if r.Header.Get("X-Forwarded-For") != "" {
			http.NotFound(w, r)
			return
		}
		t, err := s.mint()
		if err != nil {
			http.Error(w, "mint refused", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(mintResponse{Token: t})
	})
	return mux
}

// noStore sets the headers every bootstrap response carries: nothing cached,
// no Referer from this page or what it loads.
func noStore(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
}

func sessionCookieFor(value string) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: cookieSameSite,
	}
}

// proxyHandler serves the Caddy-facing listener.
func proxyHandler(s *store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /__ws_login", func(w http.ResponseWriter, r *http.Request) {
		noStore(w.Header())
		if t := r.URL.Query().Get("t"); t != "" {
			// A token in the query has been exposed in a request line (logs,
			// history): never redeem it.
			s.burn(t)
			http.Error(w, "login links no longer carry the token in the query; request a new link", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Security-Policy", bootstrapCSP)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(bootstrapPage))
	})
	mux.HandleFunc("POST /__ws_login", func(w http.ResponseWriter, r *http.Request) {
		noStore(w.Header())
		// Only the bootstrap page, on this origin, posts here. A browser
		// labels a cross-site form post; refuse it (login CSRF).
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			http.Error(w, "cross-site login refused", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		sess, ok := s.redeem(r.PostFormValue("t"))
		if !ok {
			// A reload of the same link (an embedding console re-rendering its
			// iframe) posts the spent token again: a browser that already
			// holds a live session goes on to the app, and gains nothing new.
			if c, err := r.Cookie(sessionCookie); err == nil && s.valid(c.Value) {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			http.Error(w, "this login link is invalid, expired or already used; request a new one or sign in with the workspace password", http.StatusForbidden)
			return
		}
		http.SetCookie(w, sessionCookieFor(sess))
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	// Caddy's forward_auth subrequest for every request carrying the session
	// cookie. 2xx lets the request through; anything else is written to the
	// client as is: 401 with the basic-auth challenge and the dead cookie
	// cleared, so the browser falls back to the workspace password.
	mux.HandleFunc("/__session", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil && s.valid(c.Value) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		expired := sessionCookieFor("")
		expired.MaxAge = -1
		http.SetCookie(w, expired)
		w.Header().Set("WWW-Authenticate", basicRealm)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	return mux
}

// bootstrapScript reads the token from the fragment (which a browser never
// sends to a server), drops it from the address bar and history, and posts it.
const bootstrapScript = `(function(){` +
	`var m=/(?:^#|&)t=([A-Za-z0-9_-]+)/.exec(location.hash);` +
	`history.replaceState(null,"",location.pathname);` +
	`if(!m){document.getElementById("msg").textContent="This login link has no token; request a new one.";return}` +
	`document.getElementById("t").value=m[1];document.getElementById("f").submit()})()`

const bootstrapPage = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Signing in</title></head>
<body><p id="msg">Signing in...</p>
<form id="f" method="post" action="/__ws_login"><input type="hidden" name="t" id="t"></form>
<noscript>One-click sign-in needs JavaScript; sign in with the workspace password instead.</noscript>
<script>` + bootstrapScript + `</script>
</body></html>
`

var bootstrapCSP = func() string {
	sum := sha256.Sum256([]byte(bootstrapScript))
	return "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
		"'; form-action 'self'; base-uri 'none'"
}()
