package server

import (
	"sync"
	"time"
)

// serviceTokenTTL / serviceTokenRenewBefore configure the internal admin
// token's lifetime and renewal margin. A short TTL (vs. the old 30-day max)
// bounds a leaked internal token's usefulness; renewBefore re-mints well
// ahead of expiry so no in-flight peer call ever races the cutover.
const (
	serviceTokenTTL         = 1 * time.Hour
	serviceTokenRenewBefore = 10 * time.Minute
)

// serviceTokenSource mints and caches the internal admin ("_system") JWT the
// daemon uses to call peers' admin-only endpoints (peer metrics, and the
// #1029 capacity-ranking probe), re-minting it before it expires.
//
// It replaces the previous pattern of minting ONE token for the full 30-day
// max and holding the string forever: a daemon that outlived the token then
// 401'd every internal peer call, silently and with no log line — the same
// silent-credential-death shape as the BYOC driver-token expiry (#903). A
// short TTL with automatic renewal removes that cliff and shrinks the blast
// radius of a leaked internal token to `ttl` rather than a month.
//
// Token() is safe for concurrent use.
type serviceTokenSource struct {
	mint        func() (string, error) // mints a fresh token with lifetime ttl
	ttl         time.Duration          // lifetime requested from mint
	renewBefore time.Duration          // re-mint once less than this remains
	now         func() time.Time       // clock seam for tests

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// newServiceTokenSource builds a source that mints tokens of lifetime ttl and
// renews them once less than renewBefore remains. mint is expected to request a
// token of (at least) ttl; the source assumes the minted token is good for ttl
// from now.
func newServiceTokenSource(mint func() (string, error), ttl, renewBefore time.Duration) *serviceTokenSource {
	return &serviceTokenSource{
		mint:        mint,
		ttl:         ttl,
		renewBefore: renewBefore,
		now:         time.Now,
	}
}

// Token returns a currently-valid token, minting a fresh one when the cache is
// empty or within renewBefore of expiry. If a re-mint fails but the cached
// token is still valid (not yet expired), the cached token is returned so a
// transient signer hiccup doesn't break internal calls; only an empty cache
// surfaces the mint error.
func (s *serviceTokenSource) Token() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.token != "" && now.Before(s.expiry.Add(-s.renewBefore)) {
		return s.token, nil
	}

	tok, err := s.mint()
	if err != nil {
		if s.token != "" && now.Before(s.expiry) {
			return s.token, nil // fall back to the still-valid cached token
		}
		return "", err
	}
	s.token = tok
	s.expiry = now.Add(s.ttl)
	return tok, nil
}
