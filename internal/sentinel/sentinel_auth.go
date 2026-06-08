package sentinel

import (
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// Sentinel-to-daemon authentication.
//
// Several daemon endpoints (/certs, /authorized-keys,
// /authorized-keys/sentinel) are now HMAC-gated. The shared secret
// lives in CONTAINARIUM_SENTINEL_AUTH_SECRET on both ends. This file
// is the sentinel side: a small helper that builds an HTTP request,
// stamps the auth headers, and returns it. Callers (keysync,
// certsync) replace bare client.Get / client.Post with
// client.Do(newSignedRequest(...)).
//
// The secret is loaded once and cached. A missing or short secret
// triggers a per-call WARNING (rate-limited to once per
// sentinelMisconfigLogInterval) so an operator tailing the journal
// during an SSH-down incident sees the misconfiguration in real
// time, not just in a startup line that may have scrolled away
// (#341).

const sentinelMisconfigLogInterval = 60 * time.Second

var (
	sentinelSecretOnce sync.Once
	sentinelSecret     []byte

	// lastMisconfigLogNs is the unix-nanos of the last per-call
	// WARNING. atomic.Int64 so concurrent keysync + certsync calls
	// don't double-log every minute.
	lastMisconfigLogNs atomic.Int64
)

func loadSentinelSecret() []byte {
	sentinelSecretOnce.Do(func() {
		raw := os.Getenv("CONTAINARIUM_SENTINEL_AUTH_SECRET")
		switch {
		case raw == "":
			log.Printf("[sentinel-auth] WARNING: CONTAINARIUM_SENTINEL_AUTH_SECRET is unset; daemon sentinel endpoints will reject every request")
		case len(raw) < auth.SentinelMinSecretLen:
			log.Printf("[sentinel-auth] WARNING: CONTAINARIUM_SENTINEL_AUTH_SECRET is %d bytes, want >=%d", len(raw), auth.SentinelMinSecretLen)
			sentinelSecret = []byte(raw)
		default:
			sentinelSecret = []byte(raw)
		}
	})
	return sentinelSecret
}

// newSignedRequest constructs an HTTP request signed with the
// sentinel shared secret. `body` may be nil. Returns the same error
// surface as http.NewRequest so callers can wrap with context.
//
// If the shared secret is missing or short, the request is built
// anyway (it will 401 at the daemon) and a per-call WARNING is
// emitted at most once per sentinelMisconfigLogInterval so the
// operator sees the misconfig in current logs, not just at startup.
func newSignedRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if secret := loadSentinelSecret(); len(secret) >= auth.SentinelMinSecretLen {
		auth.SignSentinelRequest(req, secret)
	} else {
		logSentinelMisconfigOncePerInterval()
	}
	return req, nil
}

func logSentinelMisconfigOncePerInterval() {
	now := time.Now().UnixNano()
	last := lastMisconfigLogNs.Load()
	if last != 0 && now-last < int64(sentinelMisconfigLogInterval) {
		return
	}
	if !lastMisconfigLogNs.CompareAndSwap(last, now) {
		return
	}
	log.Printf("[sentinel-auth] WARNING: CONTAINARIUM_SENTINEL_AUTH_SECRET unconfigured; outbound sentinel→daemon requests will 401 (every keysync/certsync cycle is failing — fix the env var on this host)")
}
