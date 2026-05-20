package sentinel

import (
	"io"
	"log"
	"net/http"
	"os"
	"sync"

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
// The secret is read lazily on first request and cached for the
// lifetime of the process. A missing or short secret is logged once
// — the request is still issued (unsigned, will get 401 from the
// daemon) so the operator sees clear keysync errors in the log
// rather than silent breakage at a different layer.

var (
	sentinelSecretOnce sync.Once
	sentinelSecret     []byte
)

func loadSentinelSecret() []byte {
	sentinelSecretOnce.Do(func() {
		raw := os.Getenv("CONTAINARIUM_SENTINEL_AUTH_SECRET")
		if raw == "" {
			log.Printf("[sentinel-auth] WARNING: CONTAINARIUM_SENTINEL_AUTH_SECRET is unset; daemon sentinel endpoints will reject every request")
			return
		}
		if len(raw) < auth.SentinelMinSecretLen {
			log.Printf("[sentinel-auth] WARNING: CONTAINARIUM_SENTINEL_AUTH_SECRET is %d bytes, want >=%d", len(raw), auth.SentinelMinSecretLen)
		}
		sentinelSecret = []byte(raw)
	})
	return sentinelSecret
}

// newSignedRequest constructs an HTTP request signed with the
// sentinel shared secret. `body` may be nil. Returns the same error
// surface as http.NewRequest so callers can wrap with context.
func newSignedRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if secret := loadSentinelSecret(); len(secret) >= auth.SentinelMinSecretLen {
		auth.SignSentinelRequest(req, secret)
	}
	return req, nil
}
