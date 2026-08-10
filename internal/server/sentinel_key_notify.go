package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/sentinel"
)

// Event-driven SSH key propagation (cloud #971).
//
// A box's host-side authorized_keys entry only becomes usable once the
// sentinel has pulled it into sshpiper's routing table. That pull runs on a
// 2-minute ticker, so a box created just after a tick reports RUNNING while
// SSH still answers `Permission denied (publickey)` — for up to two minutes,
// ~50s in the field. Every caller that trusts RUNNING (CI, agents, the
// create→ssh flow in the docs) fails its first connections.
//
// The daemon therefore tells the sentinel the moment its key set changes.
// The ticker stays exactly as it was: this is an accelerator, not a
// replacement, so a lost notification costs the old latency rather than
// leaving a box permanently unreachable.

// keyResyncTimeout bounds the notification. Long enough for the sentinel to
// pull the daemon's own /authorized-keys and rewrite the routing table on the
// same LAN hop, short enough that an unreachable sentinel can't stall a
// create for a user-visible amount of time.
const keyResyncTimeout = 5 * time.Second

// notifySentinelKeyChange asks the sentinel to re-pull this daemon's
// authorized keys now instead of on its next tick.
//
// Best-effort and synchronous. Synchronous because the point is that the key
// is live before the caller is told the box is ready — returning first and
// syncing after would restore the race in a narrower window. Best-effort
// because SSH readiness is not a precondition for the box existing: a
// sentinel that is unreachable, unconfigured, or too old to serve the
// endpoint leaves the box exactly as reachable as it was before this
// existed, and the periodic tick still converges.
func (s *ContainerServer) notifySentinelKeyChange(ctx context.Context, reason string) {
	sentinelURL := s.peerPool.SentinelURL()
	if sentinelURL == "" {
		// Standalone daemon (no sentinel in front of it): nothing routes
		// SSH through sshpiper, so there is nothing to resync.
		return
	}
	secret := loadSentinelHMACSecret()
	if len(secret) < auth.SentinelMinSecretLen {
		// The same misconfiguration that already breaks the sentinel's
		// periodic pull (#687). Logged there in detail; don't repeat it on
		// every create.
		return
	}

	ctx, cancel := context.WithTimeout(ctx, keyResyncTimeout)
	defer cancel()

	resp, err := postKeyResync(ctx, sentinelURL, s.peerPool.LocalBackendID(), reason, secret)
	if err != nil {
		log.Printf("[keysync-notify] sentinel resync after %s failed: %v "+
			"(the box is created; SSH becomes reachable on the sentinel's next periodic keysync instead)", reason, err)
		return
	}
	if !resp.Synced {
		// The sentinel accepted the call but its own pull of this daemon's
		// /authorized-keys failed — most often a mismatched
		// CONTAINARIUM_SENTINEL_AUTH_SECRET (#687), which the sentinel logs
		// in full. Say so rather than reporting a success the box can't
		// cash: SSH stays broken until that is fixed, tick or no tick.
		log.Printf("[keysync-notify] sentinel accepted the resync after %s but its key pull from this daemon failed "+
			"— SSH will not work until that is fixed; check the sentinel log for the keysync error", reason)
		return
	}
	log.Printf("[keysync-notify] sentinel resynced after %s: %d users routed (coalesced=%v)", reason, resp.Users, resp.Coalesced)
}

// postKeyResync sends one signed resync request and decodes the reply. Split
// from notifySentinelKeyChange so the wire contract is testable without a
// wired ContainerServer.
func postKeyResync(ctx context.Context, sentinelURL, backendID, reason string, secret []byte) (*sentinel.KeyResyncResponse, error) {
	body, err := json.Marshal(sentinel.KeyResyncRequest{BackendID: backendID, Reason: reason})
	if err != nil {
		return nil, fmt.Errorf("marshal resync request: %w", err)
	}

	url := strings.TrimRight(sentinelURL, "/") + "/sentinel/keys/resync"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build resync request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, secret)

	resp, err := (&http.Client{Timeout: keyResyncTimeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("POST %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var out sentinel.KeyResyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode resync response: %w", err)
	}
	return &out, nil
}
