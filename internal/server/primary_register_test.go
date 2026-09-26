package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// /sentinel/primaries is HMAC-gated the same as /sentinel/keys/resync — a
// request runPrimaryRegistration sends without a valid signature would be
// silently rejected by the sentinel, leaving the primary unregistered with
// nothing but a log line to show for it. These tests pin that the client
// actually signs every call it makes (register, and deregister on context
// cancellation), the same way TestPostKeyResync_PassesSentinelHMACGate pins
// it for the key-resync notifier.

// newPrimariesRegisterTestServer wraps real handlers in the REAL
// auth.SentinelHMACMiddleware, mirroring exactly what the sentinel's own
// binary-server mux does for /sentinel/primaries — an unsigned or
// wrongly-signed request must 401 here exactly as it would in production.
// received counts every request that reaches the server AT ALL, wired ahead
// of the auth gate — unlike posts/deletes (which only count requests the
// gate accepted), this is what distinguishes "the client never attempted the
// call" from "it attempted the call and the gate rejected it": both leave
// posts/deletes at 0, but only the latter leaves received above 0.
func newPrimariesRegisterTestServer(t *testing.T, secret []byte) (srv *httptest.Server, posts, deletes, received *atomic.Int32) {
	t.Helper()
	posts, deletes, received = &atomic.Int32{}, &atomic.Int32{}, &atomic.Int32{}

	mux := http.NewServeMux()
	mux.Handle("/sentinel/primaries", auth.SentinelHMACMiddleware(secret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		posts.Add(1)
		w.WriteHeader(http.StatusCreated)
	})))
	mux.Handle("/sentinel/primaries/", auth.SentinelHMACMiddleware(secret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPut:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	})))

	countThenServe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		mux.ServeHTTP(w, r)
	})

	srv = httptest.NewServer(countThenServe)
	t.Cleanup(srv.Close)
	return srv, posts, deletes, received
}

func TestRunPrimaryRegistration_RequestsCarryValidSignature(t *testing.T) {
	srv, posts, deletes, _ := newPrimariesRegisterTestServer(t, testHMACSecret)

	ctx, cancel := context.WithCancel(context.Background())
	runPrimaryRegistration(ctx, PrimaryRegisterConfig{
		SentinelURL:    srv.URL,
		Pool:           "p1",
		PublicHostname: "h1.example.com",
		Port:           443,
		Secret:         testHMACSecret,
	})

	// The initial POST happens synchronously inside runPrimaryRegistration,
	// before it returns — no wait needed for that one.
	if got := posts.Load(); got != 1 {
		t.Fatalf("signed POST reached the real HMAC-gated handler %d times, want 1 (a bad signature would 401 and never increment this)", got)
	}

	// Cancelling triggers the background goroutine's best-effort deregister
	// (a signed DELETE). Poll briefly rather than sleep a fixed amount.
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if deletes.Load() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := deletes.Load(); got != 1 {
		t.Fatalf("signed DELETE reached the real HMAC-gated handler %d times, want 1 on context cancellation", got)
	}
}

// TestRunPrimaryRegistration_SkipsWithoutAUsableSecret matches
// notifySentinelKeyChange's own guard (#687): rather than sending a request
// that's certain to be rejected, an absent or too-short secret must skip the
// call entirely.
func TestRunPrimaryRegistration_SkipsWithoutAUsableSecret(t *testing.T) {
	srv, _, _, received := newPrimariesRegisterTestServer(t, testHMACSecret)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runPrimaryRegistration(ctx, PrimaryRegisterConfig{
		SentinelURL:    srv.URL,
		Pool:           "p1",
		PublicHostname: "h1.example.com",
		Port:           443,
		Secret:         nil, // unusable
	})

	// received (not posts) is the discriminator here: signing with a nil/
	// too-short secret still produces A signature, just a wrong one, so a
	// send-anyway bug would also leave posts at 0 (the gate rejects it) —
	// that alone can't tell "skipped" from "sent and rejected" apart. Only
	// the server seeing zero requests AT ALL proves the call was skipped.
	if got := received.Load(); got != 0 {
		t.Fatalf("server received %d request(s) with no secret configured; want 0 (should skip the call entirely, not send an unsigned/wrongly-signed one)", got)
	}
}
