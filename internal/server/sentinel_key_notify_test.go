package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/sentinel"
)

// testHMACSecret is long enough to satisfy auth.SentinelMinSecretLen.
var testHMACSecret = []byte("0123456789abcdef0123456789abcdef")

// The daemon's notification must pass the sentinel's real HMAC gate — a
// request the middleware rejects would leave the box unreachable for the
// full tick, which is the bug this whole path exists to fix.
func TestPostKeyResync_PassesSentinelHMACGate(t *testing.T) {
	var gotBody atomic.Value
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req sentinel.KeyResyncRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		gotBody.Store(req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sentinel.KeyResyncResponse{Synced: true, Users: 3})
	})

	mux := http.NewServeMux()
	mux.Handle("/sentinel/keys/resync", auth.SentinelHMACMiddleware(testHMACSecret, inner))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := postKeyResync(context.Background(), srv.URL, "backend-a", "create_container cld-1a2b", testHMACSecret)
	if err != nil {
		t.Fatalf("postKeyResync: %v", err)
	}
	if !resp.Synced || resp.Users != 3 {
		t.Fatalf("response = %+v, want Synced=true Users=3", resp)
	}

	req, _ := gotBody.Load().(sentinel.KeyResyncRequest)
	if req.BackendID != "backend-a" {
		t.Errorf("BackendID = %q, want %q", req.BackendID, "backend-a")
	}
	if req.Reason != "create_container cld-1a2b" {
		t.Errorf("Reason = %q, want the create reason", req.Reason)
	}
}

func TestPostKeyResync_WrongSecretRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/sentinel/keys/resync", auth.SentinelHMACMiddleware(testHMACSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not be reached with a mismatched secret")
	})))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := postKeyResync(context.Background(), srv.URL, "backend-a", "test", []byte("ffffffffffffffffffffffffffffffff"))
	if err == nil {
		t.Fatal("expected an error for a mismatched HMAC secret")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error = %v, want it to report the 401", err)
	}
}

// A sentinel too old to serve the endpoint (or any other non-200) must
// surface as an error the caller logs, never as a silent success.
func TestPostKeyResync_NotFoundIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	if _, err := postKeyResync(context.Background(), srv.URL, "backend-a", "test", testHMACSecret); err == nil {
		t.Fatal("expected an error for a 404 from the sentinel")
	}
}

func TestPostKeyResync_TrailingSlashInSentinelURL(t *testing.T) {
	var path atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path.Store(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sentinel.KeyResyncResponse{Synced: true})
	}))
	defer srv.Close()

	if _, err := postKeyResync(context.Background(), srv.URL+"/", "backend-a", "test", testHMACSecret); err != nil {
		t.Fatalf("postKeyResync: %v", err)
	}
	if got, _ := path.Load().(string); got != "/sentinel/keys/resync" {
		t.Fatalf("path = %q, want /sentinel/keys/resync", got)
	}
}

// A daemon with no sentinel in front of it (standalone, or a test server)
// has nothing to notify. It must no-op rather than panic on the nil pool —
// this runs on every create.
func TestNotifySentinelKeyChange_NoSentinelIsNoOp(t *testing.T) {
	s := &ContainerServer{}
	s.notifySentinelKeyChange(context.Background(), "create_container test")

	s = &ContainerServer{peerPool: NewPeerPool("backend-a", "", nil, "pool-a")}
	s.notifySentinelKeyChange(context.Background(), "create_container test")
}
