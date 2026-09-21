package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// peerBackendFor serves one peer whose /v1/system/info answers with the given
// JSON body and returns that peer's entry from ListBackends.
func peerBackendFor(t *testing.T, systemInfoJSON string) *pb.BackendInfo {
	t.Helper()
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/system/info" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(systemInfoJSON))
	}))
	t.Cleanup(peerSrv.Close)

	pool := NewPeerPool("local-spot", "", nil, "")
	pool.mu.Lock()
	pool.peers["tunnel-peer"] = &PeerClient{
		ID:      "tunnel-peer",
		Addr:    peerSrv.Listener.Addr().String(),
		Healthy: true,
		client:  peerSrv.Client(),
	}
	pool.mu.Unlock()

	s := &ContainerServer{peerPool: pool, startTime: time.Now().Add(-time.Minute)}
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
	resp, err := s.ListBackends(ctx, &pb.ListBackendsRequest{})
	if err != nil {
		t.Fatalf("ListBackends: %v", err)
	}
	for _, b := range resp.Backends {
		if b.Id == "tunnel-peer" {
			return b
		}
	}
	t.Fatal("tunnel-peer missing from the backend list")
	return nil
}

// The fleet view must carry each peer's Incus server version, so an operator
// can audit daemon patch levels from one admin call instead of per-host
// shell access.
func TestListBackends_PeerReportsIncusVersion(t *testing.T) {
	peer := peerBackendFor(t, `{"info":{"hostname":"byoc-host","incusVersion":"6.23"}}`)
	// protojson fails the WHOLE decode on an unknown field, so check a field
	// from outside the one under test: otherwise a drifted payload reads as
	// "version dropped" rather than "this test's JSON is wrong".
	if peer.Hostname != "byoc-host" {
		t.Fatalf("Hostname = %q — the peer's SystemInfo did not decode at all", peer.Hostname)
	}
	if peer.IncusVersion != "6.23" {
		t.Errorf("IncusVersion = %q, want %q", peer.IncusVersion, "6.23")
	}
}

// An empty version means "unknown", e.g. a peer whose daemon could not read
// its Incus server info. It must stay empty, never a guessed value.
func TestListBackends_PeerWithoutIncusVersionIsEmpty(t *testing.T) {
	peer := peerBackendFor(t, `{"info":{"hostname":"old-peer"}}`)
	if peer.IncusVersion != "" {
		t.Errorf("IncusVersion = %q, want empty for a peer that reported none", peer.IncusVersion)
	}
}
