package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestStartContainer_PeerForwardAlsoStampsLastStartedAt (#1411): a
// container started via peer-forward must get the same anti-thrash
// stamp as one started locally. The stamp is what
// internal/autosleep's Decide rule 4 uses to give a just-woken
// container 2x its idle threshold of grace before it can be slept
// again — without it, a box woken on a peer can be slept seconds
// later.
//
// Local Start fails on this daemon (the container isn't here), a real
// HTTP peer accepts the forwarded start, and this daemon's own
// SetConfig call must still fire — mirroring exactly what already
// happens on the local-success path just above it in StartContainer.
func TestStartContainer_PeerForwardAlsoStampsLastStartedAt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/containers":
			// FindContainerPeer's discovery call — this peer reports it
			// has alice-container, so the daemon forwards Start to it.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"containers":[{"name":"alice-container","username":"alice","state":"CONTAINER_STATE_RUNNING"}]}`))
		case r.Method == "POST" && r.URL.Path == "/v1/containers/alice/start":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"started on peer"}`))
		default:
			t.Errorf("unexpected forwarded request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	mock := incustest.NewMockBackend()
	mock.StartContainerFunc = func(string) error { return errors.New("container not found on this backend") }
	var (
		mu         sync.Mutex
		stampCalls []struct{ name, key, value string }
	)
	mock.SetConfigFunc = func(name, key, value string) error {
		mu.Lock()
		defer mu.Unlock()
		stampCalls = append(stampCalls, struct{ name, key, value string }{name, key, value})
		return nil
	}

	pp := NewPeerPool("local-vm", "", nil, "")
	peer := peerClientFor(srv)
	peer.Healthy = true
	pp.peers["peer-1"] = peer

	s := &ContainerServer{
		manager:  container.NewWithBackend(mock),
		peerPool: pp,
	}

	resp, err := s.StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	if resp == nil {
		t.Fatal("expected a response on a successful peer-forward")
	}

	mu.Lock()
	defer mu.Unlock()
	for _, c := range stampCalls {
		if c.key == incus.LastStartedAtKey && c.name == "alice-container" {
			return
		}
	}
	t.Fatalf("expected SetConfig(alice-container, %q) after a successful peer-forward; calls=%+v",
		incus.LastStartedAtKey, stampCalls)
}
