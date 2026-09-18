package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestListContainers_ReportsUnreachablePeerInsteadOfSilentlyDroppingIt
// (#1902, sibling of #1901's GetMetrics fix): before this fix, a peer the
// sentinel marked unhealthy contributed zero containers to the fleet-wide
// ListContainers response with nothing but a server-side log line — making
// every container on that backend disappear from the list exactly like a
// backend that genuinely has no containers. The fix reports the skipped
// peer in unreachable_backends so callers can tell the two apart.
func TestListContainers_ReportsUnreachablePeerInsteadOfSilentlyDroppingIt(t *testing.T) {
	mock := incustest.NewMockBackend()

	pp := NewPeerPool("local-vm", "", nil, "")
	unhealthy := &PeerClient{ID: "containarium-jump-ase1-prod", Healthy: false}
	pp.peers[unhealthy.ID] = unhealthy

	s := &ContainerServer{
		manager:  container.NewWithBackend(mock),
		peerPool: pp,
	}

	resp, err := s.ListContainers(adminListCtx(), &pb.ListContainersRequest{})
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}

	if len(resp.Containers) != 0 {
		t.Errorf("expected no containers (no local containers, one unhealthy peer), got %d", len(resp.Containers))
	}
	if len(resp.UnreachableBackends) != 1 {
		t.Fatalf("expected exactly one unreachable backend reported, got %d: %+v", len(resp.UnreachableBackends), resp.UnreachableBackends)
	}
	got := resp.UnreachableBackends[0]
	if got.BackendId != "containarium-jump-ase1-prod" {
		t.Errorf("BackendId = %q, want %q", got.BackendId, "containarium-jump-ase1-prod")
	}
	if got.Reason == "" {
		t.Error("expected a non-empty Reason explaining why the peer is unreachable")
	}
}

// TestListContainers_ReportsPeerFetchFailure covers the sibling case: the
// sentinel says the peer is healthy, but the forwarded request itself
// fails. That must also be reported, not just logged server-side and
// dropped.
func TestListContainers_ReportsPeerFetchFailure(t *testing.T) {
	mock := incustest.NewMockBackend()

	pp := NewPeerPool("local-vm", "", nil, "")
	// A healthy peer with no reachable HTTP server behind it — the
	// fetch itself fails, distinct from the sentinel-unhealthy case.
	failing := &PeerClient{
		ID: "peer-flaky", Healthy: true, Addr: "127.0.0.1:1",
		client: &http.Client{Timeout: 2 * time.Second},
	}
	pp.peers[failing.ID] = failing

	s := &ContainerServer{
		manager:  container.NewWithBackend(mock),
		peerPool: pp,
	}

	resp, err := s.ListContainers(adminListCtx(), &pb.ListContainersRequest{})
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}

	if len(resp.UnreachableBackends) != 1 || resp.UnreachableBackends[0].BackendId != "peer-flaky" {
		t.Fatalf("expected peer-flaky reported as unreachable, got %+v", resp.UnreachableBackends)
	}
}
