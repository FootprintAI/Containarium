package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestGetMetrics_FleetWide_ReportsUnreachablePeerInsteadOfSilentlyDroppingIt
// (#1901): before this fix, a peer the sentinel marked unhealthy — even for
// one poll tick, e.g. mid-restart — contributed zero entries to the
// fleet-wide GetMetrics response with nothing but a server-side log line.
// The webui rendered that identically to "container has no usage yet",
// making a transient backend blip look like every container on that host
// had gone dark. The fix surfaces the skipped peer in
// `unreachable_backends` so callers can tell the two apart.
func TestGetMetrics_FleetWide_ReportsUnreachablePeerInsteadOfSilentlyDroppingIt(t *testing.T) {
	mock := incustest.NewMockBackend()

	pp := NewPeerPool("local-vm", "", nil, "")
	unhealthy := peerClientFor(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unhealthy peer should never be dialed for metrics, got %s %s", r.Method, r.URL.Path)
	})))
	unhealthy.ID = "containarium-jump-ase1-prod"
	unhealthy.Healthy = false
	pp.peers[unhealthy.ID] = unhealthy

	s := &ContainerServer{
		manager:  container.NewWithBackend(mock),
		peerPool: pp,
	}

	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
	resp, err := s.GetMetrics(ctx, &pb.GetMetricsRequest{})
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}

	if len(resp.Metrics) != 0 {
		t.Errorf("expected no metrics (no local containers, one unhealthy peer), got %d", len(resp.Metrics))
	}
	if len(resp.UnreachableBackends) != 1 {
		t.Fatalf("expected exactly one unreachable backend reported, got %d: %+v", len(resp.UnreachableBackends), resp.UnreachableBackends)
	}
	got := resp.UnreachableBackends[0]
	if got.BackendId != "containarium-jump-ase1-prod" {
		t.Errorf("BackendId = %q, want %q", got.BackendId, "containarium-jump-ase1-prod")
	}
	if !strings.Contains(got.Reason, "unhealthy") {
		t.Errorf("Reason = %q, want it to say why (marked unhealthy by sentinel)", got.Reason)
	}
}

// TestGetMetrics_FleetWide_ReportsPeerFetchFailure covers the sibling case:
// the sentinel says the peer is healthy, but the forwarded request itself
// fails (network error / non-2xx). That must also be reported, not just
// logged server-side and dropped.
func TestGetMetrics_FleetWide_ReportsPeerFetchFailure(t *testing.T) {
	mock := incustest.NewMockBackend()

	pp := NewPeerPool("local-vm", "", nil, "")
	failing := peerClientFor(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})))
	failing.ID = "peer-flaky"
	failing.Healthy = true
	pp.peers[failing.ID] = failing

	s := &ContainerServer{
		manager:  container.NewWithBackend(mock),
		peerPool: pp,
	}

	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
	resp, err := s.GetMetrics(ctx, &pb.GetMetricsRequest{})
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}

	if len(resp.UnreachableBackends) != 1 || resp.UnreachableBackends[0].BackendId != "peer-flaky" {
		t.Fatalf("expected peer-flaky reported as unreachable, got %+v", resp.UnreachableBackends)
	}
}
