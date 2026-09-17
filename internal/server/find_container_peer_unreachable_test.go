package server

// Tests for #1905: FindContainerPeer must distinguish "not on any peer"
// from "might be on one of these unreachable peers" so lifecycle RPCs
// don't misreport a real container as gone when its backend is merely
// unhealthy right now.

import (
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/metrics/platformstats"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestFindContainerPeer_UnhealthyPeer_ReportsUnreachableNotJustNil pins the
// core fix directly: a container that exists only on an unhealthy peer must
// come back with that peer named in the unreachable list, not just a bare
// nil indistinguishable from "this container is nowhere."
func TestFindContainerPeer_UnhealthyPeer_ReportsUnreachableNotJustNil(t *testing.T) {
	pp := NewPeerPool("local-vm", "", nil, "")
	pp.peers["containarium-jump-ase1-prod"] = &PeerClient{
		ID:      "containarium-jump-ase1-prod",
		Healthy: false,
	}

	peer, unreachable := pp.FindContainerPeer("alice", "")
	if peer != nil {
		t.Fatalf("expected no peer found (only candidate is unhealthy), got %+v", peer)
	}
	if len(unreachable) != 1 || unreachable[0].BackendID != "containarium-jump-ase1-prod" {
		t.Fatalf("expected containarium-jump-ase1-prod reported as unreachable, got %+v", unreachable)
	}
}

// TestDeleteContainer_UnreachablePeer_DoesNotClaimNotFound is the flagship
// RPC-level case from #1905: deleting a container whose only candidate
// backend is unhealthy must not report the same generic "failed to delete
// container: container not found" a genuinely-nonexistent container would
// get — that reads as "already gone," which is actively wrong here.
func TestDeleteContainer_UnreachablePeer_DoesNotClaimNotFound(t *testing.T) {
	mock := incustest.NewMockBackend() // empty: alice-container isn't local
	mock.GetContainerFunc = func(string) (*incus.ContainerInfo, error) {
		return nil, errors.New("instance not found")
	}

	pp := NewPeerPool("local-vm", "", nil, "")
	pp.peers["containarium-jump-ase1-prod"] = &PeerClient{
		ID:      "containarium-jump-ase1-prod",
		Healthy: false,
	}

	s := &ContainerServer{
		manager:       container.NewWithBackend(mock),
		peerPool:      pp,
		platformStats: platformstats.New(),
	}

	ctx := scopedTenantCtx("alice", auth.ScopeContainersWrite)
	_, err := s.DeleteContainer(ctx, &pb.DeleteContainerRequest{Username: "alice"})
	if err == nil {
		t.Fatal("expected an error (container could not be confirmed either way)")
	}
	if got := err.Error(); !strings.Contains(got, "unreachable") {
		t.Errorf("error = %q, want it to say the backend is unreachable, not just \"not found\" (which reads as already-deleted)", got)
	}
	if strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, must not claim \"not found\" — the container may still exist on the unreachable backend", err.Error())
	}
}
