package server

import (
	"context"
	"log"

	"github.com/footprintai/containarium/internal/ttlsweeper"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// ttlsweeperSandboxAdapter bridges incus.Backend -> ttlsweeper.IncusClient,
// scoped to ephemeral sandboxes only (#1488 Phase 4). Sibling of
// ttlsweeperIncusAdapter/ttlsweeperBoxAdapter (ttlsweeper_adapter.go,
// ttlsweeper_boxes_adapter.go): same one-method seam, filtered to
// instances carrying SandboxKindLabelKey rather than "every non-core
// container".
//
// Only the absolute TTL rule ever applies to a sandbox — Stopped,
// StoppedAt, DeleteAfterStopped, and Protected are all left zero, so
// Decide's stopped->delete and protected-box rules never fire: a sandbox
// is never stopped-and-kept (DeleteSandbox always destroys outright, see
// its doc comment) and delete-protection is a persistent-tenant-box
// concept that doesn't apply to a short-lived ephemeral one.
type ttlsweeperSandboxAdapter struct {
	backend incus.Backend
}

// ListContainers returns one ContainerView per sandbox the backend
// currently knows about, with TTLExpiresAt populated from the same
// user.containarium.ttl_expires_at key SpawnSandbox/claimFromPool stamp
// (see sandbox_server.go).
func (a *ttlsweeperSandboxAdapter) ListContainers() ([]ttlsweeper.ContainerView, error) {
	raw, err := a.backend.ListContainers()
	if err != nil {
		return nil, err
	}
	out := make([]ttlsweeper.ContainerView, 0, len(raw))
	for i := range raw {
		c := raw[i]
		if c.Labels[sandboxKindLabelSuffix] != SandboxKindLabelValue {
			continue
		}
		v := ttlsweeper.ContainerView{Name: c.Name}
		if !c.TTLExpiresAt.IsZero() {
			t := c.TTLExpiresAt
			v.TTLExpiresAt = &t
		}
		out = append(out, v)
	}
	return out, nil
}

// DeleteContainer implements ttlsweeper.Deleter directly on SandboxServer
// (dual_server.go wires *SandboxServer itself as the Deleter, no separate
// wrapper type needed). Routes exactly like DeleteSandbox — pool.Release
// for a pool-claimed member, which also frees its IPAM address, destroy()
// otherwise — but skips DeleteSandbox's auth/ownership checks: the
// sweeper is the daemon reaping its own expired state on a schedule, not
// acting on behalf of a tenant request.
func (s *SandboxServer) DeleteContainer(_ context.Context, name string, reason string) error {
	log.Printf("[ttl] auto-deleting sandbox=%s reason=%q", name, reason)
	if member := s.untrackClaimed(name); member != nil {
		return s.pool.Release(member)
	}
	return s.destroy(name)
}
