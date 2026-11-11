package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/network"
)

// Race-safe access to the passthrough route store (#3333). The store can be
// installed after the daemon is serving (passthrough_store_recovery.go), so
// NetworkServer and ContainerServer read it through a storeSlot on every
// call. This file has no build constraint because both servers are built
// into every binary.

const (
	// passthroughStoreService is the family's grpc.health.v1 readiness entry.
	passthroughStoreService = "containarium.passthrough"
	passthroughStoreDisplay = "passthrough route store"
)

// errPassthroughNotInstalled is every passthrough RPC's answer while
// Postgres is configured but the store is not installed (#3335 Q13). Writing
// the host's rules directly instead would apply a route that is not
// persisted, and the sync job removes it once the store installs.
var errPassthroughNotInstalled = status.Error(codes.Unavailable,
	"passthrough route store is not available yet (Postgres unavailable at startup); nothing was changed — it installs in-process once Postgres answers, readiness "+passthroughStoreService)

// passthroughRuleWriter is the host-rule side of passthrough routes, written
// directly only on a daemon with no Postgres configured.
// *network.PassthroughManager implements it.
type passthroughRuleWriter interface {
	AddRoute(externalPort int, targetIP string, targetPort int, protocol string) error
	RemoveRoute(externalPort int, protocol string) error
	ListRoutes() ([]network.PassthroughRoute, error)
}

var _ passthroughRuleWriter = (*network.PassthroughManager)(nil)

// rules is where the no-Postgres path writes: the test seam when set,
// otherwise the iptables manager.
func (s *NetworkServer) rules() passthroughRuleWriter {
	if s.passthroughRules != nil {
		return s.passthroughRules
	}
	return s.passthroughManager
}

// requirePassthroughStore marks the store as the source of truth: Postgres
// is configured, so until the store is installed the passthrough RPCs answer
// UNAVAILABLE instead of falling back to writing the host's rules.
func (s *NetworkServer) requirePassthroughStore() { s.passthroughRequired.Store(true) }

// SetPassthroughStore installs the passthrough store. Safe while serving.
func (s *NetworkServer) SetPassthroughStore(st network.PassthroughStore) {
	s.passthroughStore.Store(st)
}

// currentPassthroughStore returns the installed store; or nil and
// errPassthroughNotInstalled while it is required but absent; or nil, nil on
// a daemon with no Postgres configured, where the host's rules are written
// directly. A caller that checks and uses the store loads it once.
func (s *NetworkServer) currentPassthroughStore() (network.PassthroughStore, error) {
	if st := s.passthroughStore.Load(); st != nil {
		return st, nil
	}
	if s.passthroughRequired.Load() {
		return nil, errPassthroughNotInstalled
	}
	return nil, nil
}

// loadPassthroughStore returns the delete cascade's passthrough store, nil
// when none is installed.
func (s *ContainerServer) loadPassthroughStore() network.PassthroughStore {
	return s.passthroughStore.Load()
}

// passthroughSkippedDeletes closes the delete gap of a degraded start
// (#3407). A box deleted while the store is required but absent keeps its
// rows in Postgres, and the sync job would reconcile them back into the
// host's rules once the store installs, forwarding a port to a box that no
// longer exists. So the cascade remembers the box instead, and the install
// removes its routes before the sync job is built. The store check and the
// remembering share mu with the install, so a delete racing the install is
// either remembered and replayed, or sees the installed store. The list is
// in memory: a daemon restarted inside the window loses it, as it did before
// the store could install in-process.
type passthroughSkippedDeletes struct {
	mu       sync.Mutex
	required bool
	boxes    []string
}

// requirePassthroughStore marks Postgres as configured, so a delete while
// the store is absent is remembered rather than dropped.
func (s *ContainerServer) requirePassthroughStore() {
	s.passthroughSkipped.mu.Lock()
	defer s.passthroughSkipped.mu.Unlock()
	s.passthroughSkipped.required = true
}

// passthroughStoreForCascade returns the installed store; or nil, having
// remembered containerName, while the store is required but absent; or nil on
// a daemon with no Postgres configured.
func (s *ContainerServer) passthroughStoreForCascade(containerName string) network.PassthroughStore {
	s.passthroughSkipped.mu.Lock()
	defer s.passthroughSkipped.mu.Unlock()
	if st := s.passthroughStore.Load(); st != nil {
		return st
	}
	if s.passthroughSkipped.required {
		s.passthroughSkipped.boxes = append(s.passthroughSkipped.boxes, containerName)
		log.Printf("[delete-cascade] passthrough store not installed yet; %q's passthrough routes are removed when it installs", containerName)
	}
	return nil
}

// installPassthroughStore installs st for the delete cascade, then removes
// the routes of every box deleted while it was absent. It returns once they
// are removed, so the RPCs and the sync job installed after it never see
// them (#3441). It returns how many boxes it replayed and how many of those
// failed; a failed box keeps its rows in Postgres, and the sync job
// reconciles them back into host rules. Every failure logs a warning that
// names the box. Retrying a failed replay is not done.
func (s *ContainerServer) installPassthroughStore(ctx context.Context, st network.PassthroughStore) (replayed, failed int) {
	s.passthroughSkipped.mu.Lock()
	s.passthroughStore.Store(st)
	var skipped []string
	if st != nil {
		skipped, s.passthroughSkipped.boxes = s.passthroughSkipped.boxes, nil
	}
	s.passthroughSkipped.mu.Unlock()
	for _, name := range skipped {
		replayed++
		if err := removePassthroughRoutes(ctx, st, name); err != nil {
			failed++
			log.Printf("Warning: passthrough replay for deleted box %q failed: %v; its passthrough rows remain in Postgres and will be reconciled back into host rules by the sync job", name, err)
		}
	}
	return replayed, failed
}

// cascadePassthroughRoutes deletes every passthrough route containerName
// owns; the sync job reaps the host rules. Best-effort, like the rest of the
// delete cascade.
func cascadePassthroughRoutes(ctx context.Context, pt network.PassthroughStore, containerName string) {
	if err := removePassthroughRoutes(ctx, pt, containerName); err != nil {
		log.Printf("[delete-cascade] passthrough routes for %q: %v", containerName, err)
	}
}

// removePassthroughRoutes deletes every route containerName owns, carrying on
// past a failed delete, and returns the failures joined (nil when all gone).
func removePassthroughRoutes(ctx context.Context, pt network.PassthroughStore, containerName string) error {
	routes, err := pt.ListByContainer(ctx, containerName)
	if err != nil {
		return fmt.Errorf("list passthrough routes: %w", err)
	}
	var errs []error
	for _, r := range routes {
		if err := pt.Delete(ctx, r.ExternalPort, r.Protocol); err != nil {
			errs = append(errs, fmt.Errorf("delete passthrough route %d/%s: %w", r.ExternalPort, r.Protocol, err))
			continue
		}
		log.Printf("[delete-cascade] removed passthrough route %d/%s (sync job will reap the iptables rule)",
			r.ExternalPort, r.Protocol)
	}
	return errors.Join(errs...)
}
