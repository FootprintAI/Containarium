package server

import (
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
