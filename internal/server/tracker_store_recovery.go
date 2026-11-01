//go:build !containarium_client

package server

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/tracker"
)

// The tracker-connections store as a late-install family (#3329, on the
// #3326 helper, after the secrets store #3327). TrackerService is
// registered unconditionally and its RPCs answer UNAVAILABLE while the
// store is nil; after a degraded start the helper installs it once Postgres
// answers, through the same open path boot uses, and wires the pieces boot
// wires with it: the agent server's connection checker and lineage
// reservations, and the dispatcher's run starter.
//
// A connection's credential is a broker-only secret, so the store installs
// only once the secrets store is in: until then the tracker stays
// unavailable (fail closed) rather than serving connections whose
// credentials cannot be resolved. The helper runs families in registration
// order and the secrets family registers first, so one attempt installs
// both.

const (
	// trackerStoreService is the family's grpc.health.v1 readiness entry.
	trackerStoreService = "containarium.tracker"
	trackerStoreDisplay = "tracker connection store"
)

// errTrackerWaitingOnSecrets is the fail-closed refusal: the tracker store
// is not installed while the secrets store holding its credentials is not.
var errTrackerWaitingOnSecrets = errors.New("waiting on the secrets store, which holds tracker credentials; tracker connections stay unavailable until it is installed")

// trackerStoreFamily is the helper registration for the tracker store:
// once the secrets store is in, open the tracker store over the shared pool
// and wire it with wireTrackerStore. On error nothing is wired, so the RPCs
// keep answering UNAVAILABLE.
func trackerStoreFamily(cs *ContainerServer, agents *AgentSkillServer, open func(context.Context, *pgxpool.Pool) (*tracker.Store, error), runStarter func() tracker.RunStarter) storeFamily {
	return storeFamily{
		Service: trackerStoreService,
		Display: trackerStoreDisplay,
		Install: func(ctx context.Context, pool *pgxpool.Pool) error {
			if cs.loadSecretsStore() == nil {
				return errTrackerWaitingOnSecrets
			}
			st, err := open(ctx, pool)
			if err != nil {
				return err
			}
			wireTrackerStore(cs, agents, st, runStarter())
			return nil
		},
	}
}

// wireTrackerStore wires st and everything built over it, at boot and at
// late install. The store goes in last: it is what every tracker RPC checks
// first, so by the time one sees it the run starter is in too.
func wireTrackerStore(cs *ContainerServer, agents *AgentSkillServer, st *tracker.Store, runs tracker.RunStarter) {
	agents.SetTrackerConnections(st)
	// #2062: a run's leftover fan-out reservations are swept when its
	// lease ends.
	agents.SetLineageReservations(st)
	// #2022: dispatched runs start through the RunAgentSkill path.
	cs.SetTrackerRunStarter(runs)
	cs.SetTrackerStore(st)
}
