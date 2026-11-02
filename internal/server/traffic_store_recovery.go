//go:build !containarium_client

package server

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/autosleep"
	"github.com/footprintai/containarium/internal/traffic"
)

// Traffic persistence as a late-install family (#3401, on the #3326 helper;
// split from #3331 by #3335 Q12). The traffic collector is built and its
// TrafficServer registered at startup whatever Postgres does, and it is
// started and stopped with the daemon (DualServer.Start and its shutdown).
// The store is installed INTO that running collector (Collector.SetStore,
// an atomic, first-store-wins swap) rather than by building a second
// collector: the registered server, the eBPF flow sink and auto-sleep keep
// pointing at the one collector, its live window survives, and nothing is
// started twice. Flows that closed before the store arrived are not
// persisted; a flow still live at install is persisted when it closes.

const (
	// trafficStoreService is the family's grpc.health.v1 readiness entry.
	trafficStoreService = "containarium.traffic"
	trafficStoreDisplay = "traffic persistence store"
)

// trafficStoreTarget is the collector seen by the install: it can be given
// a store and asked for it, never started, stopped or replaced.
// *traffic.Collector implements it.
type trafficStoreTarget interface {
	SetStore(*traffic.Store) bool
	GetStore() *traffic.Store
}

var _ trafficStoreTarget = (*traffic.Collector)(nil)

// trafficStoreFamily is the helper registration: open the store over the
// shared pool and install it into the collector. On error nothing changes,
// so the collector keeps serving from memory without persistence.
func trafficStoreFamily(c trafficStoreTarget, open func(context.Context, *pgxpool.Pool) (*traffic.Store, error)) storeFamily {
	return storeFamily{
		Service: trafficStoreService,
		Display: trafficStoreDisplay,
		Install: func(ctx context.Context, pool *pgxpool.Pool) error {
			if c.GetStore() != nil {
				return nil
			}
			st, err := open(ctx, pool)
			if err != nil {
				return err
			}
			c.SetStore(st)
			return nil
		},
	}
}

func registerTrafficLateInstall(r *storeRecovery, c trafficStoreTarget, open func(context.Context, *pgxpool.Pool) (*traffic.Store, error)) {
	r.logf("Warning: traffic persistence off (Postgres unavailable at startup): the traffic API answers from the in-memory collector and history is not recorded until the store installs in-process; readiness %s is NOT_SERVING", trafficStoreService)
	r.Register(trafficStoreFamily(c, open))
}

// setupTrafficStore is the startup install: over pool (the app store's,
// nil when Postgres did not answer) open the store and install it, or hand
// it to the helper.
func setupTrafficStore(r *storeRecovery, c trafficStoreTarget, pool *pgxpool.Pool, open func(context.Context, *pgxpool.Pool) (*traffic.Store, error)) {
	if pool == nil {
		registerTrafficLateInstall(r, c, open)
		return
	}
	st, err := open(context.Background(), pool)
	if err != nil {
		r.logf("Warning: Failed to create traffic store: %v", err)
		registerTrafficLateInstall(r, c, open)
		return
	}
	c.SetStore(st)
	r.RegisterInstalled(trafficStoreFamily(c, open))
	r.logf("Traffic monitoring updated with persistence")
}

// liveTrafficSource is auto-sleep's network-activity source. Auto-sleep is
// built once, in DualServer.Start, possibly before the store arrives, so it
// reads the collector's store per call; with none it reports no signal (zero
// time), as a nil source does.
type liveTrafficSource struct {
	collector interface{ GetStore() *traffic.Store }
}

func (s liveTrafficSource) LastNetworkActivity(ctx context.Context, containerName string) (time.Time, error) {
	st := s.collector.GetStore()
	if st == nil || st.Pool() == nil {
		return time.Time{}, nil
	}
	return autosleep.NewTrafficStoreAdapter(st.Pool()).LastNetworkActivity(ctx, containerName)
}
