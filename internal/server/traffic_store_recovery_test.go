//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/traffic"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3401: traffic persistence on the late-install helper (#3326). With
// Postgres down at startup the collector runs without a store: the traffic
// API answers from its in-memory window, history answers that nothing is
// persisted, and `containarium.traffic` is NOT_SERVING. Once Postgres
// answers, the store is installed into the SAME running collector (no new
// collector, no second Start) and readiness turns SERVING, with no restart.

// fakeTrafficOpen records each open and returns store or err.
type fakeTrafficOpen struct {
	mu    sync.Mutex
	store *traffic.Store
	errs  []error // returned in order before store
	opens int
	pools []*pgxpool.Pool
}

func (f *fakeTrafficOpen) open(_ context.Context, pool *pgxpool.Pool) (*traffic.Store, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens++
	f.pools = append(f.pools, pool)
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		return nil, err
	}
	return f.store, nil
}

func (f *fakeTrafficOpen) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens
}

// newStorelessCollector is the collector a degraded start builds: no store,
// no incus client. It holds one live eBPF flow for alice-container.
func newStorelessCollector(t *testing.T) *traffic.Collector {
	t.Helper()
	c, err := traffic.NewCollector(traffic.DefaultCollectorConfig(), nil, nil, nil)
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	t.Cleanup(c.Stop)
	now := time.Now()
	c.IngestEBPFFlows([]traffic.EBPFFlow{{
		ContainerName: "alice-container", ContainerIP: "10.100.0.42", Protocol: "tcp",
		SrcIP: "10.100.0.42", SrcPort: 51000, DstIP: "192.0.2.10", DstPort: 443,
		Bytes: 2048, Packets: 4, First: now.Add(-time.Second), Last: now,
	}})
	return c
}

// assertLiveTrafficServed: the traffic API answers from the collector's
// in-memory window, store or not.
func assertLiveTrafficServed(t *testing.T, srv *TrafficServer) {
	t.Helper()
	resp, err := srv.GetConnections(adminCtx(), &pb.GetConnectionsRequest{ContainerName: "alice-container"})
	if err != nil {
		t.Fatalf("GetConnections: %v", err)
	}
	if len(resp.GetConnections()) != 1 || resp.GetConnections()[0].GetBytesSent() != 2048 {
		t.Errorf("GetConnections = %v, want the one live flow from the in-memory window", resp.GetConnections())
	}
}

// AC1 + AC2 with a fake store install: Postgres is down for two attempts.
// Before recovery the entry is NOT_SERVING, live traffic is served from
// memory and history refuses. After it, the entry is SERVING and the store
// is installed into the same collector the registered TrafficServer reads,
// with its live window intact. Readers run during the install, so -race
// catches a store that is still read raw.
func TestTrafficRecovery_DegradedStartThenInstalledInProcess(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 2})
	c := newStorelessCollector(t)
	srv := NewTrafficServer(c)
	durable := &fakeTrafficOpen{store: &traffic.Store{}}
	setupTrafficStore(f.r, c, nil, durable.open)

	if got := f.status(t, trafficStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("traffic readiness before recovery = %v, want NOT_SERVING", got)
	}
	if f.readiness.entries[trafficStoreService] == "" {
		t.Errorf("traffic family published no readiness display name: %v", f.readiness.entries)
	}
	if durable.count() != 0 {
		t.Errorf("store opened %d times with no startup pool, want 0 before recovery", durable.count())
	}
	assertLiveTrafficServed(t, srv)
	_, err := srv.QueryTrafficHistory(adminCtx(), &pb.QueryTrafficHistoryRequest{ContainerName: "alice-container"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("QueryTrafficHistory with no store = %v, want FailedPrecondition", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = c.GetStore()
			}
		}()
	}
	f.runToCompletion(t, nil)
	close(stop)
	wg.Wait()

	if got := f.status(t, trafficStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("traffic readiness after recovery = %v, want SERVING", got)
	}
	if n := durable.count(); n != 1 {
		t.Errorf("traffic store opened %d times, want once", n)
	}
	if c.GetStore() != durable.store {
		t.Error("the running collector does not hold the installed store")
	}
	if srv.collector != c {
		t.Error("the registered TrafficServer no longer reads the running collector")
	}
	assertLiveTrafficServed(t, srv)
	if f.r.pending() {
		t.Error("traffic family still pending after it installed")
	}
}

// Postgres answered at startup: the store is opened over the startup pool
// and installed at once, readiness is SERVING and nothing is left to retry.
func TestTrafficRecovery_StartupInstall(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	c := newStorelessCollector(t)
	durable := &fakeTrafficOpen{store: &traffic.Store{}}
	pool := new(pgxpool.Pool)
	setupTrafficStore(f.r, c, pool, durable.open)

	if got := f.status(t, trafficStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("traffic readiness after a startup install = %v, want SERVING", got)
	}
	if c.GetStore() != durable.store {
		t.Error("startup install did not reach the collector")
	}
	if len(durable.pools) != 1 || durable.pools[0] != pool {
		t.Errorf("store opened over %v, want once over the startup pool", durable.pools)
	}
	if f.r.pending() {
		t.Error("traffic family pending after a startup install")
	}
}

// The startup open fails (schema init, say): the family falls back to the
// helper, holds the self-restart (not a config refusal), and installs on the
// next attempt over the shared pool.
func TestTrafficRecovery_StartupOpenFailsThenRecovers(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{})
	c := newStorelessCollector(t)
	durable := &fakeTrafficOpen{store: &traffic.Store{}, errs: []error{errors.New("initialize schema: boom")}}
	setupTrafficStore(f.r, c, new(pgxpool.Pool), durable.open)

	if got := f.status(t, trafficStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("traffic readiness after a failed startup open = %v, want NOT_SERVING", got)
	}
	if c.GetStore() != nil {
		t.Fatal("a failed open installed a store")
	}
	if !f.r.holdsRestart() {
		t.Error("a failed traffic store open does not hold the self-restart")
	}
	f.runToCompletion(t, nil)
	if got := f.status(t, trafficStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("traffic readiness after recovery = %v, want SERVING", got)
	}
	if c.GetStore() != durable.store {
		t.Error("recovered store not installed into the collector")
	}
}

// A collector that already has a store keeps it: the install opens nothing
// and replaces nothing.
func TestTrafficRecovery_InstallKeepsAnExistingStore(t *testing.T) {
	c := newStorelessCollector(t)
	existing := &traffic.Store{}
	c.SetStore(existing)
	durable := &fakeTrafficOpen{store: &traffic.Store{}}
	if err := trafficStoreFamily(c, durable.open).Install(context.Background(), new(pgxpool.Pool)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if durable.count() != 0 {
		t.Errorf("store opened %d times for a collector that has one, want 0", durable.count())
	}
	if c.GetStore() != existing {
		t.Error("install replaced the collector's existing store")
	}
}

// Auto-sleep is built once, at Start, possibly before the store arrives: its
// traffic source reads the collector's store per call, and with none it is
// "no network signal" (zero time, no error), as a nil source was.
func TestLiveTrafficSource_NoStoreIsNoSignal(t *testing.T) {
	c := newStorelessCollector(t)
	src := liveTrafficSource{collector: c}
	got, err := src.LastNetworkActivity(context.Background(), "alice-container")
	if err != nil || !got.IsZero() {
		t.Errorf("LastNetworkActivity with no store = %v, %v; want zero time, nil", got, err)
	}
	c.SetStore(&traffic.Store{}) // a store with no pool is still no signal
	got, err = src.LastNetworkActivity(context.Background(), "alice-container")
	if err != nil || !got.IsZero() {
		t.Errorf("LastNetworkActivity with a pool-less store = %v, %v; want zero time, nil", got, err)
	}
}
