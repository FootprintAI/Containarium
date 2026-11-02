//go:build !containarium_client

package server

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/network"
)

// #3407: a box deleted while the passthrough store is absent (degraded
// start, #3333) skips the delete cascade's passthrough step, so its rows stay
// in Postgres. Once the store installs, the sync job reconciles Postgres into
// the host's rules; without the fix it keeps (or re-adds) a forwarding rule
// that points at a box that no longer exists.

// hostPassthroughRules is an in-memory stand-in for the host's iptables
// passthrough rules, keyed like the sync job keys them.
type hostPassthroughRules struct {
	mu     sync.Mutex
	routes map[string]network.PassthroughRoute
}

func newHostPassthroughRules(seed ...network.PassthroughRoute) *hostPassthroughRules {
	h := &hostPassthroughRules{routes: map[string]network.PassthroughRoute{}}
	for _, r := range seed {
		h.routes[passthroughKey(r.ExternalPort, r.Protocol)] = r
	}
	return h
}

func (h *hostPassthroughRules) ListRoutes() ([]network.PassthroughRoute, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]network.PassthroughRoute, 0, len(h.routes))
	for _, r := range h.routes {
		out = append(out, r)
	}
	return out, nil
}

func (h *hostPassthroughRules) AddRoute(externalPort int, targetIP string, targetPort int, protocol string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.routes[passthroughKey(externalPort, protocol)] = network.PassthroughRoute{
		ExternalPort: externalPort, TargetIP: targetIP, TargetPort: targetPort, Protocol: protocol, Active: true,
	}
	return nil
}

func (h *hostPassthroughRules) RemoveRoute(externalPort int, protocol string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.routes, passthroughKey(externalPort, protocol))
	return nil
}

func (h *hostPassthroughRules) targets() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.routes {
		out = append(out, fmt.Sprintf("%d/%s->%s:%d", r.ExternalPort, r.Protocol, r.TargetIP, r.TargetPort))
	}
	sort.Strings(out)
	return out
}

var _ network.PassthroughRules = (*hostPassthroughRules)(nil)

// realSyncJobs builds the production sync job over the host-rule fake and
// keeps it, so the test can run exactly one reconcile pass with SyncNow.
type realSyncJobs struct {
	rules *hostPassthroughRules

	mu   sync.Mutex
	jobs []*network.PassthroughSyncJob
}

func (b *realSyncJobs) build(st network.PassthroughStore) passthroughSyncRunner {
	b.mu.Lock()
	defer b.mu.Unlock()
	j := network.NewPassthroughSyncJob(st, b.rules, time.Hour)
	b.jobs = append(b.jobs, j)
	return j
}

func (b *realSyncJobs) only(t *testing.T) *network.PassthroughSyncJob {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.jobs) != 1 {
		t.Fatalf("sync jobs built = %d, want exactly one", len(b.jobs))
	}
	return b.jobs[0]
}

// AC1 + AC2: delete one box in the window, install the store, run one sync
// pass. The deleted box has neither a row nor a host rule; the box that
// still exists keeps both. The host either kept its rules across the daemon
// restart (the usual case: iptables outlives the daemon) or lost them (a
// host reboot), so the pass must neither keep nor re-add the deleted box's.
func TestPassthroughRecovery_DeleteWhileStoreAbsentLeavesNoRule(t *testing.T) {
	deleted := network.PassthroughRecord{
		ExternalPort: 4566, TargetIP: "10.0.3.5", TargetPort: 4566,
		Protocol: "tcp", ContainerName: "alice-container", Active: true,
	}
	kept := network.PassthroughRecord{
		ExternalPort: 4567, TargetIP: "10.0.3.9", TargetPort: 4567,
		Protocol: "tcp", ContainerName: "bob-container", Active: true,
	}
	asRule := func(r network.PassthroughRecord) network.PassthroughRoute {
		return network.PassthroughRoute{
			ExternalPort: r.ExternalPort, TargetIP: r.TargetIP, TargetPort: r.TargetPort, Protocol: r.Protocol, Active: true,
		}
	}

	for _, tc := range []struct {
		name string
		host []network.PassthroughRoute
	}{
		{name: "host kept its rules", host: []network.PassthroughRoute{asRule(deleted), asRule(kept)}},
		{name: "host lost its rules", host: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st := newFakePassthroughStore()
			for _, r := range []network.PassthroughRecord{deleted, kept} {
				if err := st.Save(ctx, &r); err != nil {
					t.Fatalf("seed %s: %v", r.ContainerName, err)
				}
			}
			rules := newHostPassthroughRules(tc.host...)
			syncJobs := &realSyncJobs{rules: rules}

			f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 1})
			g := newPassthroughRecoveryRig()
			g.sync = newPassthroughSync(syncJobs.build)
			durable := &fakePassthroughOpen{store: st}
			registerPassthroughLateInstall(f.r, g.consumers(), durable.open)

			// The window: the store is absent, the box is deleted.
			g.containers.cascadeContainerCleanup(ctx, deleted.ContainerName, "alice")

			f.runToCompletion(t, nil)
			if err := syncJobs.only(t).SyncNow(ctx); err != nil {
				t.Fatalf("sync pass: %v", err)
			}

			if _, err := st.GetByPortProtocol(ctx, deleted.ExternalPort, deleted.Protocol); err != network.ErrPassthroughNotFound {
				t.Errorf("deleted box's passthrough row survived the install: err=%v, want ErrPassthroughNotFound", err)
			}
			if _, err := st.GetByPortProtocol(ctx, kept.ExternalPort, kept.Protocol); err != nil {
				t.Errorf("existing box's passthrough row lost: %v", err)
			}
			want := []string{"4567/tcp->10.0.3.9:4567"}
			if got := rules.targets(); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("host rules after one sync pass = %v, want %v (no rule for the deleted box, the existing box's kept)", got, want)
			}
		})
	}
}

// Deletes racing the install: each one is either remembered and replayed by
// the install, or sees the installed store and cleans up itself. No box's
// row survives, whichever side of the install its delete lands on.
func TestPassthroughRecovery_DeleteRacingInstallLeavesNoRow(t *testing.T) {
	ctx := context.Background()
	const boxes = 32
	st := &lockedPassthroughStore{inner: newFakePassthroughStore()}
	for i := range boxes {
		if err := st.Save(ctx, &network.PassthroughRecord{
			ExternalPort: 5000 + i, TargetIP: "10.0.3.5", TargetPort: 80,
			Protocol: "tcp", ContainerName: fmt.Sprintf("box%d-container", i), Active: true,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	cs := &ContainerServer{}
	cs.requirePassthroughStore()

	var wg sync.WaitGroup
	for i := range boxes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if pt := cs.passthroughStoreForCascade(fmt.Sprintf("box%d-container", i)); pt != nil {
				cascadePassthroughRoutes(ctx, pt, fmt.Sprintf("box%d-container", i))
			}
		}()
	}
	cs.installPassthroughStore(ctx, st)
	wg.Wait()

	if n, _ := st.Count(ctx, false); n != 0 {
		t.Errorf("%d passthrough rows survived deletes racing the install, want 0", n)
	}
}

// A daemon with no Postgres configured never installs the store, so a delete
// there remembers nothing.
func TestPassthroughRecovery_NoPostgresDeleteRemembersNothing(t *testing.T) {
	cs := &ContainerServer{}
	if pt := cs.passthroughStoreForCascade("alice-container"); pt != nil {
		t.Fatalf("store = %v, want nil with none installed", pt)
	}
	if n := len(cs.passthroughSkipped.boxes); n != 0 {
		t.Errorf("remembered %d deletes on a daemon with no Postgres, want 0", n)
	}
}

// lockedPassthroughStore serializes a fakePassthroughStore for concurrent use.
type lockedPassthroughStore struct {
	mu    sync.Mutex
	inner *fakePassthroughStore
}

func (l *lockedPassthroughStore) Save(ctx context.Context, r *network.PassthroughRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inner.Save(ctx, r)
}

func (l *lockedPassthroughStore) GetByPortProtocol(ctx context.Context, port int, protocol string) (*network.PassthroughRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inner.GetByPortProtocol(ctx, port, protocol)
}

func (l *lockedPassthroughStore) List(ctx context.Context, activeOnly bool) ([]*network.PassthroughRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inner.List(ctx, activeOnly)
}

func (l *lockedPassthroughStore) ListByContainer(ctx context.Context, name string) ([]*network.PassthroughRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inner.ListByContainer(ctx, name)
}

func (l *lockedPassthroughStore) Delete(ctx context.Context, port int, protocol string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inner.Delete(ctx, port, protocol)
}

func (l *lockedPassthroughStore) SetActive(ctx context.Context, port int, protocol string, active bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inner.SetActive(ctx, port, protocol, active)
}

func (l *lockedPassthroughStore) Count(ctx context.Context, activeOnly bool) (int32, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inner.Count(ctx, activeOnly)
}

var _ network.PassthroughStore = (*lockedPassthroughStore)(nil)
