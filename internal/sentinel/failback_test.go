package sentinel

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failbackRig is a Manager in proxy mode with a preferred primary ("gcp",
// priority 0) and a lower-priority tunnel peer, whose health the test scripts
// tick by tick. switchToProxy is stubbed through its seam, but the stub applies
// the one effect everything else depends on: it makes the backend the primary.
type failbackRig struct {
	t     *testing.T
	m     *Manager
	gcp   *Backend
	peer  *Backend
	up    map[string]bool
	mu    sync.Mutex
	calls []string // IDs passed to switchToProxy, in order
}

func newFailbackRig(t *testing.T, failbackChecks int) *failbackRig {
	t.Helper()
	r := &failbackRig{t: t, up: map[string]bool{"10.0.0.1": true, "10.0.0.2": true}}
	r.m = NewManager(Config{HealthyThreshold: 2, UnhealthyThreshold: 2, FailbackChecks: failbackChecks}, &fakeRecoveryProvider{})
	r.gcp = &Backend{ID: "gcp", IP: "10.0.0.1", Healthy: true, Priority: 0}
	r.peer = &Backend{ID: "tunnel-a", IP: "10.0.0.2", Healthy: true, Priority: 10}
	r.m.backends.Add(r.gcp)
	r.m.backends.Add(r.peer)
	r.m.checkHealthFn = func(ip string) bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.up[ip]
	}
	r.m.switchToProxyFn = func(b *Backend) error {
		r.mu.Lock()
		r.calls = append(r.calls, b.ID)
		r.mu.Unlock()
		r.m.mu.Lock()
		r.m.primary = b
		r.m.mu.Unlock()
		return nil
	}
	r.m.state.Store(StateProxy)
	r.m.primary = r.gcp
	return r
}

func (r *failbackRig) set(ip string, healthy bool) {
	r.mu.Lock()
	r.up[ip] = healthy
	r.mu.Unlock()
}

// tick runs one health-check round n times.
func (r *failbackRig) tick(n int) {
	for i := 0; i < n; i++ {
		r.m.healthCheckAll(context.Background())
	}
}

func (r *failbackRig) switches() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *failbackRig) primaryID() string {
	r.m.mu.RLock()
	defer r.m.mu.RUnlock()
	if r.m.primary == nil {
		return ""
	}
	return r.m.primary.ID
}

// The production sequence (#2476): the primary blips, the sentinel fails over to
// a tunnel peer that cannot serve its hostnames, the primary comes back, and the
// sentinel used to stay on the peer until restarted.
func TestFailback_RestoresThePreferredPrimaryAfterItRecovers(t *testing.T) {
	r := newFailbackRig(t, 4)

	r.set("10.0.0.1", false)
	r.tick(2) // UnhealthyThreshold = 2
	require.Equal(t, []string{"tunnel-a"}, r.switches(), "precondition: failed over to the peer")
	require.Equal(t, "tunnel-a", r.primaryID())
	assert.False(t, r.m.primaryIsPreferred(), "sitting on the fallback is not the preferred primary")

	r.set("10.0.0.1", true)
	r.tick(3) // healthy again, but not yet stable for FailbackChecks
	assert.Equal(t, []string{"tunnel-a"}, r.switches(), "must not fail back before the hold-down has elapsed")

	r.tick(1) // 4th consecutive healthy check
	assert.Equal(t, []string{"tunnel-a", "gcp"}, r.switches(), "the recovered preferred primary must be restored")
	assert.Equal(t, "gcp", r.primaryID())
	assert.EqualValues(t, 1, r.m.FailbackCount())
	assert.EqualValues(t, 1, r.m.FailoverCount(), "failback must not be counted as a failover")
	assert.True(t, r.m.primaryIsPreferred())

	r.tick(5)
	assert.Equal(t, []string{"tunnel-a", "gcp"}, r.switches(), "once restored there is nothing further to do")
}

func TestFailback_FlappingPrimaryDoesNotOscillate(t *testing.T) {
	r := newFailbackRig(t, 4)
	r.set("10.0.0.1", false)
	r.tick(2)
	require.Equal(t, "tunnel-a", r.primaryID())

	// Up for three checks, down for one, repeatedly: never four in a row.
	for i := 0; i < 6; i++ {
		r.set("10.0.0.1", true)
		r.tick(3)
		r.set("10.0.0.1", false)
		r.tick(1)
	}
	assert.Equal(t, []string{"tunnel-a"}, r.switches(), "a flapping primary must not be failed back to")
	assert.EqualValues(t, 0, r.m.FailbackCount())
}

func TestFailback_NothingToDoWhenAlreadyOnThePreferredPrimary(t *testing.T) {
	r := newFailbackRig(t, 4)
	r.tick(12)
	assert.Empty(t, r.switches())
	assert.EqualValues(t, 0, r.m.FailbackCount())
}

func TestFailback_PeersOfEqualPriorityNeverSwapPlaces(t *testing.T) {
	r := newFailbackRig(t, 4)
	r.gcp.Healthy = false
	r.gcp.Priority = 10 // two equal-priority peers only
	r.m.primary = r.peer
	r.set("10.0.0.1", true)
	r.tick(10)
	assert.Empty(t, r.switches(), "equal priority is not 'better': no swap")
}

func TestFailback_AFailedSwitchLeavesThePrimaryAndRetries(t *testing.T) {
	r := newFailbackRig(t, 4)
	r.set("10.0.0.1", false)
	r.tick(2)
	require.Equal(t, "tunnel-a", r.primaryID())

	fail := true
	inner := r.m.switchToProxyFn
	r.m.switchToProxyFn = func(b *Backend) error {
		if b.ID == "gcp" && fail {
			r.mu.Lock()
			r.calls = append(r.calls, "gcp(refused)")
			r.mu.Unlock()
			return errors.New("iptables refused")
		}
		return inner(b)
	}

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	r.set("10.0.0.1", true)
	r.tick(4)
	assert.Equal(t, "tunnel-a", r.primaryID(), "a refused switch leaves the primary where it was")
	assert.EqualValues(t, 0, r.m.FailbackCount(), "a switch that did not happen is not a failback")
	assert.NotContains(t, logs.String(), "failback:", "a refused switch must not be logged as a failback")
	assert.Contains(t, logs.String(), "refused, staying on tunnel-a")

	fail = false
	r.tick(1)
	assert.Equal(t, "gcp", r.primaryID(), "it retries on the next check and succeeds")
	assert.EqualValues(t, 1, r.m.FailbackCount())
	assert.Contains(t, logs.String(), "failback: tunnel-a → gcp", "the successful switch is logged once, after it happened")
}

func TestFailback_NegativeThresholdDisablesIt(t *testing.T) {
	r := newFailbackRig(t, -1)
	r.set("10.0.0.1", false)
	r.tick(2)
	require.Equal(t, "tunnel-a", r.primaryID())
	r.set("10.0.0.1", true)
	r.tick(20)
	assert.Equal(t, []string{"tunnel-a"}, r.switches(), "disabled: the old behaviour is preserved")
}

func TestFailback_ZeroUsesTheDefaultAndNeverRacesAheadOfHealthyThreshold(t *testing.T) {
	assert.Equal(t, defaultFailbackChecks, NewManager(Config{HealthyThreshold: 2}, &fakeRecoveryProvider{}).failbackChecks())
	// A configured value below HealthyThreshold would fail back before the
	// backend is even marked healthy: it is raised to HealthyThreshold.
	assert.Equal(t, 5, NewManager(Config{HealthyThreshold: 5, FailbackChecks: 2}, &fakeRecoveryProvider{}).failbackChecks())
}

// Ordinary failover is unchanged.
func TestFailback_DoesNotDisturbOrdinaryFailover(t *testing.T) {
	r := newFailbackRig(t, 4)
	r.set("10.0.0.1", false)
	r.tick(1)
	assert.Empty(t, r.switches(), "one failed check is below UnhealthyThreshold")
	r.tick(1)
	assert.Equal(t, []string{"tunnel-a"}, r.switches())
	assert.EqualValues(t, 1, r.m.FailoverCount())
	assert.EqualValues(t, 0, r.m.FailbackCount())
}

func TestRenderFailbackMetrics(t *testing.T) {
	out := renderFailbackMetrics(3, false)
	assert.Contains(t, out, "# TYPE sentinel_failback_total counter\n")
	assert.Contains(t, out, "sentinel_failback_total 3\n")
	assert.Contains(t, out, "# TYPE sentinel_primary_preferred gauge\n")
	assert.Contains(t, out, "sentinel_primary_preferred 0\n")
	assert.True(t, strings.Contains(renderFailbackMetrics(0, true), "sentinel_primary_preferred 1\n"))
}
