package sentinel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPrimaryRegistry_RegisterLookupHeartbeat(t *testing.T) {
	r := NewPrimaryRegistry()

	// Initial registration
	stored := r.Register(Primary{Pool: "prod", Hostname: "prod.example.com", IP: "10.0.0.10", Port: 443})
	assert.NotNil(t, stored)
	assert.Equal(t, Pool("prod"), stored.Pool)
	assert.False(t, stored.RegisteredAt.IsZero())
	assert.Equal(t, stored.RegisteredAt, stored.LastHeartbeat)

	originalRegisteredAt := stored.RegisteredAt
	time.Sleep(10 * time.Millisecond)

	// Re-register: RegisteredAt preserved, LastHeartbeat advanced
	updated := r.Register(Primary{Pool: "prod", Hostname: "prod.example.com", IP: "10.0.0.11", Port: 443})
	assert.Equal(t, originalRegisteredAt, updated.RegisteredAt)
	assert.True(t, updated.LastHeartbeat.After(originalRegisteredAt))
	assert.Equal(t, "10.0.0.11", updated.IP, "IP should update on re-register")

	// Lookup hits
	assert.NotNil(t, r.LookupByPool("prod"))
	assert.NotNil(t, r.LookupByHostname("prod.example.com"))

	// Heartbeat refreshes
	prevHB := r.LookupByPool("prod").LastHeartbeat
	time.Sleep(10 * time.Millisecond)
	hb := r.Heartbeat("prod")
	assert.NotNil(t, hb)
	assert.True(t, hb.LastHeartbeat.After(prevHB))

	// Heartbeat for unknown pool returns nil
	assert.Nil(t, r.Heartbeat("ghost"))

	// Unregister
	assert.True(t, r.Unregister("prod"))
	assert.False(t, r.Unregister("prod"), "second unregister should be no-op")
	assert.Nil(t, r.LookupByPool("prod"))
}

func TestPrimaryRegistry_LookupByHostnameMatchesAliases(t *testing.T) {
	r := NewPrimaryRegistry()
	r.Register(Primary{
		Pool:     "prod",
		Hostname: "prod.example.com",
		Aliases:  []string{"api.example.com", "voice.example.com"},
		IP:       "10.0.0.10",
		Port:     443,
	})
	r.Register(Primary{
		Pool:     "lab",
		Hostname: "lab.example.com",
		Aliases:  []string{"lab-api.example.com"},
		IP:       "10.0.0.20",
		Port:     443,
	})

	// Primary hostname matches
	p := r.LookupByHostname("prod.example.com")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("prod"), p.Pool)
	}

	// Alias matches
	p = r.LookupByHostname("api.example.com")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("prod"), p.Pool, "api.example.com should resolve to prod via alias")
	}

	// Different pool's alias resolves to that pool
	p = r.LookupByHostname("lab-api.example.com")
	if assert.NotNil(t, p) {
		assert.Equal(t, Pool("lab"), p.Pool)
	}

	// Unknown hostname returns nil
	assert.Nil(t, r.LookupByHostname("ghost.example.com"))

	// Re-registration with new aliases replaces the list
	r.Register(Primary{
		Pool:     "prod",
		Hostname: "prod.example.com",
		Aliases:  []string{"new-app.example.com"},
		IP:       "10.0.0.10",
		Port:     443,
	})
	assert.Nil(t, r.LookupByHostname("api.example.com"), "old alias should be replaced on re-register")
	if p := r.LookupByHostname("new-app.example.com"); assert.NotNil(t, p) {
		assert.Equal(t, Pool("prod"), p.Pool)
	}
}

// TestPrimaryRegistry_TunnelBackedNoEviction is the regression test for
// Bug B: a tunnel-promoted primary (BackendID set) must NOT be evicted by
// the heartbeat TTL. Its lifetime is tied to the yamux session via
// OnTunnelConnect/OnTunnelDisconnect, not to HTTP heartbeats.
func TestPrimaryRegistry_TunnelBackedNoEviction(t *testing.T) {
	r := NewPrimaryRegistry()
	fakeNow := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return fakeNow }

	// Tunnel-backed: BackendID set, no heartbeat ever refreshed.
	r.Register(Primary{
		Pool:      "lab",
		Hostname:  "containarium-lab.example",
		IP:        "127.0.0.6",
		Port:      443,
		BackendID: "tunnel-lab-primary-1",
	})

	// HTTP-registered: BackendID empty.
	r.Register(Primary{
		Pool:     "http-pool",
		Hostname: "http-pool.example",
		IP:       "10.0.0.42",
		Port:     443,
	})

	// Fast-forward way past TTL with no heartbeats.
	fakeNow = fakeNow.Add(10 * PrimaryTTL)

	t.Run("tunnel-backed survives TTL", func(t *testing.T) {
		if assert.NotNil(t, r.LookupByPool("lab")) {
			assert.Equal(t, "tunnel-lab-primary-1", r.LookupByPool("lab").BackendID)
		}
		assert.NotNil(t, r.LookupByHostname("containarium-lab.example"))
	})

	t.Run("HTTP-registered evicts past TTL", func(t *testing.T) {
		assert.Nil(t, r.LookupByPool("http-pool"))
		assert.Nil(t, r.LookupByHostname("http-pool.example"))
	})

	t.Run("All() returns only tunnel-backed", func(t *testing.T) {
		all := r.All()
		assert.Len(t, all, 1)
		assert.Equal(t, "tunnel-lab-primary-1", all[0].BackendID)
	})

	t.Run("UnregisterByBackendID still works", func(t *testing.T) {
		removed := r.UnregisterByBackendID("tunnel-lab-primary-1")
		assert.Equal(t, 1, removed)
		assert.Nil(t, r.LookupByPool("lab"))
	})
}

// TestPrimaryRegistry_SetAliasHealth is the regression test for #1872's
// visibility gap: GET /sentinel/primaries must be able to show "registered
// but not actually reachable" rather than only structural registration.
func TestPrimaryRegistry_SetAliasHealth(t *testing.T) {
	r := NewPrimaryRegistry()
	stored := r.Register(Primary{
		Pool:      "prod-kafeido",
		Hostname:  "facelabor.kafeido.app",
		Aliases:   []string{"grpc.kafeido.app"},
		IP:        "127.0.0.2",
		Port:      443,
		BackendID: "tunnel-ase1-spot-prod",
	})

	checkedAt := time.Now()
	r.SetAliasHealth("prod-kafeido", stored.rev, []AliasHealth{
		{Hostname: "facelabor.kafeido.app", Reachable: true, CheckedAt: checkedAt},
		{Hostname: "grpc.kafeido.app", Reachable: false, Error: "upstream returned 502", CheckedAt: checkedAt},
	})

	p := r.LookupByPool("prod-kafeido")
	if assert.NotNil(t, p) {
		assert.Len(t, p.AliasHealth, 2)
	}

	// A probe racing an unregister must not resurrect a stale entry.
	r.Unregister("prod-kafeido")
	r.SetAliasHealth("prod-kafeido", stored.rev, []AliasHealth{{Hostname: "grpc.kafeido.app", Reachable: true}})
	assert.Nil(t, r.LookupByPool("prod-kafeido"), "SetAliasHealth on an unregistered pool must be a no-op")
}

// TestPrimaryRegistry_SetAliasHealth_RejectsStaleRevision is the
// regression test for the CodeRabbit finding on PR #1873: a reachability
// sweep that started against an old declaration (captured its rev via
// All()) must not have its results attributed to a NEW declaration that
// Register() installed while the sweep was still running — e.g. the spot
// reconnected with different Aliases mid-sweep. The stale sweep's
// SetAliasHealth call must be rejected, and Register() must also clear
// any AliasHealth already on file rather than let it linger under the new
// declaration.
func TestPrimaryRegistry_SetAliasHealth_RejectsStaleRevision(t *testing.T) {
	r := NewPrimaryRegistry()
	first := r.Register(Primary{
		Pool:      "prod-kafeido",
		Hostname:  "facelabor.kafeido.app",
		Aliases:   []string{"grpc.kafeido.app"},
		BackendID: "tunnel-ase1-spot-prod",
		Port:      443,
	})
	// Register() returns a pointer to the SAME live entry on an update
	// (see TestPrimaryRegistry_RegisterLookupHeartbeat), so firstRev must
	// be snapshotted as a value now — reading first.rev after the second
	// Register() call below would observe the mutated current rev, not
	// the one this sweep actually probed against. This mirrors how
	// checkTunnelPrimaries gets its rev: from a *copy* returned by All().
	firstRev := first.rev
	r.SetAliasHealth("prod-kafeido", firstRev, []AliasHealth{
		{Hostname: "grpc.kafeido.app", Reachable: false, Error: "upstream returned 502"},
	})
	assert.Len(t, r.LookupByPool("prod-kafeido").AliasHealth, 1, "health should be recorded against the first declaration")

	// Re-registration (e.g. the tunnel reconnected with a different
	// alias set) must bump rev and drop the stale health.
	second := r.Register(Primary{
		Pool:      "prod-kafeido",
		Hostname:  "facelabor.kafeido.app",
		Aliases:   []string{"voice.kafeido.app"},
		BackendID: "tunnel-ase1-spot-prod",
		Port:      443,
	})
	assert.NotEqual(t, firstRev, second.rev, "rev must change on re-registration")
	assert.Empty(t, r.LookupByPool("prod-kafeido").AliasHealth, "AliasHealth from the old declaration must be cleared")

	// A late-arriving result computed against the FIRST (now-stale)
	// declaration must be discarded, not attributed to the new one.
	r.SetAliasHealth("prod-kafeido", firstRev, []AliasHealth{
		{Hostname: "grpc.kafeido.app", Reachable: true},
	})
	assert.Empty(t, r.LookupByPool("prod-kafeido").AliasHealth, "a stale-rev SetAliasHealth call must be a no-op")

	// A result computed against the CURRENT declaration must still apply.
	r.SetAliasHealth("prod-kafeido", second.rev, []AliasHealth{
		{Hostname: "voice.kafeido.app", Reachable: true},
	})
	assert.Len(t, r.LookupByPool("prod-kafeido").AliasHealth, 1)
}

func TestPrimaryRegistry_StaleEviction(t *testing.T) {
	r := NewPrimaryRegistry()

	// Inject a clock we control
	fakeNow := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return fakeNow }

	r.Register(Primary{Pool: "fresh", Hostname: "fresh.example", IP: "10.0.0.1", Port: 443})

	// Fast-forward past TTL
	fakeNow = fakeNow.Add(PrimaryTTL + time.Second)

	// Stale entry should be invisible to lookups
	assert.Nil(t, r.LookupByPool("fresh"), "stale by-pool lookup should miss")
	assert.Nil(t, r.LookupByHostname("fresh.example"), "stale by-hostname lookup should miss")

	// All() should evict and return nothing
	assert.Empty(t, r.All())

	// Re-registration after eviction works (treated as new)
	stored := r.Register(Primary{Pool: "fresh", Hostname: "fresh.example", IP: "10.0.0.1", Port: 443})
	assert.Equal(t, fakeNow, stored.RegisteredAt)
}

func TestPrimariesHandler_HTTPFlow(t *testing.T) {
	m := &Manager{primaries: NewPrimaryRegistry()}
	h := m.PrimariesHandler()

	post := func(body string, remoteAddr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/sentinel/primaries", bytes.NewBufferString(body))
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}

	t.Run("POST registers and infers IP from RemoteAddr", func(t *testing.T) {
		body := `{"pool":"prod","hostname":"prod.example.com","port":443}`
		rec := post(body, "10.20.30.40:54321")
		assert.Equal(t, http.StatusCreated, rec.Code)
		var got Primary
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		assert.Equal(t, "10.20.30.40", got.IP, "sentinel should fill IP from RemoteAddr when omitted")
	})

	t.Run("POST honors explicit IP if provided", func(t *testing.T) {
		body := `{"pool":"lab","hostname":"lab.example.com","ip":"10.99.99.99","port":443}`
		rec := post(body, "10.20.30.40:1234")
		assert.Equal(t, http.StatusCreated, rec.Code)
		var got Primary
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		assert.Equal(t, "10.99.99.99", got.IP)
	})

	t.Run("POST rejects missing required fields", func(t *testing.T) {
		rec := post(`{"pool":"oops"}`, "10.20.30.40:1")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("GET lists registered primaries", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/sentinel/primaries", nil)
		rec := httptest.NewRecorder()
		h(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		var resp struct {
			Primaries []Primary `json:"primaries"`
		}
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Len(t, resp.Primaries, 2)
	})

	t.Run("GET ?pool= filters by pool", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/sentinel/primaries?pool=prod", nil)
		rec := httptest.NewRecorder()
		h(rec, req)
		var resp struct {
			Primaries []Primary `json:"primaries"`
		}
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Len(t, resp.Primaries, 1)
		assert.Equal(t, Pool("prod"), resp.Primaries[0].Pool)
	})

	t.Run("PUT heartbeats existing primary", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/sentinel/primaries/prod", nil)
		rec := httptest.NewRecorder()
		h(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("PUT 404s on unknown pool", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/sentinel/primaries/ghost", nil)
		rec := httptest.NewRecorder()
		h(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("DELETE removes a primary", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/sentinel/primaries/lab", nil)
		rec := httptest.NewRecorder()
		h(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Subsequent GET should now show only "prod"
		req = httptest.NewRequest(http.MethodGet, "/sentinel/primaries", nil)
		rec = httptest.NewRecorder()
		h(rec, req)
		var resp struct {
			Primaries []Primary `json:"primaries"`
		}
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Len(t, resp.Primaries, 1)
		assert.Equal(t, Pool("prod"), resp.Primaries[0].Pool)
	})
}
