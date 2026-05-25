package sentinel

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testPeer struct {
	ID        string `json:"id"`
	ProxyPath string `json:"proxy_path"`
	Healthy   bool   `json:"healthy"`
	Pool      Pool   `json:"pool,omitempty"`
}

// TestPeersHandlerPoolFilter verifies that pool tags propagate from the
// backend through /sentinel/peers and that the ?pool= query param filters
// correctly while preserving back-compat (no param = return everything).
func TestPeersHandlerPoolFilter(t *testing.T) {
	m := &Manager{backends: NewBackendPool()}

	m.backends.Add(&Backend{ID: "tunnel-a", Type: BackendTunnel, Healthy: true, Pool: "prod"})
	m.backends.Add(&Backend{ID: "tunnel-b", Type: BackendTunnel, Healthy: true, Pool: "dev"})
	m.backends.Add(&Backend{ID: "tunnel-c", Type: BackendTunnel, Healthy: false, Pool: ""})
	m.backends.Add(&Backend{ID: "gcp-x", Type: BackendGCP, Healthy: true, Pool: "prod"})

	call := func(query string) []testPeer {
		t.Helper()
		req := httptest.NewRequest("GET", "/sentinel/peers"+query, nil)
		rec := httptest.NewRecorder()
		m.PeersHandler()(rec, req)
		assert.Equal(t, 200, rec.Code)
		var resp struct {
			Peers []testPeer `json:"peers"`
		}
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.Peers
	}

	t.Run("no filter returns all tunnel peers (back-compat)", func(t *testing.T) {
		peers := call("")
		ids := idsOf(peers)
		assert.ElementsMatch(t, []string{"tunnel-a", "tunnel-b", "tunnel-c"}, ids)
		// GCP backends are never returned.
		assert.NotContains(t, ids, "gcp-x")
	})

	t.Run("filter by pool=prod returns only prod peers", func(t *testing.T) {
		peers := call("?pool=prod")
		assert.Len(t, peers, 1)
		assert.Equal(t, "tunnel-a", peers[0].ID)
		assert.Equal(t, Pool("prod"), peers[0].Pool)
	})

	t.Run("filter by pool=dev returns only dev peers", func(t *testing.T) {
		peers := call("?pool=dev")
		assert.Len(t, peers, 1)
		assert.Equal(t, "tunnel-b", peers[0].ID)
	})

	t.Run("empty pool value matches unpooled peers only", func(t *testing.T) {
		peers := call("?pool=")
		assert.Len(t, peers, 1)
		assert.Equal(t, "tunnel-c", peers[0].ID)
		assert.Equal(t, Pool(""), peers[0].Pool)
	})

	t.Run("unknown pool returns empty list", func(t *testing.T) {
		peers := call("?pool=ghost")
		assert.Empty(t, peers)
	})
}

// TestOnTunnelConnect_PromotesPrimary verifies that a tunnel handshake
// carrying PublicHostname auto-creates a primary registry entry pointing
// at the tunnel's loopback alias, and that disconnecting cleans it up.
func TestOnTunnelConnect_PromotesPrimary(t *testing.T) {
	m := &Manager{
		backends:  NewBackendPool(),
		primaries: NewPrimaryRegistry(),
		certStore: NewCertStore(),
		keyStore:  NewKeyStore(),
	}

	spot := &TunnelSpot{
		ID:             "lab-primary-1",
		LocalIP:        "127.0.0.7",
		ExternalPort:   18007,
		Pool:           "lab",
		PublicHostname: "lab.example.com",
		PublicAliases:  []string{"lab-api.example.com"},
		PublicPort:     443,
	}

	m.OnTunnelConnect(spot)

	// Backend pool sees the tunnel as before.
	b := m.backends.Get("tunnel-lab-primary-1")
	if assert.NotNil(t, b) {
		assert.Equal(t, Pool("lab"), b.Pool)
		assert.Equal(t, "127.0.0.7", b.IP)
	}

	// Primary registry has the tunnel-promoted entry.
	p := m.primaries.LookupByPool("lab")
	if assert.NotNil(t, p) {
		assert.Equal(t, "lab.example.com", p.Hostname)
		assert.Equal(t, []string{"lab-api.example.com"}, p.Aliases)
		assert.Equal(t, "127.0.0.7", p.IP)
		assert.Equal(t, 443, p.Port)
		assert.Equal(t, "tunnel-lab-primary-1", p.BackendID)
	}

	// SNI lookup by alias finds the same primary.
	if p2 := m.primaries.LookupByHostname("lab-api.example.com"); assert.NotNil(t, p2) {
		assert.Equal(t, Pool("lab"), p2.Pool)
	}

	// Disconnect removes both backend and primary entries.
	m.OnTunnelDisconnect(spot)
	assert.Nil(t, m.primaries.LookupByPool("lab"), "primary entry should be removed on disconnect")
}

// TestOnTunnelConnect_PeerOnlyDoesNotPromote confirms that a tunnel without
// PublicHostname (a regular peer) does not create a primary entry.
func TestOnTunnelConnect_PeerOnlyDoesNotPromote(t *testing.T) {
	m := &Manager{
		backends:  NewBackendPool(),
		primaries: NewPrimaryRegistry(),
		certStore: NewCertStore(),
		keyStore:  NewKeyStore(),
	}

	spot := &TunnelSpot{
		ID:           "peer-1",
		LocalIP:      "127.0.0.8",
		ExternalPort: 18008,
		Pool:         "lab",
		// No PublicHostname / PublicPort
	}

	m.OnTunnelConnect(spot)

	assert.NotNil(t, m.backends.Get("tunnel-peer-1"))
	assert.Nil(t, m.primaries.LookupByPool("lab"), "peer-only tunnel should not create a primary entry")
}

// TestRegisterPropagatesPool confirms the pool tag flows from Register()
// into the TunnelSpot.
func TestRegisterPropagatesPool(t *testing.T) {
	r := NewTunnelRegistry()
	_, err := r.Register(&TunnelHandshake{SpotID: "spot-1", Ports: []int{8080}, Pool: "prod"}, nil)
	assert.NoError(t, err)

	spot := r.Get("spot-1")
	assert.NotNil(t, spot)
	assert.Equal(t, Pool("prod"), spot.Pool)

	// Empty pool stays empty (back-compat).
	_, err = r.Register(&TunnelHandshake{SpotID: "spot-2", Ports: []int{8080}}, nil)
	assert.NoError(t, err)
	assert.Equal(t, Pool(""), r.Get("spot-2").Pool)
}

func idsOf(peers []testPeer) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.ID)
	}
	return out
}
