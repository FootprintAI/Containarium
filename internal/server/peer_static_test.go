package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseStaticPeer(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    StaticPeer
		wantErr bool
	}{
		{name: "address only keeps the address as the id", in: "10.0.0.1:8080", want: StaticPeer{ID: "10.0.0.1:8080", Addr: "10.0.0.1:8080"}},
		{name: "explicit id", in: "backend-b=10.0.0.2:8080", want: StaticPeer{ID: "backend-b", Addr: "10.0.0.2:8080"}},
		{name: "id with dots and underscores", in: "be.b_1=10.0.0.2:8080", want: StaticPeer{ID: "be.b_1", Addr: "10.0.0.2:8080"}},
		{name: "hostname address", in: "peer-b=peer-b.internal:8080", want: StaticPeer{ID: "peer-b", Addr: "peer-b.internal:8080"}},
		{name: "surrounding space is trimmed", in: "  backend-b=10.0.0.2:8080  ", want: StaticPeer{ID: "backend-b", Addr: "10.0.0.2:8080"}},
		{name: "ipv6 with brackets", in: "backend-b=[::1]:8080", want: StaticPeer{ID: "backend-b", Addr: "[::1]:8080"}},
		{name: "ipv6 without brackets", in: "backend-b=::1:8080", wantErr: true},
		{name: "id reserved for sentinel-discovered peers", in: "tunnel-gpu=10.0.0.2:8080", wantErr: true},
		{name: "non-numeric port", in: "backend-b=10.0.0.2:http", wantErr: true},
		{name: "port zero", in: "backend-b=10.0.0.2:0", wantErr: true},
		{name: "port above 65535", in: "backend-b=10.0.0.2:70000", wantErr: true},
		{name: "highest port", in: "backend-b=10.0.0.2:65535", want: StaticPeer{ID: "backend-b", Addr: "10.0.0.2:65535"}},
		{name: "lowest port", in: "backend-b=10.0.0.2:1", want: StaticPeer{ID: "backend-b", Addr: "10.0.0.2:1"}},
		{name: "empty entry", in: "", wantErr: true},
		{name: "blank entry", in: "   ", wantErr: true},
		{name: "empty id", in: "=10.0.0.2:8080", wantErr: true},
		{name: "empty address", in: "backend-b=", wantErr: true},
		{name: "address without port", in: "backend-b=10.0.0.2", wantErr: true},
		{name: "address without host", in: "backend-b=:8080", wantErr: true},
		{name: "id with a colon cannot be an incus remote name", in: "back:end=10.0.0.2:8080", wantErr: true},
		{name: "id with a slash", in: "back/end=10.0.0.2:8080", wantErr: true},
		{name: "id with a space", in: "back end=10.0.0.2:8080", wantErr: true},
		{name: "id starting with a hyphen", in: "-backend=10.0.0.2:8080", wantErr: true},
		{name: "second equals sign lands in the address", in: "a=b=c:8080", wantErr: true},
		{name: "address-only entry is accepted as-is for back-compat", in: "peer-1", want: StaticPeer{ID: "peer-1", Addr: "peer-1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseStaticPeer(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseStaticPeer(%q) = %+v, want an error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseStaticPeer(%q) error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseStaticPeer(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseStaticPeers_RejectsDuplicateIDs(t *testing.T) {
	_, err := ParseStaticPeers([]string{"a=10.0.0.1:8080", "a=10.0.0.2:8080"}, "local")
	if err == nil {
		t.Fatal("expected an error for two peers with the same id")
	}
}

// An identical entry repeated is collapsed, as the old map-keyed code did.
func TestParseStaticPeers_CollapsesIdenticalEntries(t *testing.T) {
	got, err := ParseStaticPeers([]string{"10.0.0.1:8080", "10.0.0.1:8080", "b=10.0.0.2:8080", "b=10.0.0.2:8080"}, "local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d peers, want 2 after collapsing repeats: %+v", len(got), got)
	}
}

// One daemon listed under two ids would show every container twice.
func TestParseStaticPeers_RejectsOneAddressUnderTwoIDs(t *testing.T) {
	_, err := ParseStaticPeers([]string{"a=10.0.0.2:8080", "b=10.0.0.2:8080"}, "local")
	if err == nil {
		t.Fatal("expected an error for one address under two ids")
	}
	_, err = ParseStaticPeers([]string{"10.0.0.2:8080", "b=10.0.0.2:8080"}, "local")
	if err == nil {
		t.Fatal("expected an error for an address-only entry and an id entry for the same address")
	}
}

func TestParseStaticPeers_RejectsTheLocalBackendID(t *testing.T) {
	_, err := ParseStaticPeers([]string{"local=10.0.0.2:8080"}, "local")
	if err == nil {
		t.Fatal("expected an error for a peer whose id is this daemon's own backend id")
	}
}

// A trailing comma on the flag yields an empty entry. Before explicit ids that
// became a harmless junk peer and the daemon started, so it must not be fatal.
func TestParseStaticPeers_IgnoresBlankEntries(t *testing.T) {
	got, err := ParseStaticPeers([]string{"a=10.0.0.1:8080", "", "  "}, "local")
	if err != nil {
		t.Fatalf("a blank entry must not fail startup: %v", err)
	}
	if len(got) != 1 || got[0].ID != "a" {
		t.Errorf("got %+v, want only peer a", got)
	}
}

func TestParseStaticPeers_ReportsTheBadEntry(t *testing.T) {
	_, err := ParseStaticPeers([]string{"a=10.0.0.1:8080", "b=oops"}, "local")
	if err == nil {
		t.Fatal("expected an error for an entry with no port")
	}
	if got := err.Error(); !strings.Contains(got, "b=oops") {
		t.Errorf("error %q should name the bad entry", got)
	}
}

func TestParseStaticPeers_Empty(t *testing.T) {
	got, err := ParseStaticPeers(nil, "local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d peers, want 0", len(got))
	}
}

// A static peer with an explicit id is keyed by that id, so `move --target <id>`
// and the incus remote of the same name resolve it. The address stays the dial
// target.
func TestNewPeerPool_StaticPeerWithExplicitID(t *testing.T) {
	pool := NewPeerPool("local-vm", "", []string{"backend-b=10.0.0.2:8080"}, "")

	peer := pool.Get("backend-b")
	if peer == nil {
		t.Fatal("expected the peer to be found by its explicit id")
	}
	if peer.ID != "backend-b" || peer.Addr != "10.0.0.2:8080" {
		t.Errorf("peer = {ID:%q Addr:%q}, want {backend-b 10.0.0.2:8080}", peer.ID, peer.Addr)
	}
	if pool.Get("10.0.0.2:8080") != nil {
		t.Error("a peer with an explicit id must not also be keyed by its address")
	}
}

func TestNewPeerPool_StaticPeerMixedForms(t *testing.T) {
	pool := NewPeerPool("local-vm", "", []string{"10.0.0.1:8080", "backend-b=10.0.0.2:8080"}, "")
	if len(pool.Peers()) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(pool.Peers()))
	}
	if pool.Get("10.0.0.1:8080") == nil {
		t.Error("address-only peer should still be keyed by its address")
	}
	if pool.Get("backend-b") == nil {
		t.Error("explicit-id peer should be keyed by its id")
	}
}

func TestNewPeerPool_SkipsInvalidStaticPeers(t *testing.T) {
	pool := NewPeerPool("local-vm", "", []string{"good=10.0.0.1:8080", "bad=oops", ""}, "")
	if len(pool.Peers()) != 1 {
		t.Fatalf("expected only the valid peer, got %d", len(pool.Peers()))
	}
	if pool.Get("good") == nil {
		t.Error("the valid peer should be kept")
	}
}

func TestNewPeerPool_SkipsAPeerWithTheLocalBackendID(t *testing.T) {
	pool := NewPeerPool("local-vm", "", []string{"local-vm=10.0.0.2:8080", "other=10.0.0.3:8080"}, "")
	if pool.Get("local-vm") != nil {
		t.Error("a static peer must not take this daemon's own backend id")
	}
	if pool.Get("other") == nil {
		t.Error("the other peer should be kept")
	}
}

// sentinelListing serves a sentinel /sentinel/peers response with the given
// peers, so discover() can be run against a fixed list.
func sentinelListing(t *testing.T, peers []map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"peers": peers})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Discovery removes pool keys that look sentinel-discovered once the sentinel
// stops listing them. A static peer is never discovered, so it must survive
// even when its address-only key happens to begin with the discovered prefix.
func TestDiscover_KeepsStaticPeers(t *testing.T) {
	srv := sentinelListing(t, nil)

	p := NewPeerPool("local", srv.URL, []string{"tunnel-lab", "backend-b=10.0.0.2:8080"}, "")
	p.discover()

	if p.Get("tunnel-lab") == nil {
		t.Error("an address-only static peer whose key starts with the discovered prefix must survive discovery")
	}
	if p.Get("backend-b") == nil {
		t.Error("a static peer with an explicit id must survive discovery")
	}
}

// If the sentinel lists a peer under the same id as a static one, the static
// peer's address is not redirected through the sentinel proxy.
func TestDiscover_DoesNotOverwriteAStaticPeerAddress(t *testing.T) {
	srv := sentinelListing(t, []map[string]any{
		{"id": "backend-b", "proxy_path": "/peer/backend-b", "healthy": true},
	})

	p := NewPeerPool("local", srv.URL, []string{"backend-b=10.0.0.2:8080"}, "")
	p.discover()

	peer := p.Get("backend-b")
	if peer == nil {
		t.Fatal("static peer disappeared")
	}
	if peer.Addr != "10.0.0.2:8080" {
		t.Errorf("static peer address was overwritten to %q", peer.Addr)
	}
}
