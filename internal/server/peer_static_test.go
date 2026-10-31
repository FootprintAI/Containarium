package server

import (
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
	_, err := ParseStaticPeers([]string{"a=10.0.0.1:8080", "a=10.0.0.2:8080"})
	if err == nil {
		t.Fatal("expected an error for two peers with the same id")
	}
}

func TestParseStaticPeers_RejectsDuplicateAddressOnlyEntries(t *testing.T) {
	_, err := ParseStaticPeers([]string{"10.0.0.1:8080", "10.0.0.1:8080"})
	if err == nil {
		t.Fatal("expected an error for a repeated address")
	}
}

func TestParseStaticPeers_ReportsTheBadEntry(t *testing.T) {
	_, err := ParseStaticPeers([]string{"a=10.0.0.1:8080", "b=oops"})
	if err == nil {
		t.Fatal("expected an error for an entry with no port")
	}
	if got := err.Error(); !strings.Contains(got, "b=oops") {
		t.Errorf("error %q should name the bad entry", got)
	}
}

func TestParseStaticPeers_Empty(t *testing.T) {
	got, err := ParseStaticPeers(nil)
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
