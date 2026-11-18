package server

import (
	"net/netip"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// hostAddrs builds a resolver from name -> host-known address. A name not in
// the map has no host-known address.
func hostAddrs(m map[string]string) HostAddressResolver {
	return func(name string, _ netip.Addr) (netip.Addr, bool) {
		s, ok := m[name]
		if !ok {
			return netip.Addr{}, false
		}
		return netip.MustParseAddr(s), true
	}
}

// TestBuildContainerIPMap covers the source-IP → identity projection that
// feeds container_ips.json (#231/#264 metrics ingest). Each entry must carry
// the cloud_container_id (the cloud's metrics join key) when present; core
// containers and IP-less boxes are excluded.
func TestBuildContainerIPMap(t *testing.T) {
	infos := []incus.ContainerInfo{
		{
			Name:      "alice-container",
			IPAddress: "10.0.0.5",
			Labels:    map[string]string{cloudContainerIDLabel: "cld-uuid-1"},
		},
		{
			// CLI/standalone box: has an IP but no cloud label.
			Name:      "bob-container",
			IPAddress: "10.0.0.6",
		},
		{
			// Core container — never attributed.
			Name:      "containarium-core-caddy",
			IPAddress: "10.0.0.2",
			Role:      incus.RoleCaddy,
		},
		{
			// Not placed yet — no IP to key on.
			Name:   "carol-container",
			Labels: map[string]string{cloudContainerIDLabel: "cld-uuid-2"},
		},
	}
	resolve := hostAddrs(map[string]string{
		"alice-container": "10.0.0.5",
		"bob-container":   "10.0.0.6",
		"carol-container": "10.0.0.7",
	})

	got := buildContainerIPMap(infos, resolve)

	if len(got) != 2 {
		t.Fatalf("expected 2 entries (core + IP-less skipped), got %d: %+v", len(got), got)
	}
	if e := got["10.0.0.5"]; e.Name != "alice-container" || e.CloudContainerID != "cld-uuid-1" {
		t.Errorf("alice entry = %+v; want name=alice-container cloud=cld-uuid-1", e)
	}
	if e := got["10.0.0.6"]; e.Name != "bob-container" || e.CloudContainerID != "" {
		t.Errorf("bob entry = %+v; want name=bob-container cloud=\"\" (no label)", e)
	}
	if _, ok := got["10.0.0.2"]; ok {
		t.Error("core container must be excluded")
	}
}

// #3774: the source-IP map is keyed on the host-known address, never on what the
// guest reports. A guest claiming another box's address does not take it over,
// and a box with no host-known address gets no entry (fails per box).
func TestBuildContainerIPMap_KeysOnHostKnownAddressOnly(t *testing.T) {
	infos := []incus.ContainerInfo{
		{
			// mallory's guest claims alice's address; the host knows her as .99.
			Name:      "mallory-container",
			IPAddress: "10.0.0.5",
			Labels:    map[string]string{cloudContainerIDLabel: "cld-mallory"},
		},
		{
			Name:      "alice-container",
			IPAddress: "10.0.0.5",
			Labels:    map[string]string{cloudContainerIDLabel: "cld-alice"},
		},
		{
			// guest reports .8, the host has no address for it: no entry at all.
			Name:      "eve-container",
			IPAddress: "10.0.0.8",
		},
	}
	resolve := hostAddrs(map[string]string{
		"mallory-container": "10.0.0.99",
		"alice-container":   "10.0.0.5",
	})

	got := buildContainerIPMap(infos, resolve)

	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(got), got)
	}
	if e := got["10.0.0.5"]; e.Name != "alice-container" || e.CloudContainerID != "cld-alice" {
		t.Errorf("10.0.0.5 entry = %+v; want alice (mallory's guest claim must not win)", e)
	}
	if e := got["10.0.0.99"]; e.Name != "mallory-container" {
		t.Errorf("10.0.0.99 entry = %+v; want mallory (host-known)", e)
	}
	if _, ok := got["10.0.0.8"]; ok {
		t.Error("guest-reported 10.0.0.8 with no host-known address must not be keyed")
	}
}
