package server

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

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

	got := buildContainerIPMap(infos)

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
