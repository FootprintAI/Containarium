package server

import "testing"

// TestCoreStaticIP covers the deterministic stable-IP assignment for core
// containers (#240): caddy gets a fixed high host in the bridge subnet so a
// recreate reuses the same IP, keeping the dnsmasq/DNAT references valid.
func TestCoreStaticIP(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		container string
		want      string
		wantErr   bool
	}{
		{
			name:      "caddy in /24 gateway form",
			cidr:      "10.100.0.1/24",
			container: CoreCaddyContainer,
			want:      "10.100.0.241",
		},
		{
			name:      "caddy in /24 network form",
			cidr:      "10.20.0.0/24",
			container: CoreCaddyContainer,
			want:      "10.20.0.241",
		},
		{
			name:      "caddy in /16 masks to network base + offset",
			cidr:      "10.100.5.1/16",
			container: CoreCaddyContainer,
			want:      "10.100.0.241",
		},
		{
			// Postgres and the metrics container are pinned too, so the
			// pg_hba.conf written when Postgres is first installed can name the
			// exact address Grafana will have, instead of the whole subnet.
			name:      "postgres is pinned",
			cidr:      "10.100.0.1/24",
			container: CorePostgresContainer,
			want:      "10.100.0.240",
		},
		{
			name:      "metrics container is pinned",
			cidr:      "10.100.0.1/24",
			container: CoreVictoriaMetricsContainer,
			want:      "10.100.0.239",
		},
		{
			name:      "container without an assigned offset falls back to DHCP",
			cidr:      "10.100.0.1/24",
			container: CoreSecurityContainer,
			want:      "", // no offset → empty, no error
		},
		{
			name:      "unparseable cidr errors",
			cidr:      "not-a-cidr",
			container: CoreCaddyContainer,
			wantErr:   true,
		},
		{
			name:      "subnet too small for the offset errors",
			cidr:      "10.0.0.0/28", // 16 hosts; offset 241 is out of range
			container: CoreCaddyContainer,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := coreStaticIP(tc.cidr, tc.container)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (ip=%q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("coreStaticIP(%q,%q) = %q, want %q", tc.cidr, tc.container, got, tc.want)
			}
		})
	}
}

// Two core containers on one address would be an outage that looks like a
// network fault. The pinned offsets must stay distinct and inside a /24.
func TestCoreStaticIPHostOffsets_DistinctAndInRange(t *testing.T) {
	seen := map[uint32]string{}
	for name, off := range coreStaticIPHostOffsets {
		if other, dup := seen[off]; dup {
			t.Errorf("%s and %s are both pinned to host offset %d", name, other, off)
		}
		seen[off] = name
		if off < 3 || off > 253 {
			t.Errorf("%s offset %d is outside the usable range of a /24", name, off)
		}
	}
}

// TestCoreStaticIP_Deterministic: the whole point is stability across recreates
// — same inputs must always yield the same IP.
func TestCoreStaticIP_Deterministic(t *testing.T) {
	const cidr = "10.20.0.1/24"
	first, err := coreStaticIP(cidr, CoreCaddyContainer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := coreStaticIP(cidr, CoreCaddyContainer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if again != first {
			t.Fatalf("non-deterministic: got %q then %q", first, again)
		}
	}
}
