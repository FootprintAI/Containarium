package incus

import (
	"testing"

	"github.com/lxc/incus/v7/shared/api"
)

// caddyFixtureInstance builds one running container for the core-Caddy
// discovery tests: its name, optional role label, and primary IPv4.
func caddyFixtureInstance(name string, role Role, ip string) api.InstanceFull {
	config := map[string]string{}
	if role != RoleNone {
		config[RoleKey] = string(role)
	}
	return api.InstanceFull{
		Instance: api.Instance{
			Name: name, Status: "Running", Type: "container",
			InstancePut: api.InstancePut{Config: config},
		},
		State: &api.InstanceState{
			Network: map[string]api.InstanceStateNetwork{
				"eth0": {Addresses: []api.InstanceStateNetworkAddress{{Family: "inet", Address: ip, Scope: "global"}}},
			},
		},
	}
}

const (
	tenantCaddyName = "user1-caddy-box"
	tenantCaddyIP   = "192.0.2.66"
	coreCaddyIP     = "192.0.2.241"
)

// #3371: core Caddy discovery must identify the core service by its role
// label (or, for a pre-label core container, its exact core name) and never
// by a "caddy" substring a tenant can put in their own container's name.
// Every fixture lists the tenant container first, so a first-match substring
// scan picks it.
func TestFindCaddyContainerIP_IgnoresTenantCaddyNames(t *testing.T) {
	tenant := caddyFixtureInstance(tenantCaddyName, RoleNone, tenantCaddyIP)

	tests := []struct {
		name      string
		instances []api.InstanceFull
		wantIP    string
		wantErr   string
	}{
		{
			name: "labeled core caddy listed after a tenant caddy-named container",
			instances: []api.InstanceFull{
				tenant,
				caddyFixtureInstance("containarium-core-caddy", RoleCaddy, coreCaddyIP),
			},
			wantIP: coreCaddyIP,
		},
		{
			name: "role label wins regardless of the core container's name",
			instances: []api.InstanceFull{
				tenant,
				caddyFixtureInstance("edge-proxy", RoleCaddy, coreCaddyIP),
			},
			wantIP: coreCaddyIP,
		},
		{
			name: "pre-label core caddy resolves by its exact core name",
			instances: []api.InstanceFull{
				tenant,
				caddyFixtureInstance("containarium-core-caddy", RoleNone, coreCaddyIP),
			},
			wantIP: coreCaddyIP,
		},
		{
			name:      "only a tenant caddy-named container",
			instances: []api.InstanceFull{tenant},
			wantErr:   "no running Caddy container found",
		},
		{
			name: "name merely containing the core name is not the core container",
			instances: []api.InstanceFull{
				caddyFixtureInstance("user1-containarium-core-caddy", RoleNone, tenantCaddyIP),
			},
			wantErr: "no running Caddy container found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{server: &fakeListServer{instances: tt.instances}}

			ip, err := c.FindCaddyContainerIP()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("FindCaddyContainerIP() = %q, want error %q", ip, tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("FindCaddyContainerIP() error = %q, want %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FindCaddyContainerIP() unexpected error: %v", err)
			}
			if ip != tt.wantIP {
				t.Fatalf("FindCaddyContainerIP() = %q, want %q (tenant container is %q)", ip, tt.wantIP, tenantCaddyIP)
			}
		})
	}
}

// #3371: the pre-label name fallback in FindContainerByRole matches the exact
// core Caddy name, so a tenant container named like a caddy is never treated
// as the core Caddy by the daemon's other callers either.
func TestFindContainerByRole_CaddyFallbackIsExactName(t *testing.T) {
	c := &Client{server: &fakeListServer{instances: []api.InstanceFull{
		caddyFixtureInstance(tenantCaddyName, RoleNone, tenantCaddyIP),
	}}}

	if info, err := c.FindContainerByRole(RoleCaddy); err == nil {
		t.Fatalf("FindContainerByRole(RoleCaddy) = %q, want an error: only a tenant caddy-named container exists", info.Name)
	}
}
