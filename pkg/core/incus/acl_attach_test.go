package incus

import (
	"testing"

	"github.com/lxc/incus/v7/shared/api"
)

// localNIC is a container whose eth0 is instance-local, optionally already
// carrying a security.acls list.
func localNIC(acls string) *api.Instance {
	dev := map[string]string{"type": "nic", "name": "eth0", "network": "incusbr0"}
	if acls != "" {
		dev["security.acls"] = acls
	}
	return &api.Instance{
		InstancePut:     api.InstancePut{Devices: map[string]map[string]string{"eth0": dev}},
		ExpandedDevices: map[string]map[string]string{"eth0": cloneDevices(map[string]map[string]string{"eth0": dev})["eth0"]},
	}
}

// #2348: AttachACLToContainer must work on the NIC every tenant box actually
// has (profile-inherited eth0), append to an existing security.acls list
// rather than overwrite it, and be idempotent.
func TestAttachACLToContainer(t *testing.T) {
	tests := []struct {
		name       string
		inst       *api.Instance
		acl        string
		wantWrites int
		wantACLs   string // security.acls on the written eth0, when wantWrites == 1
	}{
		{
			name:       "profile-inherited eth0 is shadowed by an instance-local copy carrying the ACL",
			inst:       profileNIC(),
			acl:        "acl-alice",
			wantWrites: 1,
			wantACLs:   "acl-alice",
		},
		{
			name:       "instance-local eth0 with no ACL gets the ACL",
			inst:       localNIC(""),
			acl:        "acl-alice",
			wantWrites: 1,
			wantACLs:   "acl-alice",
		},
		{
			name:       "an existing ACL list is appended to, not overwritten",
			inst:       localNIC("containarium-tenant-abc"),
			acl:        "acl-alice",
			wantWrites: 1,
			wantACLs:   "containarium-tenant-abc,acl-alice",
		},
		{
			name:       "already attached is a no-op",
			inst:       localNIC("containarium-tenant-abc,acl-alice"),
			acl:        "acl-alice",
			wantWrites: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &fakeDeviceServer{inst: tt.inst}
			c := &Client{server: srv}
			if err := c.AttachACLToContainer("alice-container", tt.acl, "eth0"); err != nil {
				t.Fatalf("AttachACLToContainer: %v", err)
			}
			if got := len(srv.updates); got != tt.wantWrites {
				t.Fatalf("writes = %d, want %d", got, tt.wantWrites)
			}
			if tt.wantWrites == 0 {
				return
			}
			eth0 := srv.updates[0].Devices["eth0"]
			if eth0 == nil {
				t.Fatalf("written instance has no eth0: %+v", srv.updates[0].Devices)
			}
			if eth0["security.acls"] != tt.wantACLs {
				t.Errorf("security.acls = %q, want %q", eth0["security.acls"], tt.wantACLs)
			}
			// The profile's own keys must survive the shadowing.
			if eth0["network"] != "incusbr0" || eth0["type"] != "nic" || eth0["name"] != "eth0" {
				t.Errorf("profile keys lost on shadowed eth0: %v", eth0)
			}
		})
	}
}

func TestAttachACLToContainer_noSuchDevice(t *testing.T) {
	srv := &fakeDeviceServer{inst: &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{}}}}
	c := &Client{server: srv}
	if err := c.AttachACLToContainer("alice-container", "acl-alice", "eth0"); err == nil {
		t.Fatal("expected an error when the container has no eth0 at all")
	}
	if len(srv.updates) != 0 {
		t.Fatalf("expected no writes, got %d", len(srv.updates))
	}
}

// GetContainerACL reads the effective NIC, so an ACL a profile carries is
// reported too, not only an instance-local one.
func TestGetContainerACL_readsExpandedDevices(t *testing.T) {
	inst := profileNIC()
	inst.ExpandedDevices["eth0"]["security.acls"] = "from-profile"
	c := &Client{server: &fakeDeviceServer{inst: inst}}
	got, err := c.GetContainerACL("alice-container", "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-profile" {
		t.Errorf("GetContainerACL = %q, want %q", got, "from-profile")
	}
}

// SetOwnedACL (#2364): the tenant guard owns every containarium-tenant-*
// entry on a NIC. Re-attributing a box to another tenant must replace its
// old tenant ACL, never stack the two (the old table would keep admitting the
// old siblings); entries the guard does not own are left alone.
func TestSetOwnedACL(t *testing.T) {
	const prefix = "containarium-tenant-"
	tests := []struct {
		name       string
		inst       *api.Instance
		acl        string
		wantWrites int
		wantACLs   string
	}{
		{"profile NIC is shadowed and gets the ACL", profileNIC(), prefix + "new", 1, prefix + "new"},
		{"another tenant's ACL is replaced", localNIC(prefix + "old"), prefix + "new", 1, prefix + "new"},
		{"per-container ACL is kept, old tenant ACL replaced", localNIC("acl-alice," + prefix + "old"), prefix + "new", 1, "acl-alice," + prefix + "new"},
		{"already exactly right is a no-op", localNIC("acl-alice," + prefix + "new"), prefix + "new", 0, ""},
		{"owned ACL appended when absent, others kept", localNIC("acl-alice"), prefix + "new", 1, "acl-alice," + prefix + "new"},
		{"duplicates of the owned ACL collapse", localNIC(prefix + "new," + prefix + "new"), prefix + "new", 1, prefix + "new"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &fakeDeviceServer{inst: tt.inst}
			c := &Client{server: srv}
			if err := c.SetOwnedACL("alice-container", tt.acl, "eth0", prefix); err != nil {
				t.Fatalf("SetOwnedACL: %v", err)
			}
			if got := len(srv.updates); got != tt.wantWrites {
				t.Fatalf("writes = %d, want %d", got, tt.wantWrites)
			}
			if tt.wantWrites == 1 {
				eth0 := srv.updates[0].Devices["eth0"]
				if eth0["security.acls"] != tt.wantACLs {
					t.Errorf("security.acls = %q, want %q", eth0["security.acls"], tt.wantACLs)
				}
				if eth0["network"] != "incusbr0" || eth0["type"] != "nic" {
					t.Errorf("profile keys lost: %v", eth0)
				}
			}
		})
	}
	c := &Client{server: &fakeDeviceServer{inst: localNIC("")}}
	if err := c.SetOwnedACL("alice-container", "", "eth0", prefix); err == nil {
		t.Error("an empty ACL name must be refused")
	}
	if err := c.SetOwnedACL("alice-container", "x", "eth0", ""); err == nil {
		t.Error("an empty owned prefix must be refused (it would own every ACL)")
	}
}
