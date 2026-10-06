package incus

import (
	"errors"
	"testing"

	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"
)

// fakeDeviceServer serves one instance and records every UpdateInstance
// so a test can assert on exactly what was written (or that nothing was).
type fakeDeviceServer struct {
	incusclient.InstanceServer

	inst   *api.Instance
	getErr error

	storagePool    *api.StoragePool
	storagePoolErr error
	updateErr      error

	updates []api.InstancePut
	events  []string
}

func (f *fakeDeviceServer) GetInstance(string) (*api.Instance, string, error) {
	if f.getErr != nil {
		return nil, "", f.getErr
	}
	// Hand out a copy so the code under test can't mutate the fixture
	// behind the test's back.
	cp := *f.inst
	cp.Devices = cloneDevices(f.inst.Devices)
	cp.ExpandedDevices = cloneDevices(f.inst.ExpandedDevices)
	return &cp, "etag", nil
}

func (f *fakeDeviceServer) UpdateInstance(_ string, put api.InstancePut, _ string) (incusclient.Operation, error) {
	f.updates = append(f.updates, put)
	f.events = append(f.events, "update")
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	return fakeOp{}, nil
}

func (f *fakeDeviceServer) GetStoragePool(string) (*api.StoragePool, string, error) {
	if f.storagePoolErr != nil {
		return nil, "", f.storagePoolErr
	}
	return f.storagePool, "etag", nil
}

type fakeOp struct{ incusclient.Operation }

func (fakeOp) Wait() error { return nil }

func cloneDevices(in map[string]map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(in))
	for name, dev := range in {
		d := make(map[string]string, len(dev))
		for k, v := range dev {
			d[k] = v
		}
		out[name] = d
	}
	return out
}

// profileNIC is what a container that inherits eth0 from the default
// profile looks like: nothing instance-local, but the NIC shows up in the
// expanded view.
func profileNIC() *api.Instance {
	return &api.Instance{
		InstancePut: api.InstancePut{Devices: map[string]map[string]string{}},
		ExpandedDevices: map[string]map[string]string{
			"eth0": {"type": "nic", "name": "eth0", "network": "incusbr0"},
		},
	}
}

func withRootDisk(inst *api.Instance, driver string) *fakeDeviceServer {
	inst.ExpandedDevices["root"] = map[string]string{
		"type": "disk",
		"path": "/",
		"pool": "default",
		"size": "7GiB",
	}
	return &fakeDeviceServer{inst: inst, storagePool: &api.StoragePool{Name: "default", Driver: driver}}
}

func TestEnsureNICDevice(t *testing.T) {
	tests := []struct {
		name       string
		inst       *api.Instance
		want       NICDevice
		wantWrites int
		wantDevice map[string]string // the eth0 written, when wantWrites == 1
	}{
		{
			name:       "profile-inherited NIC gets an instance-local override",
			inst:       profileNIC(),
			want:       NICDevice{Name: "eth0", Network: "incusbr0", IPv4Address: "10.100.0.242"},
			wantWrites: 1,
			wantDevice: map[string]string{"type": "nic", "name": "eth0", "network": "incusbr0", "ipv4.address": "10.100.0.242"},
		},
		{
			name:       "empty IPv4 does not write an ipv4.address key",
			inst:       profileNIC(),
			want:       NICDevice{Name: "eth0", Network: "incusbr0"},
			wantWrites: 1,
			wantDevice: map[string]string{"type": "nic", "name": "eth0", "network": "incusbr0"},
		},
		{
			name: "instance-local and equal is a no-op",
			inst: &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{
				"eth0": {"type": "nic", "name": "eth0", "network": "incusbr0", "ipv4.address": "10.100.0.242"},
			}}},
			want:       NICDevice{Name: "eth0", Network: "incusbr0", IPv4Address: "10.100.0.242"},
			wantWrites: 0,
		},
		{
			name: "instance-local with a different address is updated and keeps unrelated keys",
			inst: &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{
				"eth0": {"type": "nic", "name": "eth0", "network": "incusbr0", "ipv4.address": "10.100.0.9", "security.acls": "keep-me"},
			}}},
			want:       NICDevice{Name: "eth0", Network: "incusbr0", IPv4Address: "10.100.0.242"},
			wantWrites: 1,
			wantDevice: map[string]string{"type": "nic", "name": "eth0", "network": "incusbr0", "ipv4.address": "10.100.0.242", "security.acls": "keep-me"},
		},
		{
			name: "instance-local with an address is left alone when the caller asks for DHCP",
			inst: &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{
				"eth0": {"type": "nic", "name": "eth0", "network": "incusbr0", "ipv4.address": "10.100.0.9"},
			}}},
			want:       NICDevice{Name: "eth0", Network: "incusbr0"},
			wantWrites: 0,
		},
		{
			name:       "no NIC anywhere creates one from scratch",
			inst:       &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{}}},
			want:       NICDevice{Name: "eth0", Network: "incusbr0"},
			wantWrites: 1,
			wantDevice: map[string]string{"type": "nic", "name": "eth0", "network": "incusbr0"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeDeviceServer{inst: tc.inst}
			c := &Client{server: f}

			if err := c.EnsureNICDevice("box", tc.want); err != nil {
				t.Fatalf("EnsureNICDevice: %v", err)
			}
			if got := len(f.updates); got != tc.wantWrites {
				t.Fatalf("UpdateInstance calls = %d, want %d", got, tc.wantWrites)
			}
			if tc.wantWrites == 0 {
				return
			}
			got := f.updates[0].Devices[tc.want.Name]
			if len(got) != len(tc.wantDevice) {
				t.Fatalf("device written = %v, want %v", got, tc.wantDevice)
			}
			for k, v := range tc.wantDevice {
				if got[k] != v {
					t.Errorf("device[%q] = %q, want %q (full: %v)", k, got[k], v, got)
				}
			}
		})
	}
}

func TestEnsureNICDevice_GetErrorWritesNothing(t *testing.T) {
	boom := errors.New("incus down")
	f := &fakeDeviceServer{getErr: boom}
	c := &Client{server: f}

	err := c.EnsureNICDevice("box", NICDevice{Name: "eth0", Network: "incusbr0"})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapping %v", err, boom)
	}
	if len(f.updates) != 0 {
		t.Fatalf("UpdateInstance called %d times on a failed read", len(f.updates))
	}
}

func TestEnsureNICDevice_RejectsEmptyName(t *testing.T) {
	f := &fakeDeviceServer{inst: profileNIC()}
	c := &Client{server: f}
	if err := c.EnsureNICDevice("box", NICDevice{Network: "incusbr0"}); err == nil {
		t.Fatal("expected an error for an empty device name")
	}
	if len(f.updates) != 0 {
		t.Fatal("must not write when the request is invalid")
	}
}

func TestEnsureNICDevice_PreparesZFSQuotaHeadroomBeforeUpdate(t *testing.T) {
	f := withRootDisk(profileNIC(), "zfs")
	var gotContainer, gotPool, gotSize string
	c := &Client{
		server: f,
		ensureZFSQuotaHeadroomFn: func(containerName, pool, targetSize string) error {
			f.events = append(f.events, "quota")
			gotContainer, gotPool, gotSize = containerName, pool, targetSize
			return nil
		},
	}

	if err := c.EnsureNICDevice("box", NICDevice{Name: "eth0", Network: "incusbr0"}); err != nil {
		t.Fatalf("EnsureNICDevice: %v", err)
	}
	if gotContainer != "box" || gotPool != "default" || gotSize != "7GiB" {
		t.Errorf("quota headroom arguments = (%q, %q, %q), want (box, default, 7GiB)", gotContainer, gotPool, gotSize)
	}
	if got, want := f.events, []string{"quota", "update"}; !equalStrings(got, want) {
		t.Errorf("events = %v, want %v", got, want)
	}
}

func TestEnsureNICDevice_SkipsQuotaHeadroomForNonZFSPool(t *testing.T) {
	f := withRootDisk(profileNIC(), "dir")
	called := false
	c := &Client{
		server: f,
		ensureZFSQuotaHeadroomFn: func(string, string, string) error {
			called = true
			return nil
		},
	}

	if err := c.EnsureNICDevice("box", NICDevice{Name: "eth0", Network: "incusbr0"}); err != nil {
		t.Fatalf("EnsureNICDevice: %v", err)
	}
	if called {
		t.Fatal("quota headroom ran for a non-ZFS pool")
	}
	if len(f.updates) != 1 {
		t.Fatalf("UpdateInstance calls = %d, want 1", len(f.updates))
	}
}

func TestSetDeviceConfig(t *testing.T) {
	local := func() *api.Instance {
		return &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{
			"eth0": {"type": "nic", "name": "eth0", "network": "incusbr0", "security.acls": "old"},
		}}}
	}

	tests := []struct {
		name       string
		inst       *api.Instance
		keys       map[string]string
		wantWrites int
		wantDevice map[string]string
		wantErr    bool
	}{
		{
			name:       "merges new keys and overwrites changed ones",
			inst:       local(),
			keys:       map[string]string{"security.acls": "guard", "security.acls.default.ingress.action": "drop"},
			wantWrites: 1,
			wantDevice: map[string]string{"type": "nic", "name": "eth0", "network": "incusbr0", "security.acls": "guard", "security.acls.default.ingress.action": "drop"},
		},
		{
			name:       "all keys already equal is a no-op",
			inst:       local(),
			keys:       map[string]string{"security.acls": "old"},
			wantWrites: 0,
		},
		{
			name:       "no keys is a no-op",
			inst:       local(),
			keys:       map[string]string{},
			wantWrites: 0,
		},
		{
			name:    "profile-inherited device is refused rather than silently shadowed",
			inst:    profileNIC(),
			keys:    map[string]string{"security.acls": "guard"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeDeviceServer{inst: tc.inst}
			c := &Client{server: f}

			err := c.SetDeviceConfig("box", "eth0", tc.keys)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				if len(f.updates) != 0 {
					t.Fatal("must not write on a refused request")
				}
				return
			}
			if err != nil {
				t.Fatalf("SetDeviceConfig: %v", err)
			}
			if got := len(f.updates); got != tc.wantWrites {
				t.Fatalf("UpdateInstance calls = %d, want %d", got, tc.wantWrites)
			}
			if tc.wantWrites == 0 {
				return
			}
			got := f.updates[0].Devices["eth0"]
			if len(got) != len(tc.wantDevice) {
				t.Fatalf("device written = %v, want %v", got, tc.wantDevice)
			}
			for k, v := range tc.wantDevice {
				if got[k] != v {
					t.Errorf("device[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestSetDeviceConfig_QuotaPreparationFailureDoesNotMaskUpdateResult(t *testing.T) {
	local := func() *api.Instance {
		return &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{
			"eth0": {"type": "nic", "name": "eth0", "network": "incusbr0", "security.acls": "old"},
		}}, ExpandedDevices: map[string]map[string]string{}}
	}

	tests := []struct {
		name      string
		updateErr error
	}{
		{name: "successful update remains successful"},
		{name: "Incus update error is returned", updateErr: errors.New("update failed")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := withRootDisk(local(), "zfs")
			f.updateErr = tc.updateErr
			quotaErr := errors.New("zfs unavailable")
			quotaCalls := 0
			c := &Client{
				server: f,
				ensureZFSQuotaHeadroomFn: func(string, string, string) error {
					quotaCalls++
					return quotaErr
				},
			}

			err := c.SetDeviceConfig("box", "eth0", map[string]string{"security.acls": "guard"})
			if tc.updateErr == nil && err != nil {
				t.Fatalf("SetDeviceConfig error = %v, want nil", err)
			}
			if tc.updateErr != nil && !errors.Is(err, tc.updateErr) {
				t.Fatalf("SetDeviceConfig error = %v, want wrapping %v", err, tc.updateErr)
			}
			if len(f.updates) != 1 {
				t.Fatalf("UpdateInstance calls = %d, want 1", len(f.updates))
			}
			if quotaCalls != 1 {
				t.Fatalf("quota headroom calls = %d, want 1", quotaCalls)
			}
		})
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// The guard's reconciler is written against Backend, so every method it
// needs has to be on the interface — and the incus-less variant has to
// refuse them cleanly instead of panicking on a nil client.
func TestUnavailableBackend_GuardMethodsReturnErrUnavailable(t *testing.T) {
	var b Backend = NewUnavailableBackend()

	if _, err := b.GetNetworkACL("x"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("GetNetworkACL err = %v", err)
	}
	if err := b.CreateNetworkACL(ACLConfig{Name: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("CreateNetworkACL err = %v", err)
	}
	if err := b.UpdateNetworkACL("x", ACLConfig{Name: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("UpdateNetworkACL err = %v", err)
	}
	if err := b.AttachACLToContainer("c", "x", "eth0"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("AttachACLToContainer err = %v", err)
	}
	if err := b.EnsureNICDevice("c", NICDevice{Name: "eth0"}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("EnsureNICDevice err = %v", err)
	}
	if err := b.SetDeviceConfig("c", "eth0", map[string]string{"k": "v"}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("SetDeviceConfig err = %v", err)
	}
}
