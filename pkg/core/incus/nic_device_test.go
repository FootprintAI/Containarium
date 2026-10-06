package incus

import (
	"errors"
	"strings"
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

	storagePool      *api.StoragePool
	storagePoolErr   error
	storageVolume    *api.StorageVolume
	storageVolumeErr error
	updateErr        error
	afterUpdate      *api.Instance
	afterUpdateHook  func()

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
	if f.afterUpdate != nil {
		f.inst = f.afterUpdate
	}
	if f.afterUpdateHook != nil {
		f.afterUpdateHook()
	}
	return fakeOp{}, nil
}

func (f *fakeDeviceServer) GetStoragePool(string) (*api.StoragePool, string, error) {
	if f.storagePoolErr != nil {
		return nil, "", f.storagePoolErr
	}
	return f.storagePool, "etag", nil
}

func (f *fakeDeviceServer) GetStoragePoolVolume(string, string, string) (*api.StorageVolume, string, error) {
	if f.storageVolumeErr != nil {
		return nil, "", f.storageVolumeErr
	}
	return f.storageVolume, "etag", nil
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
	properties := map[string]string{"used": "7516192768", "quota": "7516192768"}
	c := &Client{
		server: f,
		zfsGetPropertyFn: func(_ string, property string) (string, error) {
			return properties[property], nil
		},
		zfsSetPropertyFn: func(_ string, property, value string) error {
			f.events = append(f.events, "set:"+property+":"+value)
			properties[property] = value
			return nil
		},
	}

	if err := c.EnsureNICDevice("box", NICDevice{Name: "eth0", Network: "incusbr0"}); err != nil {
		t.Fatalf("EnsureNICDevice: %v", err)
	}
	if len(f.events) != 3 {
		t.Fatalf("events = %v, want temporary set, update, restore", f.events)
	}
	if !strings.HasPrefix(f.events[0], "set:quota:7583301632") || f.events[1] != "update" || f.events[2] != "set:quota:7516192768" {
		t.Errorf("events = %v, want temporary quota set, update, restore", f.events)
	}
}

func TestEnsureNICDevice_PreparesRefquotaHeadroomBeforeUpdate(t *testing.T) {
	f := withRootDisk(profileNIC(), "zfs")
	f.storagePool.Config = map[string]string{"volume.zfs.use_refquota": "true"}
	properties := map[string]string{"referenced": "7516192768", "refquota": "7516192768"}
	c := &Client{
		server:           f,
		zfsGetPropertyFn: func(_ string, property string) (string, error) { return properties[property], nil },
		zfsSetPropertyFn: func(_ string, property, value string) error {
			f.events = append(f.events, "set:"+property+":"+value)
			properties[property] = value
			return nil
		},
	}
	if err := c.EnsureNICDevice("box", NICDevice{Name: "eth0", Network: "incusbr0"}); err != nil {
		t.Fatalf("EnsureNICDevice: %v", err)
	}
	if len(f.events) != 3 || !strings.HasPrefix(f.events[0], "set:refquota:") || f.events[1] != "update" || f.events[2] != "set:refquota:7516192768" {
		t.Errorf("events = %v, want temporary refquota set, update, restore", f.events)
	}
}

func TestEnsureNICDevice_PreservesStricterLiveQuota(t *testing.T) {
	f := withRootDisk(profileNIC(), "zfs")
	f.inst.ExpandedDevices["root"]["size"] = "10GiB"
	properties := map[string]string{"used": "8589934592", "quota": "8589934592"}
	var values []string
	c := &Client{
		server:           f,
		zfsGetPropertyFn: func(_ string, property string) (string, error) { return properties[property], nil },
		zfsSetPropertyFn: func(_ string, property, value string) error {
			values = append(values, value)
			properties[property] = value
			return nil
		},
	}

	if err := c.EnsureNICDevice("box", NICDevice{Name: "eth0", Network: "incusbr0"}); err != nil {
		t.Fatalf("EnsureNICDevice: %v", err)
	}
	if len(values) != 2 || values[0] != "10737418240" || values[1] != "8589934592" {
		t.Errorf("ZFS set values = %v, want temporary 10GiB and original live 8GiB", values)
	}
}

func TestEnsureNICDevice_UnlimitedQuotaDoesNotNeedHeadroom(t *testing.T) {
	f := withRootDisk(profileNIC(), "zfs")
	properties := map[string]string{"used": "7516192768", "quota": "none"}
	sets := 0
	c := &Client{
		server:           f,
		zfsGetPropertyFn: func(_ string, property string) (string, error) { return properties[property], nil },
		zfsSetPropertyFn: func(string, string, string) error {
			sets++
			return nil
		},
	}

	if err := c.EnsureNICDevice("box", NICDevice{Name: "eth0", Network: "incusbr0"}); err != nil {
		t.Fatalf("EnsureNICDevice: %v", err)
	}
	if sets != 0 {
		t.Fatalf("ZFS sets = %d, want none for an unlimited quota", sets)
	}
	if len(f.updates) != 1 {
		t.Fatalf("UpdateInstance calls = %d, want 1", len(f.updates))
	}
}

func TestEnsureNICDevice_VolumeRefquotaOverrideWinsOverPoolDefault(t *testing.T) {
	f := withRootDisk(profileNIC(), "zfs")
	f.storagePool.Config = map[string]string{"volume.zfs.use_refquota": "true"}
	f.storageVolume = &api.StorageVolume{StorageVolumePut: api.StorageVolumePut{Config: map[string]string{"zfs.use_refquota": "false"}}}
	properties := map[string]string{"used": "7516192768", "quota": "7516192768"}
	c := &Client{
		server:           f,
		zfsGetPropertyFn: func(_ string, property string) (string, error) { return properties[property], nil },
		zfsSetPropertyFn: func(_ string, property, value string) error {
			f.events = append(f.events, "set:"+property+":"+value)
			return nil
		},
	}
	if err := c.EnsureNICDevice("box", NICDevice{Name: "eth0", Network: "incusbr0"}); err != nil {
		t.Fatalf("EnsureNICDevice: %v", err)
	}
	if len(f.events) == 0 || !strings.HasPrefix(f.events[0], "set:quota:") {
		t.Errorf("events = %v, want volume override to select quota", f.events)
	}
}

func TestEnsureNICDevice_SkipsQuotaHeadroomForNonZFSPool(t *testing.T) {
	f := withRootDisk(profileNIC(), "dir")
	called := false
	c := &Client{
		server: f,
		zfsGetPropertyFn: func(string, string) (string, error) {
			called = true
			return "", nil
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

func TestEnsureNICDevice_ConvergedRootDoesNotTouchZFS(t *testing.T) {
	inst := &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{
		"eth0": {"type": "nic", "name": "eth0", "network": "incusbr0"},
	}}, ExpandedDevices: map[string]map[string]string{}}
	f := withRootDisk(inst, "zfs")
	c := &Client{
		server: f,
		zfsGetPropertyFn: func(string, string) (string, error) {
			t.Fatal("converged device update read ZFS")
			return "", nil
		},
	}
	if err := c.EnsureNICDevice("box", NICDevice{Name: "eth0", Network: "incusbr0"}); err != nil {
		t.Fatalf("EnsureNICDevice: %v", err)
	}
	if len(f.updates) != 0 {
		t.Fatalf("UpdateInstance calls = %d, want 0", len(f.updates))
	}
}

func TestEffectiveRootDisk_LocalOverrideWins(t *testing.T) {
	inst := &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{
		"root": {"pool": "local", "size": "13GiB"},
	}}, ExpandedDevices: map[string]map[string]string{
		"root": {"pool": "default", "size": "7GiB"},
	}}
	pool, size, ok := effectiveRootDisk(inst)
	if !ok || pool != "local" || size != "13GiB" {
		t.Errorf("effectiveRootDisk = (%q, %q, %t), want (local, 13GiB, true)", pool, size, ok)
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
				zfsGetPropertyFn: func(string, string) (string, error) {
					quotaCalls++
					return "", quotaErr
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

func TestSetDeviceConfig_RestoresHeadroomAndPreservesUpdateFailure(t *testing.T) {
	local := func(size string) *api.Instance {
		return &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{
			"eth0": {"type": "nic", "name": "eth0", "network": "incusbr0", "security.acls": "old"},
		}}, ExpandedDevices: map[string]map[string]string{
			"root": {"type": "disk", "path": "/", "pool": "default", "size": size},
		}}
	}
	tests := []struct {
		name       string
		updateErr  error
		restoreErr error
		wantErr    error
	}{
		{name: "restore after success", restoreErr: errors.New("restore failed"), wantErr: errors.New("restore failed")},
		{name: "update failure wins over restore failure", updateErr: errors.New("update failed"), restoreErr: errors.New("restore failed")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeDeviceServer{inst: local("7GiB"), storagePool: &api.StoragePool{Name: "default", Driver: "zfs"}, updateErr: tc.updateErr}
			properties := map[string]string{"used": "7516192768", "quota": "7516192768"}
			sets := 0
			c := &Client{
				server:           f,
				zfsGetPropertyFn: func(_ string, property string) (string, error) { return properties[property], nil },
				zfsSetPropertyFn: func(_ string, _ string, _ string) error {
					sets++
					if sets == 2 {
						return tc.restoreErr
					}
					return nil
				},
			}
			err := c.SetDeviceConfig("box", "eth0", map[string]string{"security.acls": "guard"})
			if tc.updateErr != nil {
				if !errors.Is(err, tc.updateErr) {
					t.Fatalf("err = %v, want update failure", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "restore failed") {
				t.Fatalf("err = %v, want restoration failure", err)
			}
			if sets != 2 {
				t.Fatalf("ZFS sets = %d, want temporary set and restoration", sets)
			}
		})
	}
}

func TestSetDeviceConfig_RestoreUsesCurrentRootSizeAfterConcurrentResize(t *testing.T) {
	initial := &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{
		"eth0": {"type": "nic", "name": "eth0", "network": "incusbr0", "security.acls": "old"},
	}}, ExpandedDevices: map[string]map[string]string{
		"root": {"type": "disk", "path": "/", "pool": "default", "size": "10GiB"},
	}}
	current := &api.Instance{InstancePut: initial.InstancePut, ExpandedDevices: map[string]map[string]string{
		"root": {"type": "disk", "path": "/", "pool": "default", "size": "20GiB"},
	}}
	f := &fakeDeviceServer{inst: initial, afterUpdate: current, storagePool: &api.StoragePool{Name: "default", Driver: "zfs"}}
	properties := map[string]string{"used": "8589934592", "quota": "8589934592"}
	var values []string
	c := &Client{
		server:           f,
		zfsGetPropertyFn: func(_ string, property string) (string, error) { return properties[property], nil },
		zfsSetPropertyFn: func(_ string, _ string, value string) error { values = append(values, value); return nil },
	}
	if err := c.SetDeviceConfig("box", "eth0", map[string]string{"security.acls": "guard"}); err != nil {
		t.Fatalf("SetDeviceConfig: %v", err)
	}
	if len(values) != 2 || values[1] != "20GiB" {
		t.Errorf("ZFS set values = %v, want restore to current 20GiB", values)
	}
}

func TestSetDeviceConfig_RestoreSkipsConcurrentPoolChange(t *testing.T) {
	initial := deviceConfigInstanceWithRoot("default", "7GiB")
	current := deviceConfigInstanceWithRoot("other", "7GiB")
	f := &fakeDeviceServer{inst: initial, afterUpdate: current, storagePool: &api.StoragePool{Name: "default", Driver: "zfs"}}
	properties := map[string]string{"used": "7516192768", "quota": "7516192768"}
	var values []string
	c := &Client{
		server:           f,
		zfsGetPropertyFn: func(_ string, property string) (string, error) { return properties[property], nil },
		zfsSetPropertyFn: func(_ string, _ string, value string) error { values = append(values, value); return nil },
	}

	if err := c.SetDeviceConfig("box", "eth0", map[string]string{"security.acls": "guard"}); err != nil {
		t.Fatalf("SetDeviceConfig: %v", err)
	}
	if len(values) != 1 {
		t.Errorf("ZFS set values = %v, want only temporary set after pool change", values)
	}
}

func TestSetDeviceConfig_RestoreSkipsConcurrentQuotaModeChange(t *testing.T) {
	f := &fakeDeviceServer{inst: deviceConfigInstanceWithRoot("default", "7GiB"), storagePool: &api.StoragePool{Name: "default", Driver: "zfs"}}
	f.afterUpdateHook = func() {
		f.storagePool.Config = map[string]string{"volume.zfs.use_refquota": "true"}
	}
	properties := map[string]string{"used": "7516192768", "quota": "7516192768"}
	var values []string
	c := &Client{
		server:           f,
		zfsGetPropertyFn: func(_ string, property string) (string, error) { return properties[property], nil },
		zfsSetPropertyFn: func(_ string, _ string, value string) error { values = append(values, value); return nil },
	}

	if err := c.SetDeviceConfig("box", "eth0", map[string]string{"security.acls": "guard"}); err != nil {
		t.Fatalf("SetDeviceConfig: %v", err)
	}
	if len(values) != 1 {
		t.Errorf("ZFS set values = %v, want only temporary set after quota-mode change", values)
	}
}

func deviceConfigInstanceWithRoot(pool, size string) *api.Instance {
	return &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{
		"eth0": {"type": "nic", "name": "eth0", "network": "incusbr0", "security.acls": "old"},
	}}, ExpandedDevices: map[string]map[string]string{
		"root": {"type": "disk", "path": "/", "pool": pool, "size": size},
	}}
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
