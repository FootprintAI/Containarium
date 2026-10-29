package incus

import (
	"reflect"
	"testing"

	"github.com/lxc/incus/v7/shared/api"
)

func TestEnsureToolchainVolume(t *testing.T) {
	for _, readonly := range []string{"", "false", "true"} {
		t.Run("readonly="+readonly, func(t *testing.T) {
			want := map[string]string{"type": "disk", "source": "/opt/containarium/toolchains", "path": "/opt/containarium/toolchains", "readonly": "true"}
			device := map[string]string{}
			for k, v := range want {
				device[k] = v
			}
			device["readonly"] = readonly
			fake := &fakeDeviceServer{inst: &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{"toolchains": device}}}}
			client := &Client{server: fake}
			mount, ok := any(client).(interface{ EnsureToolchainVolume(string, string) error })
			if !ok {
				t.Fatal("Incus client cannot attach the managed toolchain volume")
			}
			if err := mount.EnsureToolchainVolume("alice-container", "/opt/containarium/toolchains"); err != nil {
				t.Fatal(err)
			}
			if readonly == "true" {
				if len(fake.updates) != 0 {
					t.Fatal("converged volume must be a no-op")
				}
			} else if len(fake.updates) != 1 || !reflect.DeepEqual(fake.updates[0].Devices["toolchains"], want) {
				t.Fatalf("must repair a writable mount: %+v", fake.updates)
			}
		})
	}
}
