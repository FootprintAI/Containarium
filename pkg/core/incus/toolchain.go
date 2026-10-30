package incus

import (
	"reflect"

	"github.com/footprintai/containarium/pkg/core/toolchain"
)

func toolchainDevice(root string) map[string]string {
	return map[string]string{"type": "disk", "source": root, "path": toolchain.HostRoot, "readonly": "true"}
}

// EnsureToolchainVolume hotplugs the shared parent directory on existing boxes.
// Update through the same ETag/ZFS-quota seam used for other device changes.
func (c *Client) EnsureToolchainVolume(name, root string) error {
	inst, etag, err := c.server.GetInstance(name)
	if err != nil {
		return err
	}
	want := toolchainDevice(root)
	if reflect.DeepEqual(inst.Devices[toolchain.DeviceName], want) {
		return nil
	}
	if inst.Devices == nil {
		inst.Devices = map[string]map[string]string{}
	}
	inst.Devices[toolchain.DeviceName] = want
	return c.updateInstanceDevices(name, inst, etag, "ensure read-only toolchain volume")
}
