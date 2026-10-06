package incus

import (
	"fmt"
	"sort"

	"github.com/lxc/incus/v7/shared/api"
)

// EnsureNICDevice makes sure containerName has an instance-local NIC device
// named want.Name on want.Network, pinned to want.IPv4Address when that is
// non-empty. It is idempotent: an equal instance-local device is a no-op.
//
// Why instance-local matters (core-infra network guard,
// docs/architecture/core-infra-network-guard.md): a NIC inherited from a
// profile is invisible in inst.Devices, so per-device keys such as
// security.acls cannot be set on it — AttachACLToContainer and
// SetDeviceConfig both fail with "device not found". Most core containers
// inherit eth0 from the default profile, so the guard calls this first to
// shadow the profile NIC with an instance-local copy it can then configure.
//
// The override is built from the expanded (profile-merged) view when one
// exists, so any nictype/parent settings the profile carries survive; only
// network and ipv4.address are asserted. An empty want.IPv4Address means
// "leave addressing alone": it neither sets nor clears ipv4.address.
func (c *Client) EnsureNICDevice(containerName string, want NICDevice) error {
	if want.Name == "" {
		return fmt.Errorf("ensure nic device on %s: device name is required", containerName)
	}

	inst, etag, err := c.server.GetInstance(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container %s: %w", containerName, err)
	}

	device, local := inst.Devices[want.Name]
	if !local {
		// Start from the profile-merged view so we don't drop settings the
		// profile carries; fall back to a bare NIC when nothing exists.
		if expanded, ok := inst.ExpandedDevices[want.Name]; ok {
			device = make(map[string]string, len(expanded)+2)
			for k, v := range expanded {
				device[k] = v
			}
		} else {
			device = map[string]string{}
		}
		device["type"] = "nic"
		device["name"] = want.Name
	}

	changed := !local
	if want.Network != "" && device["network"] != want.Network {
		device["network"] = want.Network
		changed = true
	}
	if want.IPv4Address != "" && device["ipv4.address"] != want.IPv4Address {
		device["ipv4.address"] = want.IPv4Address
		changed = true
	}
	if !changed {
		return nil
	}

	if inst.Devices == nil {
		inst.Devices = map[string]map[string]string{}
	}
	inst.Devices[want.Name] = device
	return c.updateInstanceDevices(containerName, inst, etag, "ensure nic device "+want.Name)
}

// SetDeviceConfig merges keys into an existing instance-local device and
// writes it back. Keys already equal are skipped, and when nothing would
// change no UpdateInstance is issued — the guard reconciler runs every
// minute and must be silent when converged.
//
// A device that exists only through a profile is refused: silently adding
// an instance-local device with just these keys would shadow the profile's
// NIC with an incomplete one. Callers that need to configure a profile NIC
// call EnsureNICDevice first.
func (c *Client) SetDeviceConfig(containerName, deviceName string, keys map[string]string) error {
	if len(keys) == 0 {
		return nil
	}

	inst, etag, err := c.server.GetInstance(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container %s: %w", containerName, err)
	}

	device, ok := inst.Devices[deviceName]
	if !ok {
		if _, inherited := inst.ExpandedDevices[deviceName]; inherited {
			return fmt.Errorf("device %s on %s is profile-inherited; call EnsureNICDevice to make it instance-local first", deviceName, containerName)
		}
		return fmt.Errorf("device %s not found in container %s", deviceName, containerName)
	}

	changed := false
	for k, v := range keys {
		if device[k] != v {
			device[k] = v
			changed = true
		}
	}
	if !changed {
		return nil
	}

	inst.Devices[deviceName] = device
	return c.updateInstanceDevices(containerName, inst, etag, "set device config "+deviceName+" "+sortedKeys(keys))
}

func (c *Client) updateInstanceDevices(containerName string, inst *api.Instance, etag, what string) error {
	// Incus writes backup.yaml as part of an instance update. A ZFS-backed root
	// dataset can have a quota below its effective root-disk size (or have been
	// left at an older quota), which makes that metadata write fail even though
	// the device update itself is valid. Reapply the effective root size before
	// issuing a device update so both NIC paths get the existing protection.
	//
	// This is deliberately non-fatal, matching SetDeviceSize: an unavailable
	// ZFS command must not hide the actual Incus update result.
	if err := c.prepareZFSQuotaHeadroomForDeviceUpdate(containerName, inst); err != nil {
		fmt.Printf("Warning: ZFS quota pre-expand before %s on %s failed (non-fatal): %v\n", what, containerName, err)
	}

	op, err := c.server.UpdateInstance(containerName, inst.Writable(), etag)
	if err != nil {
		return fmt.Errorf("%s on %s: %w", what, containerName, err)
	}
	if err := op.Wait(); err != nil {
		return fmt.Errorf("%s on %s (operation failed): %w", what, containerName, err)
	}
	return nil
}

// prepareZFSQuotaHeadroomForDeviceUpdate reapplies the effective root-disk
// size as the ZFS quota before a device update. The root disk may be inherited
// from a profile, so ExpandedDevices is the primary source; an instance-local
// root device takes precedence for keys changed in this update.
//
// Non-ZFS pools and roots without a size need no quota preparation.
func (c *Client) prepareZFSQuotaHeadroomForDeviceUpdate(containerName string, inst *api.Instance) error {
	if inst == nil {
		return nil
	}

	root, ok := inst.ExpandedDevices["root"]
	if !ok {
		root = inst.Devices["root"]
	}
	if root == nil {
		return nil
	}

	pool := root["pool"]
	targetSize := root["size"]
	if localRoot, ok := inst.Devices["root"]; ok {
		if localRoot["pool"] != "" {
			pool = localRoot["pool"]
		}
		if localRoot["size"] != "" {
			targetSize = localRoot["size"]
		}
	}
	if targetSize == "" {
		return nil
	}
	if pool == "" {
		pool = c.StoragePool()
	}

	storagePool, _, err := c.server.GetStoragePool(pool)
	if err != nil {
		return fmt.Errorf("get storage pool %s: %w", pool, err)
	}
	if storagePool == nil {
		return fmt.Errorf("get storage pool %s: empty response", pool)
	}
	if storagePool.Driver != "zfs" {
		return nil
	}

	if c.ensureZFSQuotaHeadroomFn != nil {
		return c.ensureZFSQuotaHeadroomFn(containerName, pool, targetSize)
	}
	return c.ensureZFSQuotaHeadroom(containerName, pool, targetSize)
}

// sortedKeys renders a key list deterministically for error messages.
func sortedKeys(m map[string]string) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return fmt.Sprint(ks)
}
