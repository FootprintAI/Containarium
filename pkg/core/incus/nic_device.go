package incus

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/lxc/incus/v7/shared/api"
	"github.com/lxc/incus/v7/shared/units"
)

// zfsDeviceUpdateHeadroomBytes leaves room for Incus's metadata rewrite while
// remaining negligible beside the root-disk sizes this path manages.
const zfsDeviceUpdateHeadroomBytes int64 = 64 * 1024 * 1024

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
	restore, err := c.prepareZFSQuotaHeadroomForDeviceUpdate(containerName, inst)
	if err != nil {
		fmt.Printf("Warning: ZFS quota pre-expand before %s on %s failed (non-fatal): %v\n", what, containerName, err)
	}

	op, updateErr := c.server.UpdateInstance(containerName, inst.Writable(), etag)
	if updateErr == nil {
		updateErr = op.Wait()
		if updateErr != nil {
			updateErr = fmt.Errorf("%s on %s (operation failed): %w", what, containerName, updateErr)
		}
	} else {
		updateErr = fmt.Errorf("%s on %s: %w", what, containerName, updateErr)
	}

	if restore != nil {
		if restoreErr := restore(); restoreErr != nil {
			if updateErr != nil {
				fmt.Printf("Warning: restore ZFS quota after %s on %s failed: %v\n", what, containerName, restoreErr)
			} else {
				return fmt.Errorf("%s on %s: restore ZFS quota headroom: %w", what, containerName, restoreErr)
			}
		}
	}
	if updateErr != nil {
		return updateErr
	}
	return nil
}

// prepareZFSQuotaHeadroomForDeviceUpdate makes a temporary enlargement only
// when the live ZFS limit leaves less than zfsDeviceUpdateHeadroomBytes above
// the usage Incus accounts for. Its restore function re-reads the instance so
// a concurrent resize is never overwritten with the stale pre-update size.
func (c *Client) prepareZFSQuotaHeadroomForDeviceUpdate(containerName string, inst *api.Instance) (func() error, error) {
	pool, targetSize, ok := effectiveRootDisk(inst)
	if !ok || targetSize == "" {
		return nil, nil
	}
	if pool == "" {
		pool = c.StoragePool()
	}

	storagePool, _, err := c.server.GetStoragePool(pool)
	if err != nil {
		return nil, fmt.Errorf("get storage pool %s: %w", pool, err)
	}
	if storagePool == nil {
		return nil, fmt.Errorf("get storage pool %s: empty response", pool)
	}
	if storagePool.Driver != "zfs" {
		return nil, nil
	}

	quotaProperty, usageProperty, err := c.zfsQuotaProperties(containerName, pool, storagePool)
	if err != nil {
		return nil, err
	}
	dataset, err := c.ContainerDataset(containerName, pool)
	if err != nil {
		return nil, err
	}
	usage, err := c.getZFSByteProperty(dataset, usageProperty)
	if err != nil {
		return nil, err
	}
	liveLimit, unlimited, err := c.getZFSLimitProperty(dataset, quotaProperty)
	if err != nil {
		return nil, err
	}
	if unlimited || liveLimit-usage >= zfsDeviceUpdateHeadroomBytes {
		return nil, nil
	}

	intended, err := units.ParseByteSizeString(targetSize)
	if err != nil {
		return nil, fmt.Errorf("parse root disk size %q: %w", targetSize, err)
	}
	temporary := max(intended, usage+zfsDeviceUpdateHeadroomBytes)
	if err := c.setZFSProperty(dataset, quotaProperty, strconv.FormatInt(temporary, 10)); err != nil {
		return nil, err
	}

	return func() error {
		return c.restoreZFSQuotaHeadroom(containerName, pool, dataset, quotaProperty)
	}, nil
}

func (c *Client) restoreZFSQuotaHeadroom(containerName, pool, dataset, quotaProperty string) error {
	inst, _, err := c.server.GetInstance(containerName)
	if err != nil {
		return fmt.Errorf("re-read container for quota restore: %w", err)
	}
	currentPool, targetSize, ok := effectiveRootDisk(inst)
	if !ok || targetSize == "" {
		return nil
	}
	if currentPool == "" {
		currentPool = c.StoragePool()
	}
	// A move to another pool or a mode change is owned by the concurrent Incus
	// update; do not overwrite either setting from this older operation.
	if currentPool != pool {
		return nil
	}
	storagePool, _, err := c.server.GetStoragePool(pool)
	if err != nil {
		return fmt.Errorf("get storage pool %s for quota restore: %w", pool, err)
	}
	if storagePool == nil {
		return fmt.Errorf("get storage pool %s for quota restore: empty response", pool)
	}
	currentProperty, _, err := c.zfsQuotaProperties(containerName, pool, storagePool)
	if err != nil {
		return err
	}
	if currentProperty != quotaProperty {
		return nil
	}
	return c.setZFSProperty(dataset, quotaProperty, targetSize)
}

func effectiveRootDisk(inst *api.Instance) (pool, size string, ok bool) {
	if inst == nil {
		return "", "", false
	}
	root, ok := inst.ExpandedDevices["root"]
	if !ok {
		root = inst.Devices["root"]
	}
	if root == nil {
		return "", "", false
	}
	pool, size = root["pool"], root["size"]
	if localRoot, ok := inst.Devices["root"]; ok {
		if localRoot["pool"] != "" {
			pool = localRoot["pool"]
		}
		if localRoot["size"] != "" {
			size = localRoot["size"]
		}
	}
	return pool, size, true
}

func (c *Client) zfsQuotaProperties(containerName, pool string, storagePool *api.StoragePool) (quotaProperty, usageProperty string, err error) {
	volume, _, err := c.server.GetStoragePoolVolume(pool, "container", containerName)
	if err != nil {
		return "", "", fmt.Errorf("get instance volume %s/%s: %w", pool, containerName, err)
	}
	useRefquota := storagePool.Config["volume.zfs.use_refquota"]
	if volume != nil && volume.Config["zfs.use_refquota"] != "" {
		useRefquota = volume.Config["zfs.use_refquota"]
	}
	if useRefquota != "" {
		value, err := strconv.ParseBool(strings.TrimSpace(useRefquota))
		if err != nil {
			return "", "", fmt.Errorf("parse zfs.use_refquota %q: %w", useRefquota, err)
		}
		if value {
			return "refquota", "referenced", nil
		}
	}
	return "quota", "used", nil
}

func (c *Client) getZFSByteProperty(dataset, property string) (int64, error) {
	value, err := c.getZFSProperty(dataset, property)
	if err != nil {
		return 0, err
	}
	bytes, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse zfs %s %q on %s: %w", property, value, dataset, err)
	}
	return bytes, nil
}

func (c *Client) getZFSLimitProperty(dataset, property string) (int64, bool, error) {
	value, err := c.getZFSProperty(dataset, property)
	if err != nil {
		return 0, false, err
	}
	if value == "none" || value == "-" {
		return 0, true, nil
	}
	bytes, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse zfs %s %q on %s: %w", property, value, dataset, err)
	}
	return bytes, false, nil
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
