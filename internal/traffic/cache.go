package traffic

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// containerLister is the subset of *incus.Client's surface Refresh needs,
// split out so the incremental-refresh logic (#1541) is unit-testable
// without a live Incus server — same "generic loop, production function
// injected by the caller" shape as fetchAllConcurrently in pkg/core/incus.
type containerLister interface {
	GetInstanceNames() ([]string, error)
	GetContainerWithNetwork(name string) (*incus.ContainerInfo, error)
}

// ContainerCache maps IP addresses to container names
type ContainerCache struct {
	incusClient containerLister
	network     *net.IPNet

	mu       sync.RWMutex
	ipToName map[string]string
	nameToIP map[string]string
	nameToID map[string]string // container name -> cloud_container_id label ("" on non-cloud boxes)
}

// NewContainerCache creates a new container cache
func NewContainerCache(incusClient *incus.Client, networkCIDR string) *ContainerCache {
	_, network, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		log.Printf("Warning: failed to parse network CIDR %s: %v", networkCIDR, err)
	} else {
		log.Printf("Container cache network: %s (parsed from %s)", network.String(), networkCIDR)
	}
	return &ContainerCache{
		incusClient: incusClient,
		network:     network,
		ipToName:    make(map[string]string),
		nameToIP:    make(map[string]string),
		nameToID:    make(map[string]string),
	}
}

// LookupIP returns the container name for an IP address
func (c *ContainerCache) LookupIP(ip string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ipToName[ip]
}

// LookupName returns the IP for a container name
func (c *ContainerCache) LookupName(name string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nameToIP[name]
}

// LookupID returns the cloud_container_id label for a container name, or "" if
// the box is not a cloud-managed tenant (no label). Used to stamp container.id
// on egress fan-out metrics so they join to a tenant like the bytes plane.
func (c *ContainerCache) LookupID(name string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nameToID[name]
}

// IsContainerIP checks if an IP belongs to the container network
func (c *ContainerCache) IsContainerIP(ip string) bool {
	if c.network == nil {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return c.network.Contains(parsed)
}

// GetAllContainers returns a copy of all container name to IP mappings
func (c *ContainerCache) GetAllContainers() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]string, len(c.nameToIP))
	for name, ip := range c.nameToIP {
		result[name] = ip
	}
	return result
}

// Refresh updates the cache from Incus incrementally (#1541): a full
// relist-and-refetch of every container on every cycle was found live to
// be a real, unconditional contributor to Incus daemon CPU load at high
// container counts — 2 Incus API round-trips per EXISTING container, every
// cycle, regardless of whether anything actually changed. A container's IP
// essentially never changes once DHCP-assigned, so only names not already
// holding a cached IP (genuinely new, or one that hasn't gotten an IP yet)
// pay the per-container lookup; names that disappeared are dropped, and
// everything else is left untouched. Trade-off: a container that somehow
// gets reassigned a different IP without a name change (rare — e.g. a
// stop/start after DHCP lease exhaustion) goes undetected until it's
// deleted and recreated. Acceptable here — every caller of Lookup*/
// GetAllContainers uses this for traffic/egress *attribution* (metrics),
// not security or routing enforcement (see internal/traffic/collector.go,
// fanout.go) — a stale mapping briefly misattributes a metric, not a
// security decision.
func (c *ContainerCache) Refresh() error {
	names, err := c.incusClient.GetInstanceNames()
	if err != nil {
		return err
	}

	c.mu.RLock()
	currentSet := make(map[string]bool, len(names))
	toFetch := make([]string, 0)
	for _, name := range names {
		currentSet[name] = true
		if _, known := c.nameToIP[name]; !known {
			toFetch = append(toFetch, name)
		}
	}
	c.mu.RUnlock()

	fetched := make(map[string]*incus.ContainerInfo, len(toFetch))
	for _, name := range toFetch {
		info, err := c.incusClient.GetContainerWithNetwork(name)
		if err != nil {
			// Deleted between GetInstanceNames and this fetch, or a
			// transient error — skip it this cycle, same "best effort,
			// try again next tick" behavior ListContainers has always had.
			continue
		}
		fetched[name] = info
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Drop names no longer present.
	for name, ip := range c.nameToIP {
		if !currentSet[name] {
			delete(c.nameToIP, name)
			delete(c.nameToID, name)
			delete(c.ipToName, ip)
		}
	}

	// Add newly-fetched names.
	for name, info := range fetched {
		if info.IPAddress != "" {
			c.ipToName[info.IPAddress] = name
			c.nameToIP[name] = info.IPAddress
		}
		if id := info.Labels["cloud_container_id"]; id != "" {
			c.nameToID[name] = id
		}
	}

	log.Printf("Container cache refreshed: %d containers (%d fetched, %d unchanged)", len(c.nameToIP), len(toFetch), len(names)-len(toFetch))
	return nil
}

// StartRefresh begins periodic cache refresh
func (c *ContainerCache) StartRefresh(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial refresh
	if err := c.Refresh(); err != nil {
		log.Printf("Warning: initial container cache refresh failed: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Refresh(); err != nil {
				log.Printf("Warning: container cache refresh failed: %v", err)
			}
		}
	}
}

// Size returns the number of containers in the cache
func (c *ContainerCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.nameToIP)
}
