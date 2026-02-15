package traffic

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/incus"
)

// ContainerCache maps IP addresses to container names
type ContainerCache struct {
	incusClient *incus.Client
	network     *net.IPNet

	mu       sync.RWMutex
	ipToName map[string]string
	nameToIP map[string]string
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

// Refresh updates the cache from Incus
func (c *ContainerCache) Refresh() error {
	containers, err := c.incusClient.ListContainers()
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear and rebuild
	c.ipToName = make(map[string]string)
	c.nameToIP = make(map[string]string)

	for _, container := range containers {
		if container.IPAddress != "" {
			c.ipToName[container.IPAddress] = container.Name
			c.nameToIP[container.Name] = container.IPAddress
		}
	}

	log.Printf("Container cache refreshed: %d containers", len(c.ipToName))
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
