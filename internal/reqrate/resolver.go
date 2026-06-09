package reqrate

import (
	"sort"
	"strings"
)

// Container identifies a tenant container for request-rate attribution. The
// collector builds these from its existing container list — Name + primary IP
// the edge dials, plus the cloud_container_id label (empty on non-cloud boxes).
type Container struct {
	Name        string // incus container name
	IP          string // primary IPv4 the edge reverse-proxies to
	ContainerID string // cloud_container_id label; "" on standalone boxes
}

// Route maps an edge hostname to the upstream IP it proxies to — the subset of
// ProxyManager.ListRoutes the resolver needs.
type Route struct {
	Host       string
	UpstreamIP string
}

// Resolver maps a request host to the container serving it, by joining routes
// (host→upstream IP) with the container list (IP→container). Built once per
// collection tick from data the collector already has; cheap and immutable
// after construction.
type Resolver struct {
	byHost map[string]Container
}

// NewResolver joins routes and containers into a host→container map. A route
// whose upstream IP matches no container is dropped (the container may have
// gone away); a container with no IP can't be reverse-proxied so it's skipped.
func NewResolver(routes []Route, containers []Container) *Resolver {
	byIP := make(map[string]Container, len(containers))
	for _, c := range containers {
		if c.IP != "" {
			byIP[c.IP] = c
		}
	}
	byHost := make(map[string]Container, len(routes))
	for _, r := range routes {
		if c, ok := byIP[r.UpstreamIP]; ok {
			byHost[strings.ToLower(r.Host)] = c
		}
	}
	return &Resolver{byHost: byHost}
}

// Resolve returns the container serving host, or ok=false when the host maps to
// no known container — a stale route, a core service, or an L4/passthrough host
// that produced no reverse-proxy route (those have no request-rate series).
func (r *Resolver) Resolve(host string) (Container, bool) {
	c, ok := r.byHost[strings.ToLower(host)]
	return c, ok
}

// Sample is one container's request rate for a tick, ready to record as the
// container.request_rate gauge.
type Sample struct {
	ContainerName  string
	ContainerID    string
	RequestsPerSec float64
}

// Build joins a host→rate snapshot with a resolver into per-container samples.
// Several hostnames can front the same container (e.g. the default subdomain
// plus a custom-domain alias), so their rates are summed. Hosts that resolve to
// no container are dropped and tallied in dropped (surfaced by the caller for
// observability). Output is sorted by container name for stable emit ordering.
func Build(rates map[string]float64, res *Resolver) (samples []Sample, dropped int) {
	byKey := make(map[string]*Sample)
	for host, rate := range rates {
		c, ok := res.Resolve(host)
		if !ok {
			dropped++
			continue
		}
		// Key on the cloud container id when present, else the container name,
		// so two hostnames for the same container coalesce.
		key := c.ContainerID
		if key == "" {
			key = "name:" + c.Name
		}
		s := byKey[key]
		if s == nil {
			s = &Sample{ContainerName: c.Name, ContainerID: c.ContainerID}
			byKey[key] = s
		}
		s.RequestsPerSec += rate
	}
	samples = make([]Sample, 0, len(byKey))
	for _, s := range byKey {
		samples = append(samples, *s)
	}
	sort.Slice(samples, func(i, j int) bool {
		return samples[i].ContainerName < samples[j].ContainerName
	})
	return samples, dropped
}
