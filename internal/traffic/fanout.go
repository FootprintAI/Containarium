package traffic

import (
	"sort"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// EgressStat is one container's egress fan-out for a snapshot window — the
// crawler-detection signal (docs/EGRESS-FANOUT-DETECTION.md). DistinctDestinations
// is the number of unique destination IPs the container connected out to in the
// window; a crawler's hallmark is a large, churning fan-out where a normal app
// talks to a handful of destinations. EgressConnections is the total egress
// connection count. ContainerID is the cloud_container_id label (empty on
// non-cloud boxes), the tenant join key shared with the bytes plane.
//
// Deliberately a per-container *aggregate*: we count the fan-out, we do not turn
// each destination IP into its own series. Per-destination series would be
// unbounded cardinality and would index every site a customer's box visits —
// the raw destinations stay in the conntrack summary / store (query-time,
// access-controlled), never in metric labels.
type EgressStat struct {
	ContainerName        string
	ContainerID          string
	DistinctDestinations int
	EgressConnections    int
}

// egressConn is the minimal connection shape the fan-out aggregation needs.
type egressConn struct {
	containerName string
	destIP        string
}

// aggregateEgress folds a set of egress connections into per-container fan-out
// stats. idForName resolves a container name to its cloud_container_id ("" when
// unknown). Output is sorted by container name for stable emit ordering. Pure
// and side-effect free — the unit-tested core of the egress-fanout metric.
func aggregateEgress(conns []egressConn, idForName func(string) string) []EgressStat {
	type acc struct {
		dests map[string]struct{}
		count int
	}
	byName := make(map[string]*acc)
	for _, c := range conns {
		a := byName[c.containerName]
		if a == nil {
			a = &acc{dests: make(map[string]struct{})}
			byName[c.containerName] = a
		}
		a.count++
		if c.destIP != "" {
			a.dests[c.destIP] = struct{}{}
		}
	}

	out := make([]EgressStat, 0, len(byName))
	for name, a := range byName {
		id := ""
		if idForName != nil {
			id = idForName(name)
		}
		out = append(out, EgressStat{
			ContainerName:        name,
			ContainerID:          id,
			DistinctDestinations: len(a.dests),
			EgressConnections:    a.count,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ContainerName < out[j].ContainerName })
	return out
}

// EgressFanout returns per-container egress fan-out stats from the current
// connection snapshot — the crawler-detection signal. It refreshes the snapshot
// first (when conntrack is available) so the counts reflect live state, then
// aggregates only EGRESS-direction connections. Returns nil when conntrack
// monitoring is unavailable (e.g. macOS).
func (c *Collector) EgressFanout() []EgressStat {
	if c.monitor == nil {
		return nil
	}
	c.takeSnapshot()

	c.mu.RLock()
	conns := make([]egressConn, 0, len(c.connections))
	for _, conn := range c.connections {
		if conn.Direction == pb.TrafficDirection_TRAFFIC_DIRECTION_EGRESS {
			conns = append(conns, egressConn{containerName: conn.ContainerName, destIP: conn.DestIp})
		}
	}
	c.mu.RUnlock()

	return aggregateEgress(conns, c.cache.LookupID)
}
