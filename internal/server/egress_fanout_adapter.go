package server

import (
	metricsPackage "github.com/footprintai/containarium/internal/metrics"
	"github.com/footprintai/containarium/internal/traffic"
)

// EgressFanoutFetcherAdapter adapts the conntrack traffic collector to the
// metrics.EgressFanoutFetcher interface, bridging traffic.EgressStat to the
// metrics-boundary type so neither package imports the other. Supplies the
// egress fan-out crawler-detection signal to the OTel metrics collector.
type EgressFanoutFetcherAdapter struct {
	Collector *traffic.Collector
}

// EgressFanout returns per-container egress fan-out stats, or nil when conntrack
// monitoring is unavailable.
func (a *EgressFanoutFetcherAdapter) EgressFanout() []metricsPackage.EgressFanoutStat {
	if a.Collector == nil {
		return nil
	}
	stats := a.Collector.EgressFanout()
	out := make([]metricsPackage.EgressFanoutStat, len(stats))
	for i, s := range stats {
		out[i] = metricsPackage.EgressFanoutStat{
			ContainerName:        s.ContainerName,
			ContainerID:          s.ContainerID,
			DistinctDestinations: s.DistinctDestinations,
			EgressConnections:    s.EgressConnections,
		}
	}
	return out
}
