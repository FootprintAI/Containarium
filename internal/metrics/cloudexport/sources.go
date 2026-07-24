package cloudexport

import (
	"context"

	"github.com/footprintai/containarium/internal/metrics/platformstats"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SystemResources is the host-level snapshot the CloudExportCollector
// turns into the allowlisted host series (#1070). It is a deliberately
// small projection of the daemon's richer incus.SystemResources — only
// the fields that map to an exported gauge appear here, so the cost
// surface (custom metrics are billed per ingested sample) stays
// reviewable in one struct. A field here without a matching instrument
// in collector.go, or vice versa, is a review smell.
type SystemResources struct {
	// CPU load averages, straight from /proc/loadavg via the daemon's
	// existing GetSystemResources path.
	CPULoad1Min  float64
	CPULoad5Min  float64
	CPULoad15Min float64

	// Host memory, in bytes.
	MemoryUsedBytes  int64
	MemoryTotalBytes int64

	// Aggregate host disk (sum across storage pools), in bytes.
	DiskUsedBytes  int64
	DiskTotalBytes int64

	// Number of containers currently on this host (running + stopped).
	ContainerCount int64
}

// Sources is the seam over the daemon's existing metric-collection funcs
// (GetSystemResources for the host snapshot, GetAllMetrics for the
// per-container map) so the CloudExportCollector is unit-testable with a
// fake — no incus, no network — while production wires an adapter backed
// by the real *container.Manager.
//
// AllContainerMetrics is defined here for the per-container series that
// land in #1071; the #1070 host-series collector does not call it yet.
// It is on the interface now so the fake and the real adapter share one
// contract across both issues.
type Sources interface {
	// SystemResources returns the current host-level snapshot. The
	// collector logs and skips a tick when this errors — it never
	// panics or crashes the daemon.
	SystemResources(ctx context.Context) (*SystemResources, error)

	// AllContainerMetrics returns per-container metrics keyed by
	// container name. Used by the #1071 container-series collector; not
	// consulted by the #1070 host-series pipeline.
	AllContainerMetrics(ctx context.Context) (map[string]*pb.ContainerMetrics, error)
}

// PlatformSources is the read-side seam over platform-domain facts the
// platform metric group (#1082/#1083/#1084) observes at each export
// tick — a snapshot read with no server import, so the collector stays
// unit-testable with a fake. Extended incrementally as more platform
// series land: #1083 adds provisioning outcomes, #1084 adds peer/tunnel
// connectivity.
type PlatformSources interface {
	// APIStats returns the current cumulative API request/error counters
	// by code_class (#1082).
	APIStats() platformstats.APISnapshot

	// ProvisionStats returns the current cumulative provisioning
	// attempt/failure/duration counters by operation (#1083).
	ProvisionStats() platformstats.ProvisionSnapshot
}
