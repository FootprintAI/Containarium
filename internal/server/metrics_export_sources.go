package server

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/footprintai/containarium/internal/metrics/cloudexport"
	"github.com/footprintai/containarium/internal/metrics/platformstats"
	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// serverMetricsSources is the production cloudexport.Sources adapter: it
// reuses the daemon's existing collection paths (Incus GetSystemResources
// for the host snapshot, the container Manager for the count and the
// per-container map) rather than reimplementing any of it. Constructed
// when export is enabled; the Incus client it holds is a persistent
// connection reused across ticks, mirroring how the Manager holds one.
type serverMetricsSources struct {
	manager *container.Manager
	client  *incus.Client
}

// newServerMetricsSources builds the adapter, opening the one Incus
// client it reuses for host-resource reads. An Incus dial failure here
// fails enable-time, before any collector starts.
func newServerMetricsSources(manager *container.Manager) (*serverMetricsSources, error) {
	client, err := incus.New()
	if err != nil {
		return nil, fmt.Errorf("connect to Incus for metrics export: %w", err)
	}
	return &serverMetricsSources{manager: manager, client: client}, nil
}

// SystemResources returns the host snapshot projected down to exactly the
// fields the allowlisted host series need. The container count comes from
// the Manager's List (same source GetSystemInfo counts from), not a
// second Incus round trip.
func (s *serverMetricsSources) SystemResources(ctx context.Context) (*cloudexport.SystemResources, error) {
	res, err := s.client.GetSystemResources()
	if err != nil {
		return nil, fmt.Errorf("get system resources: %w", err)
	}
	containers, err := s.manager.List()
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	return &cloudexport.SystemResources{
		CPULoad1Min:      res.CPULoad1Min,
		CPULoad5Min:      res.CPULoad5Min,
		CPULoad15Min:     res.CPULoad15Min,
		MemoryUsedBytes:  res.UsedMemoryBytes,
		MemoryTotalBytes: res.TotalMemoryBytes,
		DiskUsedBytes:    res.UsedDiskBytes,
		DiskTotalBytes:   res.TotalDiskBytes,
		ContainerCount:   int64(len(containers)),
	}, nil
}

// Hostname returns this host's Incus server name — the same value
// GetSystemInfo reports as Hostname — for the exported series' hostname
// label. Empty (not an error) when server info is unavailable, so a
// transient Incus hiccup at enable time doesn't block export.
func (s *serverMetricsSources) Hostname() string {
	info, err := s.client.GetServerInfo()
	if err != nil || info == nil {
		return ""
	}
	return info.Environment.ServerName
}

// AllContainerMetrics returns per-container metrics keyed by name, for
// the #1071 container-series collector. The #1070 host pipeline does not
// call this; it is here so the real adapter satisfies the full Sources
// contract shared with #1071.
func (s *serverMetricsSources) AllContainerMetrics(ctx context.Context) (map[string]*pb.ContainerMetrics, error) {
	all, err := s.manager.GetAllMetrics()
	if err != nil {
		return nil, fmt.Errorf("get all metrics: %w", err)
	}
	out := make(map[string]*pb.ContainerMetrics, len(all))
	for _, m := range all {
		out[m.Name] = toProtoMetrics(m)
	}
	return out, nil
}

// serverPlatformSources is the production cloudexport.PlatformSources
// adapter (#1082): a thin wrapper over the daemon's platformstats.Stats,
// the same instance the gRPC unary interceptor records into (see
// DualServer's interceptor chain), plus the daemon's *PeerPool (#1084)
// for connectivity. No independent state of its own.
type serverPlatformSources struct {
	stats     *platformstats.Stats
	peers     *PeerPool
	backupMgr *backup.Manager
	// backupReadFailures counts BackupHealth reads that failed (#2305). A
	// pointer so the value-receiver copies the collector holds share one
	// counter; nil (tests, harnesses) counts nothing.
	backupReadFailures *atomic.Int64
	// liveContainers returns the names of the containers present on this
	// host (#3234). A backup-index tenant whose "<username>-container" is
	// not in the set has moved or been deleted, and BackupHealth skips it
	// so the old host stops exporting a growing-age ghost series. nil, or
	// an error, means liveness is unknown and nothing is skipped.
	liveContainers func() (map[string]struct{}, error)
}

// APIStats returns the current cumulative API counters. Nil-safe: a
// ContainerServer constructed directly (bypassing NewContainerServer,
// as some tests do) may have a nil platformStats, and this must degrade
// to an empty snapshot rather than panic — consistent with every other
// seam in this package never crashing the export tick.
func (s serverPlatformSources) APIStats() platformstats.APISnapshot {
	if s.stats == nil {
		return platformstats.APISnapshot{}
	}
	return s.stats.SnapshotAPI()
}

// ProvisionStats returns the current cumulative provisioning counters
// (#1083). Nil-safe for the same reason as APIStats.
func (s serverPlatformSources) ProvisionStats() platformstats.ProvisionSnapshot {
	if s.stats == nil {
		return platformstats.ProvisionSnapshot{}
	}
	return s.stats.SnapshotProvision()
}

// Peers returns the current peer-health snapshot (#1084). Nil-safe: a
// ContainerServer without a wired PeerPool degrades to no peers, same
// as every other seam in this package.
func (s serverPlatformSources) Peers() []cloudexport.PeerState {
	if s.peers == nil {
		return nil
	}
	return s.peers.Snapshot()
}

// BackupHealth returns the current last-success-per-tenant snapshot
// (#2294), read straight from the daemon's durable backup index — not
// cached state tied to this adapter's or the daemon process's own
// lifetime. Nil-safe for the same reason as every other seam here: a
// ContainerServer without a wired backup Manager (e.g. a test harness,
// or in principle a build with BackupService disabled) degrades to no
// tenants reporting backup health, never a panic.
//
// Tenants with no container on this host (moved or deleted, #3234) are
// omitted: absence from the series means no backup exists OR the tenant is
// not expected here.
//
// A read failure (e.g. the backup directory briefly unreadable) is
// logged and degrades to an empty snapshot rather than erroring the
// whole export tick — losing one tick of backup-health data is a far
// smaller problem than losing the host/container/platform series
// alongside it over a transient, unrelated I/O hiccup. Each failure also
// bumps BackupHealthReadFailures (#2305): a persistent one would
// otherwise be indistinguishable from "no tenant has any backup".
func (s serverPlatformSources) BackupHealth() []cloudexport.BackupHealthState {
	if s.backupMgr == nil {
		return nil
	}
	last, err := s.backupMgr.LastSuccessByUsername()
	if err != nil {
		log.Printf("[metrics-export] backup health snapshot failed, skipping this tick: %v", err)
		if s.backupReadFailures != nil {
			s.backupReadFailures.Add(1)
		}
		return nil
	}
	// A tenant is live when its container exists on this host in any
	// state (running or stopped). Backup configuration is deliberately not
	// consulted: a configured-but-broken tenant keeps its container and so
	// keeps a growing age (#2294). When the container list cannot be read
	// we fail open and skip nothing; this is not an index read failure and
	// does not touch the read-failure counter.
	var live map[string]struct{}
	if s.liveContainers != nil {
		var lerr error
		if live, lerr = s.liveContainers(); lerr != nil {
			log.Printf("[metrics-export] container list for backup liveness failed, keeping all tenants this tick: %v", lerr)
			live = nil
		}
	}
	out := make([]cloudexport.BackupHealthState, 0, len(last))
	for username, at := range last {
		if live != nil {
			if _, ok := live[username+"-container"]; !ok {
				continue
			}
		}
		out = append(out, cloudexport.BackupHealthState{Username: username, LastSuccessAt: at})
	}
	return out
}

// liveContainerNames adapts the container manager to the liveContainers
// seam: the set of container names present on this host.
func liveContainerNames(m *container.Manager) func() (map[string]struct{}, error) {
	return func() (map[string]struct{}, error) {
		cs, err := m.List()
		if err != nil {
			return nil, err
		}
		out := make(map[string]struct{}, len(cs))
		for _, c := range cs {
			out[c.Name] = struct{}{}
		}
		return out, nil
	}
}

// BackupHealthReadFailures returns the cumulative count of failed backup
// index reads (#2305). Nil-safe: an adapter built without the counter
// reports zero.
func (s serverPlatformSources) BackupHealthReadFailures() int64 {
	if s.backupReadFailures == nil {
		return 0
	}
	return s.backupReadFailures.Load()
}
