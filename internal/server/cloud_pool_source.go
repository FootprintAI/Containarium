package server

import (
	"context"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// cloudPoolProbeTimeout bounds each pool read so a saturated Incus cannot
// stall the status report loop (#2325).
const cloudPoolProbeTimeout = 10 * time.Second

// cloudPoolSource feeds the cloud host status probe the Incus storage pool
// capacity (#3449), via the same incus.SumStoragePools the capability profile
// uses. It connects lazily and retries after a failure, so an Incus that is
// down at daemon start only costs the statfs fallback until it answers.
type cloudPoolSource struct {
	mu     sync.Mutex
	client *incus.Client
}

func (s *cloudPoolSource) StoragePoolSpace(_ context.Context) (int64, int64, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil {
		c, err := incus.NewWithSocketAndTimeout(incus.DefaultSocketPath, cloudPoolProbeTimeout)
		if err != nil {
			return 0, 0, 0, err
		}
		s.client = c
	}
	t, err := s.client.StoragePoolTotals()
	if err != nil {
		s.client = nil // reconnect next cycle
		return 0, 0, 0, err
	}
	return t.TotalBytes, t.UsedBytes, t.Pools, nil
}
