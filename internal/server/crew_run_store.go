package server

import (
	"sync"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// crewRunStore is an in-memory record of crew executions, keyed by run id.
// Phase 3 keeps runs in memory (they don't survive a daemon restart); a
// Postgres-backed store mirrors the network-policy store pattern when run
// durability is needed.
type crewRunStore struct {
	mu   sync.RWMutex
	runs map[string]*pb.CrewRun
}

func newCrewRunStore() *crewRunStore {
	return &crewRunStore{runs: make(map[string]*pb.CrewRun)}
}

func (s *crewRunStore) put(r *pb.CrewRun) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[r.Id] = r
}

func (s *crewRunStore) get(id string) (*pb.CrewRun, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.runs[id]
	return r, ok
}
