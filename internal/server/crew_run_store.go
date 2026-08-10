package server

import (
	"sync"

	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// crewRunStore is an in-memory record of crew executions, keyed by run id.
// Runs do not survive a daemon restart; a Postgres-backed store mirroring the
// network-policy store pattern is tracked in #1182.
//
// Entries are cloned on the way in and on the way out, which is what makes a
// run safe to store while it is still being driven. Handing out the same
// pointer the caller keeps mutating would let GetCrewRun observe a run
// mid-write — a proto message is several fields, and nothing makes updating
// them atomic.
type crewRunStore struct {
	mu   sync.RWMutex
	runs map[string]*pb.CrewRun
}

func newCrewRunStore() *crewRunStore {
	return &crewRunStore{runs: make(map[string]*pb.CrewRun)}
}

func (s *crewRunStore) put(r *pb.CrewRun) {
	if r == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[r.Id] = proto.Clone(r).(*pb.CrewRun)
}

func (s *crewRunStore) get(id string) (*pb.CrewRun, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.runs[id]
	if !ok {
		return nil, false
	}
	return proto.Clone(r).(*pb.CrewRun), true
}
