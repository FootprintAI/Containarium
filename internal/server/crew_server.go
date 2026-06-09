package server

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/crews"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// CrewServer implements the gRPC CrewService (Phase 3). A crew is a
// collaborating set of skills bound to a task purpose. RunCrew validates the
// crew's topology against the union of members' allowed_peers (rejecting any
// edge the Phase 2 trust fabric would drop), provisions each member's box by
// reusing the AgentSkillService, and threads one trace_id through the run.
//
// Phase 3 seam: the actual inter-agent choreography and artifact aggregation
// are the in-box agent loop's job (the agent-runtime image, not yet wired), so
// a run lands in RUNNING once the boxes are up + network-gated, not COMPLETED.
type CrewServer struct {
	pb.UnimplementedCrewServiceServer
	catalog *crews.Manager
	skills  *skills.Manager
	agents  *AgentSkillServer // reuse RunAgentSkill: provision + scoped token + per-box net policy
	runs    *crewRunStore
}

// NewCrewServer wires the crew service to the agent-skill server (for box
// provisioning) and the embedded crew + skill catalogs.
func NewCrewServer(agents *AgentSkillServer) *CrewServer {
	return &CrewServer{
		catalog: crews.GetDefault(),
		skills:  skills.GetDefault(),
		agents:  agents,
		runs:    newCrewRunStore(),
	}
}

// ListCrews returns all built-in crews.
func (s *CrewServer) ListCrews(ctx context.Context, _ *pb.ListCrewsRequest) (*pb.ListCrewsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeCrewsRead); err != nil {
		return nil, err
	}
	return &pb.ListCrewsResponse{Crews: s.catalog.List()}, nil
}

// GetCrew returns a single crew by ID.
func (s *CrewServer) GetCrew(ctx context.Context, req *pb.GetCrewRequest) (*pb.GetCrewResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeCrewsRead); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	crew, err := s.catalog.Get(req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return &pb.GetCrewResponse{Crew: crew}, nil
}

// RunCrew validates a crew's topology, provisions each member's box under one
// trace_id, and records the run. Gated on crews:run; box provisioning reuses
// RunAgentSkill, so the caller also needs agents:run + containers:write.
func (s *CrewServer) RunCrew(ctx context.Context, req *pb.RunCrewRequest) (*pb.RunCrewResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeCrewsRun); err != nil {
		return nil, err
	}
	if req.CrewId == "" {
		return nil, status.Error(codes.InvalidArgument, "crew_id is required")
	}
	crew, err := s.catalog.Get(req.CrewId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	// Keystone: a crew's wiring may not ask for an A2A hop the trust fabric
	// would drop. Reject before provisioning anything.
	if err := validateCrewTopology(crew, s.skillByID); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	trace := genTraceID()
	run := &pb.CrewRun{
		Id:        "crewrun-" + trace,
		CrewId:    crew.Id,
		TraceId:   trace,
		State:     pb.CrewRunState_CREW_RUN_STATE_RUNNING,
		InputJson: req.InputJson,
	}

	// Provision each member box (reuses RunAgentSkill: scoped token + per-box
	// allowed_peers network policy). The in-box loop drives the actual
	// collaboration; the run stays RUNNING until that lands (Phase 3 seam).
	for _, sid := range crew.SkillIds {
		_, err := s.agents.RunAgentSkill(ctx, &pb.RunAgentSkillRequest{
			SkillId:   sid,
			BackendId: req.BackendId,
			Pool:      req.Pool,
		})
		if err != nil {
			run.State = pb.CrewRunState_CREW_RUN_STATE_FAILED
			run.Error = fmt.Sprintf("provision skill %q: %v", sid, err)
			s.runs.put(run)
			return nil, status.Errorf(codes.Internal, "crew %q: %s", crew.Id, run.Error)
		}
	}

	s.runs.put(run)
	return &pb.RunCrewResponse{Run: run}, nil
}

// GetCrewRun returns the status and artifact of a crew run.
func (s *CrewServer) GetCrewRun(ctx context.Context, req *pb.GetCrewRunRequest) (*pb.GetCrewRunResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeCrewsRead); err != nil {
		return nil, err
	}
	run, ok := s.runs.get(req.Id)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "crew run %q not found", req.Id)
	}
	return &pb.GetCrewRunResponse{Run: run}, nil
}

// skillByID adapts the skill catalog to the lookup validateCrewTopology needs.
func (s *CrewServer) skillByID(id string) (*pb.AgentSkill, bool) {
	sk, err := s.skills.Get(id)
	if err != nil {
		return nil, false
	}
	return sk, true
}

// validateCrewTopology checks that every A2A edge the topology implies is
// permitted by the members' allowed_peers — so a crew can never ask for a hop
// the Phase 2 network policy would drop. Pure (skill lookup injected) and
// unit-testable without a daemon.
func validateCrewTopology(crew *pb.Crew, getSkill func(id string) (*pb.AgentSkill, bool)) error {
	for _, sid := range crew.SkillIds {
		if _, ok := getSkill(sid); !ok {
			return fmt.Errorf("crew %q references unknown skill %q", crew.Id, sid)
		}
	}
	for _, edge := range crewRequiredEdges(crew) {
		from, _ := getSkill(edge[0])
		if !peersContain(from.AllowedPeers, edge[1]) {
			return fmt.Errorf(
				"crew %q topology requires edge %s->%s, but %s.allowed_peers does not permit it (the trust fabric would drop the hop)",
				crew.Id, edge[0], edge[1], edge[0])
		}
	}
	return nil
}

// crewRequiredEdges returns the directed A2A edges a topology implies.
func crewRequiredEdges(crew *pb.Crew) [][2]string {
	ids := crew.SkillIds
	var edges [][2]string
	switch crew.Topology {
	case pb.CrewTopology_CREW_TOPOLOGY_PIPELINE:
		for i := 0; i+1 < len(ids); i++ {
			edges = append(edges, [2]string{ids[i], ids[i+1]})
		}
	case pb.CrewTopology_CREW_TOPOLOGY_ORCHESTRATOR:
		for i := 1; i < len(ids); i++ {
			edges = append(edges, [2]string{ids[0], ids[i]})
		}
	case pb.CrewTopology_CREW_TOPOLOGY_FREEFORM:
		// No required edges: members coordinate freely within whatever their
		// allowed_peers permit; the crew just bounds the set + the trace.
	}
	return edges
}

func peersContain(peers []string, id string) bool {
	for _, p := range peers {
		if p == id {
			return true
		}
	}
	return false
}
