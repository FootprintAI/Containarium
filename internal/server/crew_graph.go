package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/taskgraph"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const defaultGraphConcurrency = 5

type graphNodeRunner func(context.Context, *pb.TaskNode, string, string, *pb.RunCrewRequest) (string, error)

type graphDependency struct {
	NodeID     string `json:"node_id"`
	OutputJSON string `json:"output_json"`
}

type graphNodeInput struct {
	Goal         string            `json:"goal"`
	InputJSON    string            `json:"input_json"`
	Dependencies []graphDependency `json:"dependencies"`
}

// validateExecutableGraph adds dispatch policy to the generic #2803 validator.
// Both planning and execution apply it: model prompts are not enforcement.
func (s *CrewServer) validateExecutableGraph(g *pb.TaskGraph) (*taskgraph.Result, error) {
	res, err := taskgraph.Validate(g, s.skills, s.catalog)
	if err != nil {
		return nil, err
	}
	for _, node := range g.Nodes {
		if node.GetSkillId() == plannerSkillID {
			return nil, fmt.Errorf("node %q assigns the planner to itself", node.Id)
		}
		if node.GetCrewId() != "" {
			crew, _ := s.catalog.Get(node.GetCrewId())
			for _, id := range crew.SkillIds {
				if id == plannerSkillID {
					return nil, fmt.Errorf("node %q crew contains the planner", node.Id)
				}
			}
			if err := validateCrewTopology(crew, s.skillByID); err != nil {
				return nil, fmt.Errorf("node %q: %w", node.Id, err)
			}
		}
	}
	return res, nil
}

// runCrewGraph validates the entire graph before allocating any boxes. Only
// this goroutine mutates results; workers return values through events.
func (s *CrewServer) runCrewGraph(ctx context.Context, req *pb.RunCrewRequest, crew *pb.Crew, runID string, execute graphNodeRunner) (*pb.RunCrewResponse, error) {
	for _, scope := range []string{auth.ScopeAgentsRun, auth.ScopeAgentsCall, auth.ScopeContainersWrite} {
		if err := auth.RequireScope(ctx, scope); err != nil {
			return nil, err
		}
	}
	if crew.Topology != pb.CrewTopology_CREW_TOPOLOGY_ORCHESTRATOR && crew.Topology != pb.CrewTopology_CREW_TOPOLOGY_FREEFORM {
		return nil, status.Error(codes.InvalidArgument, "only ORCHESTRATOR/FREEFORM accept a task graph")
	}
	validated, err := s.validateExecutableGraph(req.Graph)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "task graph: %v", err)
	}
	limit := int(req.Concurrency)
	if limit == 0 {
		limit = defaultGraphConcurrency
	}
	if limit > taskgraph.MaxNodes {
		return nil, status.Errorf(codes.InvalidArgument, "concurrency must not exceed %d", taskgraph.MaxNodes)
	}
	for _, node := range req.Graph.Nodes {
		if _, err := s.validateLocalNodeResources(node, req); err != nil {
			return nil, err
		}
	}
	run := &pb.CrewRun{Id: runID, CrewId: crew.Id, TraceId: genTraceID(), Owner: s.owner,
		State: pb.CrewRunState_CREW_RUN_STATE_RUNNING, Graph: req.Graph,
		GitSource: req.GitSource, GitRef: req.GitRef}
	nodes := make(map[string]*pb.TaskNode, len(req.Graph.Nodes))
	results := make(map[string]*pb.TaskNodeResult, len(req.Graph.Nodes))
	deps := make(map[string][]string)
	for _, node := range req.Graph.Nodes {
		nodes[node.Id] = node
	}
	for _, id := range validated.Order {
		childID, err := resolveRunID("")
		if err != nil {
			return nil, err
		}
		r := &pb.TaskNodeResult{NodeId: id, RunId: childID, State: pb.TaskNodeState_TASK_NODE_STATE_PENDING}
		results[id] = r
		run.NodeResults = append(run.NodeResults, r)
	}
	for _, edge := range req.Graph.Edges {
		deps[edge.NodeId] = append(deps[edge.NodeId], edge.DependsOn)
	}
	persist := func() error {
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return s.runs.Put(wctx, run)
	}
	if err := persist(); err != nil {
		return nil, status.Errorf(codes.Internal, "record graph run: %v", err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type event struct {
		id, output string
		err        error
	}
	events := make(chan event, len(nodes))
	active, finished := 0, 0
	var saveErr error
	for finished < len(nodes) {
		for _, r := range run.NodeResults {
			if r.State != pb.TaskNodeState_TASK_NODE_STATE_PENDING {
				continue
			}
			if workerCtx.Err() != nil {
				r.State, r.Error = pb.TaskNodeState_TASK_NODE_STATE_CANCELLED, workerCtx.Err().Error()
				r.FinishedAt = timestamppb.Now()
				finished++
				continue
			}
			ready := true
			var inputs []graphDependency
			for _, id := range deps[r.NodeId] {
				d := results[id]
				switch d.State {
				case pb.TaskNodeState_TASK_NODE_STATE_FAILED, pb.TaskNodeState_TASK_NODE_STATE_BLOCKED, pb.TaskNodeState_TASK_NODE_STATE_CANCELLED:
					r.State, r.Error = pb.TaskNodeState_TASK_NODE_STATE_BLOCKED, "blocked by dependency "+id
					r.FinishedAt = timestamppb.Now()
				case pb.TaskNodeState_TASK_NODE_STATE_SUCCEEDED:
					inputs = append(inputs, graphDependency{NodeID: id, OutputJSON: d.OutputJson})
				default:
					ready = false
				}
			}
			if r.State == pb.TaskNodeState_TASK_NODE_STATE_BLOCKED {
				finished++
				continue
			}
			if !ready || active == limit {
				continue
			}
			// This payload contains only strings/slices, so marshaling cannot fail.
			input, err := json.Marshal(graphNodeInput{Goal: nodes[r.NodeId].Goal, InputJSON: nodes[r.NodeId].InputJson, Dependencies: inputs})
			if err != nil {
				return nil, status.Errorf(codes.Internal, "encode node input: %v", err)
			}
			r.State, r.StartedAt = pb.TaskNodeState_TASK_NODE_STATE_RUNNING, timestamppb.Now()
			active++
			go func(id, childID, input string) {
				e := event{id: id}
				defer func() {
					if recover() != nil {
						e.err = fmt.Errorf("node executor panicked")
					}
					events <- e
				}()
				// Recheck after dependencies finish: a profile may have been
				// refreshed since preflight. Never let pool fallback place a
				// locally validated node on an unvalidated peer.
				backend, err := s.validateLocalNodeResources(nodes[id], req)
				if err != nil {
					e.err = err
					return
				}
				nodeReq := req
				if backend != "" {
					nodeReq = proto.Clone(req).(*pb.RunCrewRequest)
					nodeReq.BackendId, nodeReq.Pool = backend, ""
				}
				e.output, e.err = execute(workerCtx, nodes[id], childID, input, nodeReq)
			}(r.NodeId, r.RunId, string(input))
		}
		if err := persist(); err != nil && saveErr == nil {
			saveErr = err
			cancel() // stop new dispatch, then drain workers so leases still end
		}
		if active == 0 {
			continue
		}
		e := <-events
		r := results[e.id]
		r.FinishedAt = timestamppb.Now()
		if e.err != nil {
			r.State, r.Error = pb.TaskNodeState_TASK_NODE_STATE_FAILED, e.err.Error()
		} else {
			r.State, r.OutputJson = pb.TaskNodeState_TASK_NODE_STATE_SUCCEEDED, e.output
		}
		active--
		finished++
	}
	run.State = pb.CrewRunState_CREW_RUN_STATE_COMPLETED
	for _, r := range run.NodeResults {
		if r.State != pb.TaskNodeState_TASK_NODE_STATE_SUCCEEDED {
			run.State = pb.CrewRunState_CREW_RUN_STATE_FAILED
			run.Error = "one or more task nodes did not succeed; see node_results"
		}
	}
	if ctx.Err() != nil {
		run.State = pb.CrewRunState_CREW_RUN_STATE_CANCELLED
	}
	if err := persist(); err != nil {
		return nil, status.Errorf(codes.Internal, "record graph result: %v", err)
	}
	if saveErr != nil {
		return nil, status.Errorf(codes.Internal, "record graph progress: %v", saveErr)
	}
	return &pb.RunCrewResponse{Run: run}, nil
}
