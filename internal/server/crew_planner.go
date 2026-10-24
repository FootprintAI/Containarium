package server

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/taskgraph"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

const plannerSkillID = "task-planner"

type plannerAssignee struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

type plannerInput struct {
	Goal     string            `json:"goal"`
	Skills   []plannerAssignee `json:"skills"`
	Crews    []plannerAssignee `json:"crews"`
	MaxNodes int               `json:"max_nodes"`
	MaxDepth int               `json:"max_depth"`
}

// PlanTaskGraph reuses skill provisioning and lease cleanup. The injected
// runner in planTaskGraph lets tests exercise validation without a real box.
func (s *CrewServer) PlanTaskGraph(ctx context.Context, req *pb.PlanTaskGraphRequest) (*pb.PlanTaskGraphResponse, error) {
	return s.planTaskGraph(ctx, req, s.runPlannerSkill)
}

func (s *CrewServer) runPlannerSkill(ctx context.Context, req *pb.RunAgentSkillRequest) (*pb.RunAgentSkillResponse, error) {
	if s.agents == nil {
		return nil, status.Error(codes.FailedPrecondition, "agent runtime is unavailable")
	}
	run, err := s.agents.beginSkillRun(ctx, req)
	if err != nil {
		return nil, err
	}
	defer s.agents.endRunLease(ctx, run.lease, s.agents.boxWiper(), runExitReason)
	// Unlike RunAgentSkill's compatibility fallback, planning must fail if
	// the runtime or artifact is unavailable.
	out, err := s.agents.runInBoxAgentResult(run.containerName, run.lease.SeedDir, run.runID, run.skillID, run.engineRes, run.model)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "planner runtime: %v", err)
	}
	return &pb.RunAgentSkillResponse{ArtifactJson: out, RunId: run.runID, GitCommit: run.gitCommit}, nil
}

func (s *CrewServer) planTaskGraph(ctx context.Context, req *pb.PlanTaskGraphRequest, run func(context.Context, *pb.RunAgentSkillRequest) (*pb.RunAgentSkillResponse, error)) (*pb.PlanTaskGraphResponse, error) {
	for _, scope := range []string{auth.ScopeCrewsRead, auth.ScopeAgentsRun, auth.ScopeContainersWrite} {
		if err := auth.RequireScope(ctx, scope); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(req.GetGoal()) == "" || strings.TrimSpace(req.GetRepo()) == "" {
		return nil, status.Error(codes.InvalidArgument, "goal and repo are required")
	}
	in := plannerInput{Goal: req.Goal, MaxNodes: taskgraph.MaxNodes, MaxDepth: taskgraph.MaxDepth}
	for _, sk := range s.skills.List() {
		if sk.Id != plannerSkillID {
			in.Skills = append(in.Skills, plannerAssignee{ID: sk.Id, Description: sk.Description})
		}
	}
	for _, crew := range s.catalog.List() {
		in.Crews = append(in.Crews, plannerAssignee{ID: crew.Id, Description: crew.Description})
	}
	input, err := json.Marshal(in)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode planner input: %v", err)
	}
	runID, err := resolveRunID("")
	if err != nil {
		return nil, err
	}
	record := &pb.CrewRun{Id: runID, SkillId: plannerSkillID, Owner: s.owner,
		State: pb.CrewRunState_CREW_RUN_STATE_RUNNING, InputJson: string(input),
		GitSource: req.Repo, GitRef: req.GitRef}
	if err := s.runs.Put(ctx, record); err != nil {
		return nil, status.Errorf(codes.Internal, "record planner run: %v", err)
	}
	out, runErr := run(ctx, &pb.RunAgentSkillRequest{SkillId: plannerSkillID, RunId: runID,
		InputJson: string(input), GitSource: req.Repo, GitRef: req.GitRef,
		GitCredential: req.GitCredential, BackendId: req.BackendId, Pool: req.Pool})
	graph := &pb.TaskGraph{}
	if runErr == nil {
		record.GitCommit = out.GetGitCommit()
		if err := protojson.Unmarshal([]byte(out.GetArtifactJson()), graph); err != nil {
			runErr = status.Errorf(codes.FailedPrecondition, "invalid planner output: %v", err)
		} else if graph.Goal != req.Goal {
			runErr = status.Error(codes.FailedPrecondition, "planner graph goal differs from requested goal")
		} else if _, err := s.validateExecutableGraph(graph); err != nil {
			runErr = status.Errorf(codes.FailedPrecondition, "invalid planner graph: %v", err)
		}
	}
	if runErr == nil {
		encoded, err := protojson.Marshal(graph)
		if err != nil {
			runErr = status.Errorf(codes.Internal, "encode planner graph: %v", err)
		} else {
			record.State, record.ArtifactJson = pb.CrewRunState_CREW_RUN_STATE_COMPLETED, string(encoded)
		}
	}
	if runErr != nil {
		record.State, record.Error = pb.CrewRunState_CREW_RUN_STATE_FAILED, runErr.Error()
	}
	// Preserve the failure reason even when the caller cancels its request.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.runs.Put(wctx, record); err != nil {
		return nil, status.Errorf(codes.Internal, "record planner run %s: %v", runID, err)
	}
	if runErr != nil {
		return nil, status.Errorf(status.Code(runErr), "planner run %s: %v", runID, runErr)
	}
	return &pb.PlanTaskGraphResponse{Graph: graph, RunId: runID, GitCommit: record.GitCommit}, nil
}
