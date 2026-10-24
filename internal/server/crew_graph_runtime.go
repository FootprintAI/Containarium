package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/runlease"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type graphPeer struct {
	skill    *pb.AgentSkill
	instance string
}
type graphPeerSet map[string]graphPeer

// graphInstanceID reserves tg- for short, run-scoped box identities.
func graphInstanceID(runID, skillID string) string {
	h := sha256.Sum256([]byte(runID + ":" + skillID))
	return fmt.Sprintf("tg-%x", h[:12])
}

// graphPeerTarget resolves logical peer ids inside a child run, enforcing
// the original manifest's allowed_peers even for generated box identities.
func (s *AgentSkillServer) graphPeerTarget(runID, caller, target string) (string, bool, error) {
	value, ok := s.graphPeers.Load(runID)
	if !ok {
		if strings.HasPrefix(caller, "tg-") {
			return "", true, status.Error(codes.PermissionDenied, "graph node run is no longer active")
		}
		return target, false, nil
	}
	peers := value.(graphPeerSet)
	to, ok := peers[target]
	if !ok {
		return "", true, status.Error(codes.PermissionDenied, "peer is outside this graph node's crew")
	}
	if caller != "" {
		var from *pb.AgentSkill
		for _, peer := range peers {
			if caller == peer.instance {
				from = peer.skill
				break
			}
		}
		if from == nil || !peersContain(from.AllowedPeers, target) {
			return "", true, status.Error(codes.PermissionDenied, "graph peer is not in allowed_peers")
		}
	}
	return to.instance, true, nil
}

// executeGraphNode gives every skill/member a fresh physical box while
// retaining catalog ids in journals and logical A2A requests.
func (s *CrewServer) executeGraphNode(ctx context.Context, node *pb.TaskNode, runID, input string, parent *pb.RunCrewRequest) (output string, err error) {
	if s.agents == nil || s.agents.recipes == nil || s.agents.recipes.containers == nil || s.agents.recipes.containers.manager == nil {
		return "", status.Error(codes.FailedPrecondition, "agent runtime is unavailable")
	}
	ids := []string{node.GetSkillId()}
	var crew *pb.Crew
	if node.GetCrewId() != "" {
		crew, err = s.catalog.Get(node.GetCrewId())
		if err != nil {
			return "", err
		}
		ids = crew.SkillIds
	}
	peers := make(graphPeerSet, len(ids))
	for _, id := range ids {
		skill, lookupErr := s.skills.Get(id)
		if lookupErr != nil {
			return "", lookupErr
		}
		peers[id] = graphPeer{skill: skill, instance: graphInstanceID(runID, id)}
	}
	s.agents.graphPeers.Store(runID, peers)
	defer s.agents.graphPeers.Delete(runID)
	if crew == nil {
		defer func() {
			record := &pb.CrewRun{Id: runID, SkillId: ids[0], Owner: s.owner, InputJson: input,
				State: pb.CrewRunState_CREW_RUN_STATE_COMPLETED, ArtifactJson: output,
				GitSource: parent.GitSource, GitRef: parent.GitRef}
			if err != nil {
				record.State, record.Error, record.ArtifactJson = pb.CrewRunState_CREW_RUN_STATE_FAILED, err.Error(), ""
			}
			wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			if saveErr := s.runs.Put(wctx, record); saveErr != nil {
				err = errors.Join(err, fmt.Errorf("record node run: %w", saveErr))
			}
		}()
	}
	// Delete only freshly allocated node identities, never catalog boxes.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		for _, id := range ids {
			_, deleteErr := s.agents.recipes.containers.DeleteContainer(cleanupCtx,
				&pb.DeleteContainerRequest{Username: "agent-" + peers[id].instance, Force: true})
			if deleteErr != nil && status.Code(deleteErr) != codes.NotFound {
				err = errors.Join(err, fmt.Errorf("delete node box: %w", deleteErr))
			}
		}
	}()
	if crew == nil {
		task := &pb.RunAgentSkillRequest{SkillId: ids[0], RunId: runID, InputJson: input,
			BackendId: parent.BackendId, Pool: parent.Pool, GitSource: parent.GitSource,
			GitRef: parent.GitRef, GitCredential: parent.GitCredential, Engine: parent.EngineOverrides[ids[0]]}
		run, err := s.agents.beginSkillRunWith(ctx, task, provisionOptions{instanceID: peers[ids[0]].instance})
		if err != nil {
			return "", err
		}
		defer s.agents.endRunLease(ctx, run.lease, s.agents.boxWiper(), runExitReason)
		return s.agents.runInBoxAgentResult(run.containerName, run.lease.SeedDir, runID, run.skillID, run.engineRes, run.model)
	}
	req := proto.Clone(parent).(*pb.RunCrewRequest)
	req.Graph, req.Concurrency = nil, 0
	req.CrewId, req.RunId, req.InputJson = crew.Id, runID, input
	deps := crewRunDeps{send: func(ctx context.Context, task *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
		// Only the daemon's topology driver translates logical senders. An
		// authenticated box must already carry this node's physical identity.
		copy := proto.Clone(task).(*pb.SendAgentTaskRequest)
		if peer, ok := peers[copy.FromSkillId]; ok {
			copy.FromSkillId = peer.instance
		}
		return s.agents.SendAgentTask(ctx, copy)
	}, wiper: s.agents.boxWiper(),
		provision: func(ctx context.Context, skill *pb.AgentSkill, req *pb.RunCrewRequest, runID string) (runlease.Lease, string, error) {
			instance := proto.Clone(skill).(*pb.AgentSkill)
			instance.Id = peers[skill.Id].instance
			instance.AllowedPeers = nil
			for _, id := range skill.AllowedPeers {
				if peer, ok := peers[id]; ok {
					instance.AllowedPeers = append(instance.AllowedPeers, peer.instance)
				}
			}
			name, _, lease, commit, _, engine, err := s.agents.provisionSkillBoxWith(ctx, instance,
				req.BackendId, req.Pool, "", runID, req.GitSource, req.GitRef, req.GitCredential, "",
				provisionOptions{engineOverride: req.EngineOverrides[skill.Id]})
			if err != nil {
				return runlease.Lease{}, "", err
			}
			command := s.agents.serveModeCommandFor(lease.SeedDir, skill.Id, instance.Id, engine, skill.Model)
			if _, _, err := s.agents.recipes.containers.manager.ExecWithOutput(name, []string{"bash", "-lc", command}); err != nil {
				s.agents.endRunLease(ctx, lease, s.agents.boxWiper(), provisionFailedReason)
				return runlease.Lease{}, "", err
			}
			return lease, commit, nil
		}}
	resp, err := s.runCrew(ctx, req, crew, runID, deps)
	if err != nil {
		return "", err
	}
	if resp.Run.State != pb.CrewRunState_CREW_RUN_STATE_COMPLETED {
		return "", fmt.Errorf("crew node failed: %s", resp.Run.Error)
	}
	return resp.Run.ArtifactJson, nil
}
