package server

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/proofpack"
	"github.com/footprintai/containarium/internal/runlease"
	containerpkg "github.com/footprintai/containarium/pkg/core/container"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// A crew's PACK_PRODUCER (#2799) is a box, not an agent. The daemon
// provisions it with the run's checkout and no credentials, writes the crew's
// final files into that checkout once the last A2A member returns them, and
// runs the repository's test commands there with proofpack.Generate. Nothing
// in the pack comes from the coder's box or from any agent's own claim.

// packBoxOps is the part of *container.Manager producing a pack goes through.
type packBoxOps interface {
	proofpack.Execer
	Exec(container string, cmd []string) error
	WriteFile(container, path string, content []byte, mode string) error
}

var _ packBoxOps = (*containerpkg.Manager)(nil)

// crewFileArtifact is the part of a coding crew's final artifact the producer
// needs: the whole content of every changed file (cloud#1738's shape, which
// diff-reviewer and issue-implementer both emit).
type crewFileArtifact struct {
	Files []crewArtifactFile `json:"files"`
}

type crewArtifactFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// parseArtifactFiles reads the files out of a final artifact and refuses any
// path that is not inside the checkout. The whole artifact is refused, so a
// pack never tests a partial write.
func parseArtifactFiles(artifactJSON string) ([]crewArtifactFile, error) {
	var a crewFileArtifact
	if err := json.Unmarshal([]byte(artifactJSON), &a); err != nil {
		return nil, fmt.Errorf("final artifact is not a files artifact: %w", err)
	}
	for _, f := range a.Files {
		if !filepath.IsLocal(f.Path) || strings.Contains(f.Path, `\`) {
			return nil, fmt.Errorf("final artifact names path %q, which is not inside the checkout", f.Path)
		}
	}
	return a.Files, nil
}

// produceProofPack writes the artifact's files into repoDir in box, then
// generates the pack there. A path the checkout itself redirects (a symlink
// committed to the repository) is followed inside this box only, which runs
// the repository's commands as root anyway.
func produceProofPack(ctx context.Context, ops packBoxOps, box, repoDir, artifactJSON string) (*pb.ProofPack, error) {
	files, err := parseArtifactFiles(artifactJSON)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		dst := path.Join(repoDir, f.Path)
		if err := ops.Exec(box, []string{"mkdir", "-p", "--", path.Dir(dst)}); err != nil {
			return nil, fmt.Errorf("create %s in %s: %w", path.Dir(dst), box, err)
		}
		if err := ops.WriteFile(box, dst, []byte(f.Content), "0644"); err != nil {
			return nil, fmt.Errorf("write %s in %s: %w", f.Path, box, err)
		}
	}
	return proofpack.Generate(ctx, ops, box, proofpack.Options{RepoDir: repoDir})
}

// producePackIn is the production producePackFunc.
func (s *CrewServer) producePackIn(ctx context.Context, box, repoDir, artifactJSON string) (*pb.ProofPack, error) {
	if s.agents == nil || s.agents.recipes == nil || s.agents.recipes.containers == nil || s.agents.recipes.containers.manager == nil {
		return nil, fmt.Errorf("no container manager to run the test commands with")
	}
	return produceProofPack(ctx, s.agents.recipes.containers.manager, box, repoDir, artifactJSON)
}

// provisionProducerBox is the production provisionMemberFunc for a
// PACK_PRODUCER. Unlike provisionMemberBox it mints no platform or gateway
// token, seeds nothing and starts no agent runtime: the box gets the run's
// checkout and its skill's egress policy, nothing else. Its lease carries no
// credentials, and ending it removes the checkout like every member's.
func (s *CrewServer) provisionProducerBox(ctx context.Context, skill *pb.AgentSkill, req *pb.RunCrewRequest, runID string) (runlease.Lease, string, error) {
	box, _, _, err := s.agents.provisionBoxOnly(ctx, skill, req.GetBackendId(), req.GetPool())
	if err != nil {
		return runlease.Lease{}, "", err
	}
	// SeedDir is set although nothing is seeded: runlease.End refuses an
	// empty one, and would then leave the workspace behind.
	lease := runlease.Lease{RunID: runID, Box: box, SeedDir: seedDirFor(runID)}
	var commit string
	if req.GetGitSource() != "" {
		lease.Workspace = workspaceDirFor(runID)
		commit, err = s.agents.agentBox().FetchGitSource(box, containerpkg.GitSourceSpec{
			Source:        req.GetGitSource(),
			Ref:           req.GetGitRef(),
			Credential:    req.GetGitCredential(),
			WorkspacePath: lease.Workspace,
		})
		if err != nil {
			s.agents.endRunLease(ctx, lease, s.agents.boxWiper(), provisionFailedReason)
			return runlease.Lease{}, "", status.Errorf(codes.FailedPrecondition, "git fetch into pack producer box %s failed: %v", box, err)
		}
	}
	s.agents.applyAllowedPeersPolicy(ctx, "agent-"+skill.Id, skill)
	s.agents.auditRunLease(ctx, "agent.run_lease_issue", runID, runLeaseIssuePayload(lease, pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED))
	return lease, commit, nil
}

// crewProofPack produces the pack for a crew run whose A2A members returned
// artifactJSON, and summarizes it. It never fails the run: every outcome,
// including no pack at all, is reported on the summary.
func crewProofPack(ctx context.Context, produce producePackFunc, coderBox string, producer runlease.Lease, artifactJSON string) *pb.CrewProofPack {
	res := &pb.CrewProofPack{ProducerBox: producer.Box, CoderBox: coderBox}
	if producer.Box == "" || producer.Box == coderBox {
		res.Error = fmt.Sprintf("refusing to produce the pack in %q: it is the coder's box", producer.Box)
		return res
	}
	if produce == nil {
		res.Error = "this daemon has no pack producer wired"
		return res
	}
	files, err := parseArtifactFiles(artifactJSON)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	dir := producer.Workspace
	if dir == "" {
		dir = proofpack.DefaultRepoDir
	}
	pack, err := produce(ctx, producer.Box, dir, artifactJSON)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	digest, err := proofpack.PackDigest(pack)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Status, res.PackSha256, res.GitCommit = pack.GetStatus(), digest, pack.GetGitCommit()
	for _, f := range files {
		res.AppliedFiles = append(res.AppliedFiles, f.Path)
	}
	return res
}
