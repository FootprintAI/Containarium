package server

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/runlease"
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
	runs    CrewRunStore
	// owner identifies this daemon on the runs it drives, so startup
	// reconciliation can tell its own stranded runs from a peer's live ones
	// (#1322). Empty on a daemon with no backend id configured, which reads
	// as unowned — the single-daemon case, where that is correct.
	owner string
}

// SetOwner records which daemon this server drives runs as.
func (s *CrewServer) SetOwner(id string) { s.owner = id }

// NewCrewServer wires the crew service to the agent-skill server (for box
// provisioning) and the embedded crew + skill catalogs.
func NewCrewServer(agents *AgentSkillServer) *CrewServer {
	s := &CrewServer{
		catalog: crews.GetDefault(),
		skills:  skills.GetDefault(),
		agents:  agents,
		runs:    NewMemCrewRunStore(),
	}
	// TailRunLog (#2096) resolves a crew run's members from its run record.
	// #2122 reuses the same store + hook for a standalone skill run: recordSkillRun
	// writes it, runMembers below resolves it, reapSkillRun sweeps it.
	if agents != nil {
		agents.crewRunMembers = s.runMembers
		agents.recordSkillRun = s.recordSkillRun
		agents.reapSkillRun = s.reapSkillRunRecord
	}
	return s
}

// runMembers resolves a run id to its member skill ids, entry first. Two
// shapes share this store (#2122): a crew run (crew_id set) resolves its
// members from the crew catalog, exactly as before; a standalone skill run
// (crew_id empty, skill_id set — recordSkillRun's record) has no crew to
// look up and IS its own single-member list.
func (s *CrewServer) runMembers(ctx context.Context, runID string) ([]string, bool, error) {
	run, ok, err := s.runs.Get(ctx, runID)
	if err != nil || !ok {
		return nil, false, err
	}
	if run.GetCrewId() == "" {
		if run.GetSkillId() == "" {
			return nil, false, nil
		}
		return []string{run.GetSkillId()}, true, nil
	}
	crew, err := s.catalog.Get(run.GetCrewId())
	if err != nil {
		return nil, false, nil
	}
	return append([]string(nil), crew.GetSkillIds()...), true, nil
}

// recordSkillRun persists a standalone skill run's durable run->skill record
// (#2122), reusing the crew-run store rather than a second persistence
// mechanism: crew_id is left empty (this run has no crew) and skill_id is
// set, which runMembers above resolves directly. Wired onto AgentSkillServer
// so beginSkillRunWith can call it right after a skill run is provisioned.
func (s *CrewServer) recordSkillRun(ctx context.Context, runID, skillID string) error {
	return s.runs.Put(ctx, &pb.CrewRun{Id: runID, SkillId: skillID})
}

// reapSkillRunRecord removes a standalone skill run's durable record once its
// journal directory has been reaped (#2122), coupling the record's lifetime
// to --run-journal-retention. Delegates the crew-run guard to the store (see
// CrewRunStore.DeleteSkillRun) — this method is safe to call with ANY reaped
// run id, crew or skill.
func (s *CrewServer) reapSkillRunRecord(ctx context.Context, runID string) error {
	return s.runs.DeleteSkillRun(ctx, runID)
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
	// Resolve the run id before any catalog/topology work, same as
	// RunAgentSkill (#1899): a malformed caller-supplied id must fail the RPC,
	// not the run, and a caller with its own run-tracking id (e.g. Containarium
	// Cloud's CrewRunID) needs it to become this run's id so OSS's audit trail
	// and every member's lease resolve back to the same identifier.
	runID, err := resolveRunID(req.GetRunId())
	if err != nil {
		return nil, err
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

	// The three collaborators the run itself is driven through. Injected
	// rather than reached for off s, for the same reason driveCrew already
	// takes its taskSender as a parameter: none of them is reachable from a
	// unit test. provisionSkillBox's seed step can only ever FAIL against a
	// fake container backend ((*container.Manager).Exec type-asserts its
	// backend to the concrete *incus.Client) and SendAgentTask makes a real
	// A2A HTTP call, so without this seam RunCrew's success and
	// driveCrew-failure terminal paths — the ones that must end every member's
	// lease (#2100) — have no unit-testable form at all. The wiper is a
	// parameter for exactly the reason endRunLease already takes one.
	return s.runCrew(ctx, req, crew, runID, crewRunDeps{
		provision: s.provisionMemberBox,
		send:      s.agents.SendAgentTask,
		wiper:     s.agents.boxWiper(),
	})
}

// provisionMemberFunc provisions one crew member's box and starts it serving,
// handing back the lease whose credentials RunCrew must end once the run
// reaches a terminal state. provisionMemberBox in production.
type provisionMemberFunc func(ctx context.Context, skill *pb.AgentSkill, req *pb.RunCrewRequest, runID string) (lease runlease.Lease, gitCommit string, err error)

// crewRunDeps are the collaborators runCrew drives a crew run through. See
// RunCrew's construction of it for why they are parameters.
type crewRunDeps struct {
	provision provisionMemberFunc
	send      taskSender
	wiper     runlease.Wiper
}

// provisionMemberBox is the production provisionMemberFunc: provision the
// member's box (scoped token + per-box allowed_peers policy) and start it in
// serve mode so it serves /tasks for the hops runCrew drives. Members are
// seeded with no task input — the crew delivers per-hop input over A2A.
//
// git_source/git_ref/git_credential (cloud#1554): every member fetches the
// SAME repo+ref into its own per-run workspace — its own box, so trivially
// isolated from every other member's checkout. This is the "git at a pinned
// SHA, not a shared filesystem" design decision (Containarium-cloud
// docs/product/coding-skill-on-a-repo.md §Decided, 2026-09-15): a role
// hand-off between members is a commit on a branch, so two members never
// write the same file at once.
func (s *CrewServer) provisionMemberBox(ctx context.Context, skill *pb.AgentSkill, req *pb.RunCrewRequest, runID string) (runlease.Lease, string, error) {
	containerName, _, lease, gitCommit, _, err := s.agents.provisionSkillBox(ctx, skill, req.BackendId, req.Pool, "", runID,
		req.GetGitSource(), req.GetGitRef(), req.GetGitCredential(), "")
	if err != nil {
		return runlease.Lease{}, "", err
	}
	s.agents.startServeMode(containerName, lease.SeedDir, skill.Id)
	return lease, gitCommit, nil
}

// endMemberLeases ends every collected member lease: revoke its credentials,
// wipe its seed files, remove its seed dir + fetched workspace, and write the
// agent.run_lease_end audit row — RunAgentSkill's single
// `defer s.endRunLease(...)` applied to a crew's N members (#2100).
//
// Nothing detaches the context here: endRunLease already runs on
// context.WithoutCancel, so a cancelled or timed-out RunCrew still gets every
// member's credentials killed. Best-effort and independent per member —
// endRunLease reports through logs and the audit row rather than an error, so
// one member's unreachable box can never leave the next member's credentials
// alive.
func (s *CrewServer) endMemberLeases(ctx context.Context, leases []runlease.Lease, w runlease.Wiper, reason string) {
	for _, lease := range leases {
		s.agents.endRunLease(ctx, lease, w, reason)
	}
}

// runCrew is RunCrew past its request validation: provision every member,
// drive the topology, record the terminal state, and end every member's lease
// at whichever terminal point the run reaches.
func (s *CrewServer) runCrew(ctx context.Context, req *pb.RunCrewRequest, crew *pb.Crew, runID string, deps crewRunDeps) (*pb.RunCrewResponse, error) {
	trace := genTraceID()
	run := &pb.CrewRun{
		Id:        runID,
		CrewId:    crew.Id,
		TraceId:   trace,
		State:     pb.CrewRunState_CREW_RUN_STATE_RUNNING,
		InputJson: req.InputJson,
		// Which daemon is driving it (#1322). Startup reconciliation fails
		// runs that are its own or unowned and leaves a peer's alone; without
		// this every run is unowned and a restart fails all of them, on every
		// daemon sharing the database.
		Owner: s.owner,
		// Echo the request's git fields (cloud#1554) — empty on a run with
		// no git_source, unchanged from today. git_commit is filled in below,
		// once the first member's fetch resolves one.
		GitSource: req.GetGitSource(),
		GitRef:    req.GetGitRef(),
	}

	// Record the run before driving it, so an in-flight run is observable.
	//
	// Previously the first write happened only after driveCrew returned, so
	// GetCrewRun answered NotFound for the entire duration of a run — the one
	// window where a caller most wants to look — and CREW_RUN_STATE_RUNNING
	// was set on a struct that was overwritten before anyone could read it.
	// The state existed in the proto and never in the store.
	//
	// Safe to store now because the store clones: the mutations below act on
	// the local run, and each put replaces the stored copy.
	if err := s.runs.Put(ctx, run); err != nil {
		log.Printf("[crew] record run %s: %v", run.GetId(), err)
	}

	// Every member's lease, in provisioning order. RunAgentSkill holds ONE
	// lease and ends it with one `defer`; a crew holds one per member and ends
	// all of them at every terminal point below — including the mid-loop
	// provisioning failure, where the members already up are serving with live
	// gateway tokens and a checkout of the caller's repo (#2100).
	leases := make([]runlease.Lease, 0, len(crew.SkillIds))

	for _, sid := range crew.SkillIds {
		skill, _ := s.skillByID(sid) // existence already checked by validateCrewTopology
		// The crew run's own id IS the run id (#1817): every member box's
		// credentials carry it in their `run_id` claim, and the lease's issue
		// audit row resolves back to this one handle — as, now, does its
		// matching agent.run_lease_end row.
		lease, gitCommit, err := deps.provision(ctx, skill, req, run.Id)
		if err != nil {
			run.State = pb.CrewRunState_CREW_RUN_STATE_FAILED
			run.Error = fmt.Sprintf("provision skill %q: %v", sid, err)
			if putErr := s.runs.Put(ctx, run); putErr != nil {
				log.Printf("[crew] record run %s: %v", run.GetId(), putErr)
			}
			// The earlier members provisioned and are serving; this RPC IS the
			// run, so nothing will ever come back for them. End their leases
			// here or they hold live credentials and their checkout of the
			// caller's repo indefinitely (#2100). The member that just failed
			// has no lease to end — provisionSkillBox ends its own partial one
			// before returning its error.
			s.endMemberLeases(ctx, leases, deps.wiper, provisionFailedReason)
			return nil, status.Errorf(codes.Internal, "crew %q: %s", crew.Id, run.Error)
		}
		leases = append(leases, lease)
		// Record the commit the FIRST member's fetch resolved to — every
		// member fetches the same git_source/git_ref, so they resolve to the
		// same commit barring a concurrent push mid-run (accepted, same as a
		// single-agent run's own git_source race). Empty gitCommit means this
		// run had no git_source; nothing to record.
		if run.GitCommit == "" && gitCommit != "" {
			run.GitCommit = gitCommit
		}
	}

	// Drive the topology hops over A2A under the shared trace_id, and record the
	// terminal state. driveCrew failures (e.g. a member's A2A server not up yet)
	// land the run in FAILED rather than erroring the RPC — the caller gets the
	// run handle to inspect via GetCrewRun.
	out, err := driveCrew(ctx, crew, trace, req.InputJson, withRunID(deps.send, run.Id))
	if err != nil {
		run.State = pb.CrewRunState_CREW_RUN_STATE_FAILED
		run.Error = err.Error()
	} else {
		run.State = pb.CrewRunState_CREW_RUN_STATE_COMPLETED
		run.ArtifactJson = out
	}

	if err := s.runs.Put(ctx, run); err != nil {
		log.Printf("[crew] record run %s: %v", run.GetId(), err)
	}

	// The run is over on either branch, so every member's lease ends on either
	// branch (#2100). Same reason RunAgentSkill records for its own run exit: a
	// crew member's box is long-lived and keeps serving, but the credentials
	// and the workspace it was given for THIS run do not outlive it.
	s.endMemberLeases(ctx, leases, deps.wiper, runExitReason)

	return &pb.RunCrewResponse{Run: run}, nil
}

// taskSender delivers one A2A task — AgentSkillServer.SendAgentTask in
// production, a fake in tests. Lets driveCrew be unit-tested without boxes.
type taskSender func(ctx context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error)

// withRunID stamps every hop with the crew run's id, so each member's runtime
// journals its task under that run (#2095).
func withRunID(send taskSender, runID string) taskSender {
	return func(ctx context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
		req.RunId = runID
		return send(ctx, req)
	}
}

// driveCrew runs the crew's topology to a final artifact, threading the run's
// trace_id through every hop:
//   - PIPELINE: deliver the crew input to skill[0], chain each output into the
//     next skill (from = the previous skill, so allowed_peers gates the hop).
//   - ORCHESTRATOR / FREEFORM: deliver the input to the entry skill and return
//     its artifact — the agent self-delegates to the rest within its
//     allowed_peers.
func driveCrew(ctx context.Context, crew *pb.Crew, trace, input string, send taskSender) (string, error) {
	ids := crew.SkillIds
	if len(ids) == 0 {
		return "", fmt.Errorf("crew %q has no skills", crew.Id)
	}

	deliver := func(from, to, in string) (string, error) {
		resp, err := send(ctx, &pb.SendAgentTaskRequest{
			FromSkillId: from,
			ToPeerId:    to,
			InputJson:   in,
			TraceId:     trace,
		})
		if err != nil {
			return "", fmt.Errorf("hop %q->%q: %w", from, to, err)
		}
		if resp.Artifact == nil {
			return "", fmt.Errorf("hop %q->%q returned no artifact", from, to)
		}
		if resp.Artifact.State == pb.AgentTaskState_AGENT_TASK_STATE_FAILED {
			return "", fmt.Errorf("hop %q->%q failed: %s", from, to, resp.Artifact.Error)
		}
		return resp.Artifact.OutputJson, nil
	}

	if crew.Topology == pb.CrewTopology_CREW_TOPOLOGY_PIPELINE {
		cur := input
		from := "" // first hop originates from the crew/operator, not a skill
		for _, sid := range ids {
			out, err := deliver(from, sid, cur)
			if err != nil {
				return "", err
			}
			cur, from = out, sid
		}
		return cur, nil
	}

	// ORCHESTRATOR / FREEFORM: the entry skill owns the rest.
	return deliver("", ids[0], input)
}

// GetCrewRun returns the status and artifact of a crew run.
func (s *CrewServer) GetCrewRun(ctx context.Context, req *pb.GetCrewRunRequest) (*pb.GetCrewRunResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeCrewsRead); err != nil {
		return nil, err
	}
	run, ok, err := s.runs.Get(ctx, req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read crew run %q: %v", req.Id, err)
	}
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
