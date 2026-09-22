package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/crews"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func completed(out string) *pb.SendAgentTaskResponse {
	return &pb.SendAgentTaskResponse{Artifact: &pb.AgentArtifact{
		OutputJson: out, State: pb.AgentTaskState_AGENT_TASK_STATE_COMPLETED,
	}}
}

// TestRunCrew_RunIDValidatedBeforeCrewLookup is #1899: a malformed
// caller-supplied run_id must fail the RPC before any catalog/topology work,
// same posture as RunAgentSkill's resolveRunID check. Uses NewCrewServer(nil)
// (no agents server) — reachable because run_id resolution happens before
// s.agents is ever touched.
func TestRunCrew_RunIDValidatedBeforeCrewLookup(t *testing.T) {
	s := NewCrewServer(nil)
	ctx := ctxAs("admin", true)

	// A bad run_id is rejected even for an unknown crew — proves resolveRunID
	// runs before the catalog lookup, not after.
	_, err := s.RunCrew(ctx, &pb.RunCrewRequest{CrewId: "no-such-crew", RunId: "bad id with spaces"})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad run_id: code = %v, want InvalidArgument", status.Code(err))
	}

	// A well-formed run_id is not rejected at this boundary — the request
	// proceeds to the (failing) crew lookup instead.
	_, err = s.RunCrew(ctx, &pb.RunCrewRequest{CrewId: "no-such-crew", RunId: "run-ok"})
	if status.Code(err) == codes.InvalidArgument {
		t.Errorf("valid run_id must not be rejected: %v", err)
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("unknown crew: code = %v, want NotFound", status.Code(err))
	}
}

// TestRunCrew_ResponseCarriesRunID pins the run_id half of #1899's contract
// against the GENERATED pb types (RunCrewRequest.run_id, CrewRun.id), so a
// stale regeneration fails to compile rather than passing quietly — same
// rationale as TestRunAgentSkill_ResponseCarriesRunID. The full RPC can't be
// driven to COMPLETED from a unit test (box provisioning needs a real
// backend); what's pinned here is that a resolved run id round-trips into the
// CrewRun the same way RunCrew's own code constructs it (Id: runID).
func TestRunCrew_ResponseCarriesRunID(t *testing.T) {
	for _, in := range []string{"", "run-echoed"} {
		runID, err := resolveRunID(in)
		if err != nil {
			t.Fatalf("resolveRunID(%q): %v", in, err)
		}
		run := &pb.CrewRun{Id: runID}
		if run.GetId() != runID {
			t.Errorf("run id = %q, want %q", run.GetId(), runID)
		}
		if in != "" && run.GetId() != in {
			t.Errorf("run id = %q, want the caller's %q echoed", run.GetId(), in)
		}
	}
}

func TestDriveCrew(t *testing.T) {
	const trace = "trace-xyz"

	t.Run("pipeline chains outputs, threads from + trace", func(t *testing.T) {
		var calls []*pb.SendAgentTaskRequest
		send := func(_ context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
			calls = append(calls, req)
			return completed("out-of-" + req.ToPeerId), nil
		}
		crew := &pb.Crew{Id: "c", Topology: pb.CrewTopology_CREW_TOPOLOGY_PIPELINE, SkillIds: []string{"relay", "hello"}}

		out, err := driveCrew(context.Background(), crew, trace, "seed-input", send)
		if err != nil {
			t.Fatalf("driveCrew: %v", err)
		}
		if out != "out-of-hello" {
			t.Errorf("final output = %q, want out-of-hello", out)
		}
		if len(calls) != 2 {
			t.Fatalf("expected 2 hops, got %d", len(calls))
		}
		if calls[0].FromSkillId != "" || calls[0].ToPeerId != "relay" || calls[0].InputJson != "seed-input" {
			t.Errorf("hop1 = %+v", calls[0])
		}
		if calls[1].FromSkillId != "relay" || calls[1].ToPeerId != "hello" || calls[1].InputJson != "out-of-relay" {
			t.Errorf("hop2 = %+v (want from=relay to=hello input=out-of-relay)", calls[1])
		}
		for i, c := range calls {
			if c.TraceId != trace {
				t.Errorf("hop %d trace = %q, want %q", i, c.TraceId, trace)
			}
		}
	})

	t.Run("failed hop surfaces the peer error", func(t *testing.T) {
		send := func(_ context.Context, _ *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
			return &pb.SendAgentTaskResponse{Artifact: &pb.AgentArtifact{
				State: pb.AgentTaskState_AGENT_TASK_STATE_FAILED, Error: "boom",
			}}, nil
		}
		crew := &pb.Crew{Id: "c", Topology: pb.CrewTopology_CREW_TOPOLOGY_PIPELINE, SkillIds: []string{"a", "b"}}
		if _, err := driveCrew(context.Background(), crew, trace, "x", send); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Errorf("expected the peer failure to surface, got %v", err)
		}
	})

	t.Run("transport error propagates", func(t *testing.T) {
		send := func(_ context.Context, _ *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
			return nil, errors.New("unavailable")
		}
		crew := &pb.Crew{Id: "c", Topology: pb.CrewTopology_CREW_TOPOLOGY_PIPELINE, SkillIds: []string{"a", "b"}}
		if _, err := driveCrew(context.Background(), crew, trace, "x", send); err == nil {
			t.Error("expected transport error to propagate")
		}
	})

	t.Run("orchestrator delivers to the entry skill only", func(t *testing.T) {
		var calls []*pb.SendAgentTaskRequest
		send := func(_ context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
			calls = append(calls, req)
			return completed("coordinated"), nil
		}
		crew := &pb.Crew{Id: "c", Topology: pb.CrewTopology_CREW_TOPOLOGY_ORCHESTRATOR, SkillIds: []string{"coord", "w1", "w2"}}
		out, err := driveCrew(context.Background(), crew, trace, "x", send)
		if err != nil {
			t.Fatalf("driveCrew: %v", err)
		}
		if out != "coordinated" {
			t.Errorf("output = %q", out)
		}
		if len(calls) != 1 || calls[0].ToPeerId != "coord" {
			t.Errorf("expected one delivery to coord, got %d calls (%+v)", len(calls), calls)
		}
	})
}

// TestEmbeddedFreeformCrewValidatesAndDrives proves the embedded freeform-crew
// (#1552) is actually exercisable end-to-end: it clears RunCrew's topology
// gate against the real skill catalog (not a fake), and driveCrew delivers to
// its entry skill and returns that skill's artifact, same as a real RunCrew
// would. Without this crew, #1548's scenario has no freeform topology to run.
func TestEmbeddedFreeformCrewValidatesAndDrives(t *testing.T) {
	crew, err := crews.GetDefault().Get("freeform-crew")
	if err != nil {
		t.Fatalf("freeform-crew missing from embedded catalog: %v", err)
	}
	if crew.Topology != pb.CrewTopology_CREW_TOPOLOGY_FREEFORM {
		t.Fatalf("freeform-crew topology = %v, want FREEFORM", crew.Topology)
	}
	if len(crew.SkillIds) < 2 {
		t.Fatalf("freeform-crew should reference >=2 skills, got %v", crew.SkillIds)
	}

	sk := skills.GetDefault()
	getSkill := func(id string) (*pb.AgentSkill, bool) {
		s, err := sk.Get(id)
		if err != nil {
			return nil, false
		}
		return s, true
	}
	if err := validateCrewTopology(crew, getSkill); err != nil {
		t.Errorf("RunCrew's topology gate rejects the embedded freeform crew: %v", err)
	}

	var calls []*pb.SendAgentTaskRequest
	send := func(_ context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
		calls = append(calls, req)
		return completed("done"), nil
	}
	out, err := driveCrew(context.Background(), crew, "trace-1", "seed", send)
	if err != nil {
		t.Fatalf("driveCrew: %v", err)
	}
	if out != "done" {
		t.Errorf("output = %q, want done", out)
	}
	if len(calls) != 1 || calls[0].ToPeerId != crew.SkillIds[0] {
		t.Errorf("expected a single delivery to the entry skill %q, got %+v", crew.SkillIds[0], calls)
	}
}

// TestEmbeddedDiffCrewValidatesAndDrives proves diff-crew (cloud#1549 Layer
// 2) is actually exercisable end-to-end against the real skill catalog: it
// clears RunCrew's topology gate, and PIPELINE hand-off delivers
// diff-drafter's artifact as diff-reviewer's task input — the collaboration
// mechanism itself, no new turn-taking machinery. Without this crew, #1549's
// scenario has no drafter/reviewer pair to run.
func TestEmbeddedDiffCrewValidatesAndDrives(t *testing.T) {
	crew, err := crews.GetDefault().Get("diff-crew")
	if err != nil {
		t.Fatalf("diff-crew missing from embedded catalog: %v", err)
	}
	if crew.Topology != pb.CrewTopology_CREW_TOPOLOGY_PIPELINE {
		t.Fatalf("diff-crew topology = %v, want PIPELINE", crew.Topology)
	}
	if got := crew.SkillIds; len(got) != 2 || got[0] != "diff-drafter" || got[1] != "diff-reviewer" {
		t.Fatalf("diff-crew skill_ids = %v, want [diff-drafter diff-reviewer] in order", got)
	}

	sk := skills.GetDefault()
	getSkill := func(id string) (*pb.AgentSkill, bool) {
		s, err := sk.Get(id)
		if err != nil {
			return nil, false
		}
		return s, true
	}
	if err := validateCrewTopology(crew, getSkill); err != nil {
		t.Errorf("RunCrew's topology gate rejects the embedded diff-crew: %v", err)
	}

	// Whole-file artifact shape (cloud#1738), not a unified diff — matches
	// what the actual skill prompts in skills.yaml ask for.
	draftArtifact := `{"files":[{"path":"x.go","content":"package x\n\nfunc New() {}\n"}],"summary":"fix x"}`
	finalArtifact := `{"files":[{"path":"x.go","content":"package x\n\nfunc New() { /* reviewed */ }\n"}],"drafter_summary":"fix x","review_notes":"tightened the fix"}`
	var calls []*pb.SendAgentTaskRequest
	send := func(_ context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
		calls = append(calls, req)
		if req.ToPeerId == "diff-reviewer" {
			return completed(finalArtifact), nil
		}
		return completed(draftArtifact), nil
	}
	out, err := driveCrew(context.Background(), crew, "trace-1", `{"repo":"https://github.com/org/repo","ref":"main","task":"fix x"}`, send)
	if err != nil {
		t.Fatalf("driveCrew: %v", err)
	}
	if out != finalArtifact {
		t.Errorf("crew artifact = %q, want the reviewer's final files %q", out, finalArtifact)
	}

	if len(calls) != 2 {
		t.Fatalf("expected 2 hops (drafter, then reviewer), got %d: %+v", len(calls), calls)
	}
	if calls[0].ToPeerId != "diff-drafter" || calls[0].FromSkillId != "" {
		t.Errorf("hop 1 = from %q to %q, want the crew input delivered to diff-drafter", calls[0].FromSkillId, calls[0].ToPeerId)
	}
	if calls[1].ToPeerId != "diff-reviewer" || calls[1].FromSkillId != "diff-drafter" {
		t.Errorf("hop 2 = from %q to %q, want diff-drafter -> diff-reviewer", calls[1].FromSkillId, calls[1].ToPeerId)
	}
	// The core of the joint-editing mechanism: the drafter's OWN artifact,
	// unmodified, IS the reviewer's task input. No platform-level merge or
	// turn-taking step exists between them — driveCrew's pipeline chaining
	// is the entire hand-off.
	if calls[1].InputJson != draftArtifact {
		t.Errorf("reviewer's input = %q, want the drafter's artifact %q verbatim", calls[1].InputJson, draftArtifact)
	}
}

// skillSet builds a lookup over a fixed set of skills for topology tests.
// skillSet builds a lookup over a fixed set of skills for topology tests.
func skillSet(skills ...*pb.AgentSkill) func(string) (*pb.AgentSkill, bool) {
	m := map[string]*pb.AgentSkill{}
	for _, s := range skills {
		m[s.Id] = s
	}
	return func(id string) (*pb.AgentSkill, bool) { s, ok := m[id]; return s, ok }
}

func TestValidateCrewTopology(t *testing.T) {
	relay := &pb.AgentSkill{Id: "relay", AllowedPeers: []string{"hello"}}
	hello := &pb.AgentSkill{Id: "hello"} // leaf, no peers
	get := skillSet(relay, hello)

	t.Run("pipeline edge permitted", func(t *testing.T) {
		crew := &pb.Crew{Id: "c", Topology: pb.CrewTopology_CREW_TOPOLOGY_PIPELINE, SkillIds: []string{"relay", "hello"}}
		if err := validateCrewTopology(crew, get); err != nil {
			t.Errorf("relay->hello is in allowed_peers; want nil, got %v", err)
		}
	})

	t.Run("pipeline edge NOT permitted", func(t *testing.T) {
		// Reverse direction: hello (leaf) -> relay is not in hello.allowed_peers.
		crew := &pb.Crew{Id: "c", Topology: pb.CrewTopology_CREW_TOPOLOGY_PIPELINE, SkillIds: []string{"hello", "relay"}}
		if err := validateCrewTopology(crew, get); err == nil {
			t.Error("hello->relay is not allowed; want rejection, got nil")
		}
	})

	t.Run("unknown skill", func(t *testing.T) {
		crew := &pb.Crew{Id: "c", Topology: pb.CrewTopology_CREW_TOPOLOGY_PIPELINE, SkillIds: []string{"relay", "ghost"}}
		if err := validateCrewTopology(crew, get); err == nil {
			t.Error("unknown skill should be rejected")
		}
	})

	t.Run("orchestrator coordinator must reach workers", func(t *testing.T) {
		// relay is coordinator; relay->hello allowed, but relay->relay2 (absent peer) not.
		crew := &pb.Crew{Id: "c", Topology: pb.CrewTopology_CREW_TOPOLOGY_ORCHESTRATOR, SkillIds: []string{"relay", "hello"}}
		if err := validateCrewTopology(crew, get); err != nil {
			t.Errorf("relay->hello permitted; want nil, got %v", err)
		}
	})

	t.Run("freeform has no required edges", func(t *testing.T) {
		crew := &pb.Crew{Id: "c", Topology: pb.CrewTopology_CREW_TOPOLOGY_FREEFORM, SkillIds: []string{"hello", "relay"}}
		if err := validateCrewTopology(crew, get); err != nil {
			t.Errorf("freeform implies no required edges; want nil, got %v", err)
		}
	})
}

// TestRunCrew_GitFieldsRoundTrip pins RunCrewRequest.git_source/git_ref/
// git_credential and CrewRun.git_source/git_ref/git_commit against the
// GENERATED pb types (cloud#1554), so a stale regeneration fails to compile
// rather than passing quietly — same pattern
// TestRunAgentSkill_GitFieldsRoundTrip uses for the single-agent request.
func TestRunCrew_GitFieldsRoundTrip(t *testing.T) {
	req := &pb.RunCrewRequest{
		CrewId:        "freeform-crew",
		GitSource:     "https://github.com/org/repo",
		GitRef:        "abc123",
		GitCredential: "ghs_secret",
	}
	if req.GetGitSource() != "https://github.com/org/repo" {
		t.Errorf("GetGitSource() = %q, want the set value", req.GetGitSource())
	}
	if req.GetGitRef() != "abc123" {
		t.Errorf("GetGitRef() = %q, want the set value", req.GetGitRef())
	}
	if req.GetGitCredential() != "ghs_secret" {
		t.Errorf("GetGitCredential() = %q, want the set value", req.GetGitCredential())
	}

	empty := &pb.RunCrewRequest{CrewId: "freeform-crew"}
	if empty.GetGitSource() != "" || empty.GetGitRef() != "" || empty.GetGitCredential() != "" {
		t.Errorf("unset git fields must read as empty, got source=%q ref=%q credential=%q",
			empty.GetGitSource(), empty.GetGitRef(), empty.GetGitCredential())
	}

	run := &pb.CrewRun{
		Id:        "run-1",
		GitSource: "https://github.com/org/repo",
		GitRef:    "abc123",
		GitCommit: "deadbeefcafe",
	}
	if run.GetGitSource() != "https://github.com/org/repo" || run.GetGitRef() != "abc123" || run.GetGitCommit() != "deadbeefcafe" {
		t.Errorf("CrewRun git fields = source=%q ref=%q commit=%q, want the set values",
			run.GetGitSource(), run.GetGitRef(), run.GetGitCommit())
	}

	emptyRun := &pb.CrewRun{Id: "run-1"}
	if emptyRun.GetGitSource() != "" || emptyRun.GetGitRef() != "" || emptyRun.GetGitCommit() != "" {
		t.Errorf("a run with no git_source must report empty git fields, got source=%q ref=%q commit=%q",
			emptyRun.GetGitSource(), emptyRun.GetGitRef(), emptyRun.GetGitCommit())
	}
}

// pipelineCrewCatalog builds a one-crew pipeline catalog over exactly the
// given (ordered) skill ids, so RunCrew can be driven against a topology
// that's actually valid for a provisioning-focused test — pipeline needs
// >=2 skills, and each edge must be permitted by the earlier skill's
// allowed_peers (checked at real Get-time against the real embedded skill
// catalog, so the caller must pass ids that are really wired that way —
// relay-agent -> hello-agent, same as the embedded hello-crew/freeform-crew).
func pipelineCrewCatalog(t *testing.T, crewID string, skillIDs ...string) *crews.Manager {
	t.Helper()
	m := crews.New()
	var b strings.Builder
	fmt.Fprintf(&b, "crews:\n  - id: %s\n    name: Test Crew\n    topology: pipeline\n    skill_ids:\n", crewID)
	for _, id := range skillIDs {
		fmt.Fprintf(&b, "      - %s\n", id)
	}
	if err := m.LoadFromBytes([]byte(b.String())); err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	return m
}

// newSkillBoxHarnessForSkills is newSkillBoxHarness generalized to several
// skills sharing one fake backend, each with its own pre-created container
// so every one takes the "reuse" provisioning path and hits the SAME
// deterministic seed-exec failure newSkillBoxHarness documents.
func newSkillBoxHarnessForSkills(t *testing.T, store auth.RevocationStore, skillIDs ...string) (*AgentSkillServer, []*pb.AgentSkill) {
	t.Helper()
	tm, err := auth.NewTokenManager("test-secret-must-be-at-least-32-bytes-long-ok", "test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	backend := newFakeSandboxBackend()
	catalog := skills.GetDefault()
	var out []*pb.AgentSkill
	for _, id := range skillIDs {
		skill, err := catalog.Get(id)
		if err != nil {
			t.Fatalf("catalog %s: %v", id, err)
		}
		if err := backend.CreateContainer(incus.ContainerConfig{Name: "agent-" + skill.Id + "-container"}); err != nil {
			t.Fatalf("seed fake backend for %s: %v", id, err)
		}
		out = append(out, skill)
	}
	cs := &ContainerServer{manager: container.NewWithBackend(backend)}
	s := &AgentSkillServer{
		catalog: catalog,
		recipes: NewRecipeServer(cs, nil),
		tokens:  tm,
		gateway: &gatewayProvisioning{provider: "anthropic", httpPort: 8080, secret: []byte("test-shared-secret")},
	}
	s.SetRevocationStore(store)
	return s, out
}

// TestRunCrew_GitSourceThreadedToEveryMember is cloud#1554's core fix: a
// crew run carrying git_source/git_ref must (a) not be rejected at the RPC
// layer — it fails at the same provisioning step ("failed to seed agent
// box") a git_source-less run would, proving the fields don't derail request
// handling — and (b) have the CrewRun row echo git_source/git_ref even on
// failure, the same way a failed skill run still records what it was asked
// to fetch. What this test CANNOT observe from outside provisionSkillBox: a
// unit test can't tell "the field reached provisionSkillBox but the fetch
// never ran because seed failed first" (the design's own fetch-after-seed
// ordering) apart from "the field was silently dropped" — both produce the
// identical seed-exec failure. The threading itself is the same one-line
// pattern RunAgentSkill already uses (req.GetGitSource()/GetGitRef()/
// GetGitCredential() passed straight through, pinned by
// TestRunCrew_GitFieldsRoundTrip); the happy-path fetch needs a real box and
// is e2e territory, same limitation TestProvisionSkillBox_GitSourceSet_SeedFailsBeforeFetch
// documents for the single-agent path.
func TestRunCrew_GitSourceThreadedToEveryMember(t *testing.T) {
	store := newFakeRevocationStore()
	agents, _ := newSkillBoxHarnessForSkills(t, store, "relay-agent", "hello-agent")
	s := &CrewServer{
		catalog: pipelineCrewCatalog(t, "test-crew", "relay-agent", "hello-agent"),
		skills:  skills.GetDefault(),
		agents:  agents,
		runs:    NewMemCrewRunStore(),
	}
	ctx := ctxAs("admin", true)

	_, err := s.RunCrew(ctx, &pb.RunCrewRequest{
		CrewId:    "test-crew",
		RunId:     "run-git-crew",
		GitSource: "https://github.com/org/repo",
		GitRef:    "main",
	})
	if err == nil {
		t.Fatal("expected an error — the harness's fake backend always fails the seed exec")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("code = %v, want Internal (a provisioning failure, not a validation error)", status.Code(err))
	}
	if got := err.Error(); !strings.Contains(got, "failed to seed agent box") {
		t.Errorf("error = %q, want it to name the seed step — a different error here would mean\n"+
			"the git fields changed the failure path instead of just reaching provisionSkillBox", got)
	}

	// The CrewRun row must echo the request's git_source/git_ref even though
	// the run failed — same as a failed skill run still recording what it
	// was asked to fetch.
	run, ok, gerr := s.runs.Get(ctx, "run-git-crew")
	if gerr != nil {
		t.Fatalf("Get: %v", gerr)
	}
	if !ok {
		t.Fatal("expected the failed run to still be recorded")
	}
	if run.GetState() != pb.CrewRunState_CREW_RUN_STATE_FAILED {
		t.Errorf("state = %v, want FAILED", run.GetState())
	}
	if run.GetGitSource() != "https://github.com/org/repo" || run.GetGitRef() != "main" {
		t.Errorf("run git fields = source=%q ref=%q, want them echoed even on failure",
			run.GetGitSource(), run.GetGitRef())
	}
}
