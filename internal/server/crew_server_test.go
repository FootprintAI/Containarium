package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/crews"
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
