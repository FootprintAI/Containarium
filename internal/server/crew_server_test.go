package server

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

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
