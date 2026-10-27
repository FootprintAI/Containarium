package taskgraph

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type fakeSkills map[string]bool

func (f fakeSkills) Get(id string) (*pb.AgentSkill, error) {
	if !f[id] {
		return nil, fmt.Errorf("skill not found: %s", id)
	}
	return &pb.AgentSkill{Id: id}, nil
}

type fakeCrews map[string]bool

func (f fakeCrews) Get(id string) (*pb.Crew, error) {
	if !f[id] {
		return nil, fmt.Errorf("crew not found: %s", id)
	}
	return &pb.Crew{Id: id}, nil
}

var (
	knownSkills = fakeSkills{"coder": true, "reviewer": true}
	knownCrews  = fakeCrews{"build-crew": true}
)

func skillNode(id, skill string) *pb.TaskNode {
	return &pb.TaskNode{Id: id, Goal: "do " + id, Assignee: &pb.TaskNode_SkillId{SkillId: skill}}
}

func crewNode(id, crew string) *pb.TaskNode {
	return &pb.TaskNode{Id: id, Goal: "do " + id, Assignee: &pb.TaskNode_CrewId{CrewId: crew}}
}

func edge(node, dependsOn string) *pb.TaskEdge {
	return &pb.TaskEdge{NodeId: node, DependsOn: dependsOn}
}

// chain returns n skill nodes where each depends on the one before it.
func chain(n int) *pb.TaskGraph {
	g := &pb.TaskGraph{Goal: "chain"}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("n%02d", i)
		g.Nodes = append(g.Nodes, skillNode(id, "coder"))
		if i > 0 {
			g.Edges = append(g.Edges, edge(id, fmt.Sprintf("n%02d", i-1)))
		}
	}
	return g
}

func TestValidateAcceptsDiamond(t *testing.T) {
	g := &pb.TaskGraph{
		Goal: "ship a feature",
		Nodes: []*pb.TaskNode{
			skillNode("design", "coder"),
			skillNode("backend", "coder"),
			crewNode("frontend", "build-crew"),
			skillNode("review", "reviewer"),
		},
		Edges: []*pb.TaskEdge{
			edge("backend", "design"),
			edge("frontend", "design"),
			edge("review", "backend"),
			edge("review", "frontend"),
			edge("review", "frontend"), // repeated edges are tolerated
		},
	}
	res, err := Validate(g, knownSkills, knownCrews)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if want := []string{"design", "backend", "frontend", "review"}; !reflect.DeepEqual(res.Order, want) {
		t.Errorf("Order = %v, want %v", res.Order, want)
	}
	if res.Depth != 3 {
		t.Errorf("Depth = %d, want 3", res.Depth)
	}
}

func TestValidateIndependentNodesHaveDepthOne(t *testing.T) {
	g := &pb.TaskGraph{Nodes: []*pb.TaskNode{skillNode("b", "coder"), skillNode("a", "reviewer")}}
	res, err := Validate(g, knownSkills, knownCrews)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if want := []string{"a", "b"}; !reflect.DeepEqual(res.Order, want) {
		t.Errorf("Order = %v, want %v", res.Order, want)
	}
	if res.Depth != 1 {
		t.Errorf("Depth = %d, want 1", res.Depth)
	}
}

func TestValidateRejectsCycle(t *testing.T) {
	g := &pb.TaskGraph{
		Nodes: []*pb.TaskNode{skillNode("a", "coder"), skillNode("b", "coder"), skillNode("c", "coder"), skillNode("d", "coder")},
		Edges: []*pb.TaskEdge{edge("b", "a"), edge("c", "b"), edge("b", "c"), edge("d", "c")},
	}
	_, err := Validate(g, knownSkills, knownCrews)
	if !errors.Is(err, ErrCycle) {
		t.Fatalf("err = %v, want ErrCycle", err)
	}
	// a is upstream of the cycle and resolvable, so it is not named.
	if !strings.Contains(err.Error(), "b, c, d") || strings.Contains(err.Error(), "a,") {
		t.Errorf("err = %q, want the stuck nodes b, c, d named", err)
	}
}

func TestValidateRejectsSelfDependency(t *testing.T) {
	g := &pb.TaskGraph{Nodes: []*pb.TaskNode{skillNode("a", "coder")}, Edges: []*pb.TaskEdge{edge("a", "a")}}
	if _, err := Validate(g, knownSkills, knownCrews); !errors.Is(err, ErrCycle) {
		t.Fatalf("err = %v, want ErrCycle", err)
	}
}

func TestValidateRejectsUnknownAssignee(t *testing.T) {
	for name, n := range map[string]*pb.TaskNode{
		"skill": skillNode("a", "no-such-skill"),
		"crew":  crewNode("a", "no-such-crew"),
	} {
		t.Run(name, func(t *testing.T) {
			g := &pb.TaskGraph{Nodes: []*pb.TaskNode{n}}
			_, err := Validate(g, knownSkills, knownCrews)
			if !errors.Is(err, ErrUnknownAssignee) {
				t.Fatalf("err = %v, want ErrUnknownAssignee", err)
			}
			if !strings.Contains(err.Error(), "no-such-") {
				t.Errorf("err = %q, want the unknown id named", err)
			}
		})
	}
}

func TestValidateRejectsOverCap(t *testing.T) {
	cases := map[string]*pb.TaskGraph{
		"too many nodes": func() *pb.TaskGraph {
			g := &pb.TaskGraph{}
			for i := 0; i <= MaxNodes; i++ {
				g.Nodes = append(g.Nodes, skillNode(fmt.Sprintf("n%02d", i), "coder"))
			}
			return g
		}(),
		"too deep": chain(MaxDepth + 1),
		"over the graph's own max_nodes": func() *pb.TaskGraph {
			g := chain(3)
			g.Edges = nil
			g.Limits = &pb.TaskGraphLimits{MaxNodes: 2}
			return g
		}(),
		"over the graph's own max_depth": func() *pb.TaskGraph {
			g := chain(3)
			g.Limits = &pb.TaskGraphLimits{MaxDepth: 2}
			return g
		}(),
		"max_nodes above the platform cap": func() *pb.TaskGraph {
			g := chain(1)
			g.Limits = &pb.TaskGraphLimits{MaxNodes: MaxNodes + 1}
			return g
		}(),
		"max_depth above the platform cap": func() *pb.TaskGraph {
			g := chain(1)
			g.Limits = &pb.TaskGraphLimits{MaxDepth: MaxDepth + 1}
			return g
		}(),
	}
	for name, g := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Validate(g, knownSkills, knownCrews); !errors.Is(err, ErrOverCap) {
				t.Fatalf("err = %v, want ErrOverCap", err)
			}
		})
	}
}

func TestValidateAcceptsGraphAtTheCap(t *testing.T) {
	g := chain(MaxDepth)
	for i := len(g.Nodes); i < MaxNodes; i++ {
		g.Nodes = append(g.Nodes, skillNode(fmt.Sprintf("x%02d", i), "reviewer"))
	}
	res, err := Validate(g, knownSkills, knownCrews)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(res.Order) != MaxNodes || res.Depth != MaxDepth {
		t.Errorf("got %d nodes, depth %d; want %d, %d", len(res.Order), res.Depth, MaxNodes, MaxDepth)
	}
}

func TestValidateRejectsMalformed(t *testing.T) {
	cases := map[string]*pb.TaskGraph{
		"nil graph":      nil,
		"no nodes":       {Goal: "empty"},
		"missing id":     {Nodes: []*pb.TaskNode{skillNode("", "coder")}},
		"missing goal":   {Nodes: []*pb.TaskNode{{Id: "a", Assignee: &pb.TaskNode_SkillId{SkillId: "coder"}}}},
		"no assignee":    {Nodes: []*pb.TaskNode{{Id: "a", Goal: "g"}}},
		"empty skill id": {Nodes: []*pb.TaskNode{skillNode("a", "")}},
		"duplicate id":   {Nodes: []*pb.TaskNode{skillNode("a", "coder"), skillNode("a", "reviewer")}},
		"bad input_json": {Nodes: []*pb.TaskNode{{Id: "a", Goal: "g", InputJson: "{", Assignee: &pb.TaskNode_SkillId{SkillId: "coder"}}}},
		"edge from unknown node": {
			Nodes: []*pb.TaskNode{skillNode("a", "coder")},
			Edges: []*pb.TaskEdge{edge("ghost", "a")},
		},
		"edge to unknown node": {
			Nodes: []*pb.TaskNode{skillNode("a", "coder")},
			Edges: []*pb.TaskEdge{edge("a", "ghost")},
		},
	}
	for name, g := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Validate(g, knownSkills, knownCrews); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}
