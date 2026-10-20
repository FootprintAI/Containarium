// Package taskgraph validates a TaskGraph (#2803, slice 1 of #2369): a
// high-level goal decomposed into subtasks, each assigned to a crew or a
// skill, wired by depends-on edges. The daemon (CrewService.ValidateTaskGraph)
// and the CLI (`containarium crew plan validate`) both call Validate, so a
// graph accepted by one is accepted by the other given the same catalogs.
package taskgraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Platform caps. A graph's own TaskGraphLimits may tighten these but never
// raise them.
const (
	MaxNodes = 32
	MaxDepth = 8
)

// Sentinel errors, so callers and tests can tell the failure classes apart
// with errors.Is. Every error Validate returns wraps exactly one of them.
var (
	// ErrInvalid: a structural problem — missing field, duplicate id, an edge
	// to a node that does not exist, malformed input_json.
	ErrInvalid = errors.New("invalid task graph")
	// ErrCycle: the depends-on edges form a cycle.
	ErrCycle = errors.New("task graph has a cycle")
	// ErrUnknownAssignee: a node names a crew or skill the catalogs do not have.
	ErrUnknownAssignee = errors.New("task graph references an unknown crew or skill")
	// ErrOverCap: node count or depth exceeds the limit, or a limit exceeds
	// the platform cap.
	ErrOverCap = errors.New("task graph exceeds its limits")
)

// SkillLookup resolves a skill id; *skills.Manager satisfies it.
type SkillLookup interface {
	Get(id string) (*pb.AgentSkill, error)
}

// CrewLookup resolves a crew id; *crews.Manager satisfies it.
type CrewLookup interface {
	Get(id string) (*pb.Crew, error)
}

// Result is what a valid graph yields.
type Result struct {
	// Order lists node ids so that every node follows everything it depends
	// on. Ties are broken by node id, so the order is deterministic.
	Order []string
	// Depth is the number of nodes on the longest depends-on chain.
	Depth int
}

// Validate checks g is well-formed, acyclic, references only known crews and
// skills, and is within its node and depth limits. It returns the first
// problem found.
func Validate(g *pb.TaskGraph, skills SkillLookup, crews CrewLookup) (*Result, error) {
	if g == nil {
		return nil, fmt.Errorf("%w: graph is required", ErrInvalid)
	}
	maxNodes, maxDepth, err := effectiveLimits(g.GetLimits())
	if err != nil {
		return nil, err
	}
	nodes := g.GetNodes()
	if len(nodes) == 0 {
		return nil, fmt.Errorf("%w: graph has no nodes", ErrInvalid)
	}
	// Checked before anything that walks the graph, so an oversized graph
	// costs no more than its length to reject.
	if len(nodes) > maxNodes {
		return nil, fmt.Errorf("%w: %d nodes, limit is %d", ErrOverCap, len(nodes), maxNodes)
	}

	index := make(map[string]int, len(nodes))
	for i, n := range nodes {
		if err := validateNode(n, skills, crews); err != nil {
			return nil, err
		}
		if _, dup := index[n.GetId()]; dup {
			return nil, fmt.Errorf("%w: duplicate node id %q", ErrInvalid, n.GetId())
		}
		index[n.GetId()] = i
	}

	// deps[i] holds the nodes i waits for; dependents[j] the nodes waiting on j.
	deps := make([][]int, len(nodes))
	dependents := make([][]int, len(nodes))
	seen := make(map[[2]int]bool, len(g.GetEdges()))
	for _, e := range g.GetEdges() {
		from, ok := index[e.GetNodeId()]
		if !ok {
			return nil, fmt.Errorf("%w: edge from unknown node %q", ErrInvalid, e.GetNodeId())
		}
		to, ok := index[e.GetDependsOn()]
		if !ok {
			return nil, fmt.Errorf("%w: node %q depends on unknown node %q", ErrInvalid, e.GetNodeId(), e.GetDependsOn())
		}
		if from == to {
			return nil, fmt.Errorf("%w: node %q depends on itself", ErrCycle, e.GetNodeId())
		}
		key := [2]int{from, to}
		if seen[key] {
			continue // a repeated edge says nothing new
		}
		seen[key] = true
		deps[from] = append(deps[from], to)
		dependents[to] = append(dependents[to], from)
	}

	order, depth, err := topoOrder(nodes, deps, dependents)
	if err != nil {
		return nil, err
	}
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: depth %d, limit is %d", ErrOverCap, depth, maxDepth)
	}
	return &Result{Order: order, Depth: depth}, nil
}

func effectiveLimits(l *pb.TaskGraphLimits) (maxNodes, maxDepth int, err error) {
	maxNodes, maxDepth = MaxNodes, MaxDepth
	if n := l.GetMaxNodes(); n != 0 {
		if n > MaxNodes {
			return 0, 0, fmt.Errorf("%w: limits.max_nodes %d is above the platform cap %d", ErrOverCap, n, MaxNodes)
		}
		maxNodes = int(n)
	}
	if d := l.GetMaxDepth(); d != 0 {
		if d > MaxDepth {
			return 0, 0, fmt.Errorf("%w: limits.max_depth %d is above the platform cap %d", ErrOverCap, d, MaxDepth)
		}
		maxDepth = int(d)
	}
	return maxNodes, maxDepth, nil
}

func validateNode(n *pb.TaskNode, skills SkillLookup, crews CrewLookup) error {
	if n.GetId() == "" {
		return fmt.Errorf("%w: a node is missing its id", ErrInvalid)
	}
	if strings.TrimSpace(n.GetGoal()) == "" {
		return fmt.Errorf("%w: node %q is missing its goal", ErrInvalid, n.GetId())
	}
	if in := n.GetInputJson(); in != "" && !json.Valid([]byte(in)) {
		return fmt.Errorf("%w: node %q input_json is not valid JSON", ErrInvalid, n.GetId())
	}
	switch a := n.GetAssignee().(type) {
	case *pb.TaskNode_SkillId:
		if a.SkillId == "" {
			return fmt.Errorf("%w: node %q has an empty skill_id", ErrInvalid, n.GetId())
		}
		if _, err := skills.Get(a.SkillId); err != nil {
			return fmt.Errorf("%w: node %q: skill %q not found", ErrUnknownAssignee, n.GetId(), a.SkillId)
		}
	case *pb.TaskNode_CrewId:
		if a.CrewId == "" {
			return fmt.Errorf("%w: node %q has an empty crew_id", ErrInvalid, n.GetId())
		}
		if _, err := crews.Get(a.CrewId); err != nil {
			return fmt.Errorf("%w: node %q: crew %q not found", ErrUnknownAssignee, n.GetId(), a.CrewId)
		}
	default:
		return fmt.Errorf("%w: node %q needs a crew_id or a skill_id", ErrInvalid, n.GetId())
	}
	return nil
}

// topoOrder runs Kahn's algorithm, computing each node's depth (1 + the
// deepest node it waits for) on the way. Nodes left unvisited sit on, or
// downstream of, a cycle.
func topoOrder(nodes []*pb.TaskNode, deps, dependents [][]int) ([]string, int, error) {
	pending := make([]int, len(nodes))
	var ready []int
	for i := range nodes {
		pending[i] = len(deps[i])
		if pending[i] == 0 {
			ready = append(ready, i)
		}
	}
	byID := func(s []int) {
		sort.Slice(s, func(a, b int) bool { return nodes[s[a]].GetId() < nodes[s[b]].GetId() })
	}
	byID(ready)

	level := make([]int, len(nodes))
	order := make([]string, 0, len(nodes))
	depth := 0
	for len(ready) > 0 {
		i := ready[0]
		ready = ready[1:]
		level[i]++ // its own node on top of the deepest dependency
		if level[i] > depth {
			depth = level[i]
		}
		order = append(order, nodes[i].GetId())
		var next []int
		for _, j := range dependents[i] {
			if level[i] > level[j] {
				level[j] = level[i]
			}
			pending[j]--
			if pending[j] == 0 {
				next = append(next, j)
			}
		}
		ready = append(ready, next...)
		byID(ready)
	}

	if len(order) < len(nodes) {
		var stuck []string
		for i := range nodes {
			if pending[i] > 0 {
				stuck = append(stuck, nodes[i].GetId())
			}
		}
		sort.Strings(stuck)
		return nil, 0, fmt.Errorf("%w: involving %s", ErrCycle, strings.Join(stuck, ", "))
	}
	return order, depth, nil
}
