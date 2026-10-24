package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/pkg/core/taskgraph"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The plan in crewPlanValidateCmd's help text, against the embedded catalog.
const examplePlanYAML = `
goal: add rate limiting to the API
nodes:
  - id: implement
    goal: implement the limiter
    skill_id: issue-implementer
  - id: review
    goal: review the change
    skill_id: code-review
edges:
  - node_id: review
    depends_on: implement
`

func writePlan(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func withNoServer(t *testing.T) {
	t.Helper()
	prev := serverAddr
	serverAddr = ""
	t.Cleanup(func() { serverAddr = prev })
}

func TestLoadTaskGraph_YAMLAndJSONAgree(t *testing.T) {
	fromYAML, err := loadTaskGraph(writePlan(t, "plan.yaml", examplePlanYAML))
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	fromJSON, err := loadTaskGraph(writePlan(t, "plan.json", `{
  "goal": "add rate limiting to the API",
  "nodes": [
    {"id": "implement", "goal": "implement the limiter", "skillId": "issue-implementer"},
    {"id": "review", "goal": "review the change", "skill_id": "code-review"}
  ],
  "edges": [{"nodeId": "review", "dependsOn": "implement"}]
}`))
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if !proto.Equal(fromYAML, fromJSON) {
		t.Errorf("YAML and JSON parsed differently\nyaml: %v\njson: %v", fromYAML, fromJSON)
	}
}

func TestLoadTaskGraph_RejectsUnknownField(t *testing.T) {
	_, err := loadTaskGraph(writePlan(t, "plan.yaml", "goal: g\nnodes:\n  - id: a\n    skil_id: code-review\n"))
	if err == nil {
		t.Fatal("want an error for a misspelled field")
	}
}

func TestCrewPlanValidate_LocalAcceptsExample(t *testing.T) {
	withNoServer(t)
	if err := runCrewPlanValidate(crewPlanValidateCmd, []string{writePlan(t, "plan.yaml", examplePlanYAML)}); err != nil {
		t.Fatalf("runCrewPlanValidate: %v", err)
	}
}

// The CLI runs the same taskgraph.Validate the daemon does, so its errors
// carry the same sentinels.
func TestCrewPlanValidate_LocalRejects(t *testing.T) {
	withNoServer(t)
	cases := map[string]struct {
		plan string
		want error
	}{
		"cycle": {`
nodes:
  - {id: a, goal: g, skill_id: code-review}
  - {id: b, goal: g, skill_id: code-review}
edges:
  - {node_id: a, depends_on: b}
  - {node_id: b, depends_on: a}
`, taskgraph.ErrCycle},
		"unknown skill": {`
nodes:
  - {id: a, goal: g, skill_id: no-such-skill}
`, taskgraph.ErrUnknownAssignee},
		"over cap": {`
limits: {max_nodes: 1}
nodes:
  - {id: a, goal: g, skill_id: code-review}
  - {id: b, goal: g, crew_id: hello-crew}
`, taskgraph.ErrOverCap},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := runCrewPlanValidate(crewPlanValidateCmd, []string{writePlan(t, "plan.yaml", tc.plan)})
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// taskGraphCaptureServer records the graph the daemon's handler receives.
type taskGraphCaptureServer struct {
	pb.UnimplementedCrewServiceServer

	mu  sync.Mutex
	got *pb.TaskGraph
}

func (s *taskGraphCaptureServer) ValidateTaskGraph(_ context.Context, req *pb.ValidateTaskGraphRequest) (*pb.ValidateTaskGraphResponse, error) {
	s.mu.Lock()
	s.got = proto.Clone(req.GetGraph()).(*pb.TaskGraph)
	s.mu.Unlock()
	return &pb.ValidateTaskGraphResponse{Order: []string{"implement", "review"}, Depth: 2}, nil
}

func TestCrewPlanValidate_ServerReceivesGraph(t *testing.T) {
	path := writePlan(t, "plan.yaml", examplePlanYAML)
	want, err := loadTaskGraph(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{"grpc", "http"} {
		t.Run(transport, func(t *testing.T) {
			capture := &taskGraphCaptureServer{}
			startCrewRunDaemon(t, transport, capture)
			if err := runCrewPlanValidate(crewPlanValidateCmd, []string{path}); err != nil {
				t.Fatalf("runCrewPlanValidate: %v", err)
			}
			capture.mu.Lock()
			got := capture.got
			capture.mu.Unlock()
			if !proto.Equal(got, want) {
				t.Errorf("daemon received a different graph\n got: %v\nwant: %v", got, want)
			}
		})
	}
}
