package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/footprintai/containarium/pkg/core/crews"
	"github.com/footprintai/containarium/pkg/core/skills"
	"github.com/footprintai/containarium/pkg/core/taskgraph"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"
)

var crewPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Work with task graphs — a goal split into crew/skill subtasks (#2369)",
}

var crewPlanValidateCmd = &cobra.Command{
	Use:   "validate <file>",
	Short: "Validate a task graph file",
	Long: `Check a TaskGraph (YAML or JSON, the proto's field names) is acyclic, that
every node's crew or skill exists, and that its node count and depth are
within the cap. Prints a dependency-respecting node order on success.

Without --server the graph is checked against the crews and skills compiled
into this CLI; with --server, against the daemon's catalogs (including any
external ones it loaded).

Example plan.yaml:
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

  containarium crew plan validate plan.yaml
  containarium crew plan validate plan.yaml --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runCrewPlanValidate,
}

func init() {
	crewCmd.AddCommand(crewPlanCmd)
	crewPlanCmd.AddCommand(crewPlanValidateCmd)
}

// loadTaskGraph reads a TaskGraph from a YAML or JSON file. YAML is turned
// into JSON first so both go through protojson, which rejects unknown fields.
func loadTaskGraph(path string) (*pb.TaskGraph, error) {
	// #nosec G304 -- operator-supplied path; reading it is the command's purpose.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	js, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	g := &pb.TaskGraph{}
	if err := protojson.Unmarshal(js, g); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return g, nil
}

func runCrewPlanValidate(cmd *cobra.Command, args []string) error {
	g, err := loadTaskGraph(args[0])
	if err != nil {
		return err
	}
	var order []string
	var depth int
	if serverAddr == "" {
		res, err := taskgraph.Validate(g, skills.GetDefault(), crews.GetDefault())
		if err != nil {
			return err
		}
		order, depth = res.Order, res.Depth
	} else {
		c, err := newCrewClient()
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		resp, err := c.ValidateTaskGraph(g)
		if err != nil {
			return err
		}
		order, depth = resp.GetOrder(), int(resp.GetDepth())
	}
	fmt.Printf("Valid: %d nodes, depth %d\n", len(order), depth)
	fmt.Printf("Order: %s\n", strings.Join(order, " -> "))
	return nil
}
