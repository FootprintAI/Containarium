package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// Scope routes (#2021): map a `scope:<role>` label on a tracker
// connection to the skill the dispatcher (#2022) starts for it. An
// unmapped scope label is never dispatched. Requires tracker:admin, like
// connection CRUD. See docs/architecture/issue-triggered-agents.md.

var trackerRouteCmd = &cobra.Command{
	Use:   "route",
	Short: "Map scope:<role> labels to skills on a tracker connection",
	Long: `A route sends issues labeled scope:<scope> on one tracker connection to
one agent skill. --scope is the label suffix: --scope product matches the
label "scope:product".

  containarium tracker route set alice default --scope product --skill product-define
  containarium tracker route list alice default
  containarium tracker route delete alice default --scope product

Deleting the connection deletes its routes.`,
}

var trackerRouteSetCmd = &cobra.Command{
	Use:   "set <username> <connection> --scope <scope> --skill <skill-id>",
	Short: "Create or update the route for one scope label",
	Args:  cobra.ExactArgs(2),
	RunE:  runTrackerRouteSet,
}

var trackerRouteListCmd = &cobra.Command{
	Use:   "list <username> <connection>",
	Short: "List a connection's scope routes",
	Args:  cobra.ExactArgs(2),
	RunE:  runTrackerRouteList,
}

var trackerRouteDeleteCmd = &cobra.Command{
	Use:     "delete <username> <connection> --scope <scope>",
	Aliases: []string{"rm", "remove"},
	Short:   "Remove the route for one scope label",
	Args:    cobra.ExactArgs(2),
	RunE:    runTrackerRouteDelete,
}

var (
	trackerRouteScope       string
	trackerRouteSkill       string
	trackerRouteDeleteScope string
)

func init() {
	trackerCmd.AddCommand(trackerRouteCmd)

	trackerRouteCmd.AddCommand(trackerRouteSetCmd)
	trackerRouteSetCmd.Flags().StringVar(&trackerRouteScope, "scope", "",
		`Label suffix: "product" matches the label "scope:product". Required.`)
	trackerRouteSetCmd.Flags().StringVar(&trackerRouteSkill, "skill", "",
		"Agent skill id to run for issues with this scope label (see `containarium agent list`). Required.")

	trackerRouteCmd.AddCommand(trackerRouteListCmd)

	trackerRouteCmd.AddCommand(trackerRouteDeleteCmd)
	trackerRouteDeleteCmd.Flags().StringVar(&trackerRouteDeleteScope, "scope", "", "Label suffix of the route to remove. Required.")
}

// trackerRouteClient is the slice of the typed client the route
// subcommands need; *client.GRPCClient and *client.HTTPClient both
// satisfy it, so each handler is written once for both transports.
type trackerRouteClient interface {
	SetTrackerRoute(req *pb.SetTrackerRouteRequest) (*pb.TrackerRoute, string, error)
	ListTrackerRoutes(username, connection string) ([]*pb.TrackerRoute, error)
	DeleteTrackerRoute(req *pb.DeleteTrackerRouteRequest) (string, error)
	Close() error
}

var (
	_ trackerRouteClient = (*client.GRPCClient)(nil)
	_ trackerRouteClient = (*client.HTTPClient)(nil)
)

func newTrackerRouteClient() (trackerRouteClient, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required for tracker commands (daemon owns the route store)")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

// scopeLabelPrefix mirrors internal/tracker.ScopeLabelPrefix. Not
// imported: internal/tracker links pgx, which the client build must not
// (scripts/test-cli-split-deps.sh).
const scopeLabelPrefix = "scope:"

// validateRouteScopeFlag catches the common --scope mistakes locally,
// pointing at the likeliest one (passing the whole label) with the exact
// flag to use instead. The daemon applies the full scope grammar
// (internal/tracker.ValidateRouteScope) and is authoritative.
func validateRouteScopeFlag(scope string) error {
	if scope == "" {
		return fmt.Errorf("--scope is required")
	}
	if strings.HasPrefix(scope, scopeLabelPrefix) {
		return fmt.Errorf("--scope takes the label suffix, not the label: use --scope %s", strings.TrimPrefix(scope, scopeLabelPrefix))
	}
	if strings.ContainsAny(scope, " \t\n:/") {
		return fmt.Errorf("--scope %q is invalid: a scope is a single label suffix like \"product\"", scope)
	}
	return nil
}

func buildSetTrackerRouteRequest(username, connection, scope, skill string) (*pb.SetTrackerRouteRequest, error) {
	scope, skill = strings.TrimSpace(scope), strings.TrimSpace(skill)
	if err := validateRouteScopeFlag(scope); err != nil {
		return nil, err
	}
	if skill == "" {
		return nil, fmt.Errorf("--skill is required")
	}
	return &pb.SetTrackerRouteRequest{Username: username, Connection: connection, Scope: scope, SkillId: skill}, nil
}

func buildDeleteTrackerRouteRequest(username, connection, scope string) (*pb.DeleteTrackerRouteRequest, error) {
	scope = strings.TrimSpace(scope)
	if err := validateRouteScopeFlag(scope); err != nil {
		return nil, err
	}
	return &pb.DeleteTrackerRouteRequest{Username: username, Connection: connection, Scope: scope}, nil
}

func runTrackerRouteSet(cmd *cobra.Command, args []string) error {
	req, err := buildSetTrackerRouteRequest(args[0], args[1], trackerRouteScope, trackerRouteSkill)
	if err != nil {
		return err
	}
	c, err := newTrackerRouteClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	route, msg, err := c.SetTrackerRoute(req)
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s: %s%s -> %s\n", msg, scopeLabelPrefix, route.GetScope(), route.GetSkillId())
	return nil
}

func runTrackerRouteList(cmd *cobra.Command, args []string) error {
	username, connection := args[0], args[1]
	c, err := newTrackerRouteClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	routes, err := c.ListTrackerRoutes(username, connection)
	if err != nil {
		return err
	}
	printTrackerRoutes(username, connection, routes)
	return nil
}

func runTrackerRouteDelete(cmd *cobra.Command, args []string) error {
	req, err := buildDeleteTrackerRouteRequest(args[0], args[1], trackerRouteDeleteScope)
	if err != nil {
		return err
	}
	c, err := newTrackerRouteClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	msg, err := c.DeleteTrackerRoute(req)
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s\n", msg)
	return nil
}

func printTrackerRoutes(username, connection string, routes []*pb.TrackerRoute) {
	if len(routes) == 0 {
		fmt.Printf("(no scope routes on %s/%s)\n", username, connection)
		return
	}
	fmt.Printf("%-28s %s\n", "LABEL", "SKILL")
	for _, r := range routes {
		fmt.Printf("%-28s %s\n", scopeLabelPrefix+r.GetScope(), r.GetSkillId())
	}
}
