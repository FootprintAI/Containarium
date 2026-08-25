package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/spf13/cobra"
)

var containerGetFormat string

var getCmd = &cobra.Command{
	Use:   "get <username>",
	Short: "Get one container's current state",
	Long: `Look up a single container by username — the O(1) counterpart to
'containarium list', which always fetches and filters every container on
the backend even when only one is wanted.

Found live (#1541): a script polling readiness with 'list' in a tight loop
makes the backend do 2 Incus API round-trips per EXISTING container on
every single poll, regardless of how many containers the caller actually
cares about — at a few hundred containers this becomes real load on the
Incus daemon itself. 'get' costs exactly one round-trip, for the one
container asked about, no matter how many others exist. Prefer it over
'list --user <name>' for polling loops and any other single-container
lookup.

Examples:
  containarium get alice
  containarium get alice --format json`,
	Args: cobra.ExactArgs(1),
	RunE: runGet,
}

func init() {
	rootCmd.AddCommand(getCmd)
	getCmd.Flags().StringVarP(&containerGetFormat, "format", "f", "table", "Output format: table, json, yaml")
}

func runGet(cmd *cobra.Command, args []string) error {
	username := args[0]

	var info *incus.ContainerInfo
	var err error

	switch {
	case httpMode && serverAddr != "":
		info, err = getRemoteHTTP(username)
	case serverAddr != "":
		info, err = getRemote(username)
	default:
		info, err = getLocal(username)
	}
	if err != nil {
		return fmt.Errorf("failed to get container %q: %w", username, err)
	}
	if info == nil {
		return fmt.Errorf("container %q not found", username)
	}

	containers := []incus.ContainerInfo{*info}
	switch containerGetFormat {
	case "table":
		printTableFormat(containers, boolToCount(info.State == "Running"), boolToCount(info.State != "Running"), false)
	case "json":
		return printJSONFormat(containers)
	case "yaml":
		printYAMLFormat(containers)
	default:
		return fmt.Errorf("unknown format: %s (use: table, json, yaml)", containerGetFormat)
	}
	return nil
}

// boolToCount turns a single container's running/not-running check into the
// running/stopped counts printTableFormat's footer expects, without
// duplicating that footer logic for a one-item list.
func boolToCount(b bool) int {
	if b {
		return 1
	}
	return 0
}

func getLocal(username string) (*incus.ContainerInfo, error) {
	mgr, err := container.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}
	return mgr.Get(username)
}

func getRemote(username string) (*incus.ContainerInfo, error) {
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, err
	}
	defer func() { _ = grpcClient.Close() }()
	return grpcClient.GetContainer(username)
}

func getRemoteHTTP(username string) (*incus.ContainerInfo, error) {
	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return nil, err
	}
	defer func() { _ = httpClient.Close() }()
	return httpClient.GetContainer(username)
}
