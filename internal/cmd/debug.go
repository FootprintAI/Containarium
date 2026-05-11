package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var debugFormat string

var debugCmd = &cobra.Command{
	Use:   "debug <username>",
	Short: "Diagnose a container's SSH path",
	Long: `Inspect backend-local state for a container to explain SSH failures.

Returns a structured report covering:
  - container runtime state (running / stopped / missing)
  - host /etc/passwd entry for the username
  - whether the user's shell wrapper exists on the backend
  - recent sshd journal lines mentioning this user
  - a likely_cause + ordered next_actions list

Use --format json to get a machine-readable report. The same diagnostic is
exposed to AI agents as the debug_container MCP tool.

Examples:
  containarium debug alice
  containarium debug alice --format json`,
	Args: cobra.ExactArgs(1),
	RunE: runDebug,
}

func init() {
	rootCmd.AddCommand(debugCmd)
	debugCmd.Flags().StringVarP(&debugFormat, "format", "f", "human", "Output format: human | json")
}

func runDebug(cmd *cobra.Command, args []string) error {
	username := args[0]

	report, err := fetchDebugReport(username)
	if err != nil {
		return err
	}

	switch debugFormat {
	case "json":
		buf, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(buf))
	default:
		printDebugReportHuman(username, report)
	}
	return nil
}

func fetchDebugReport(username string) (*pb.DebugContainerResponse, error) {
	if httpMode && serverAddr != "" {
		httpClient, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP client: %w", err)
		}
		defer httpClient.Close()
		return httpClient.DebugContainer(username)
	}
	if serverAddr != "" {
		grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to remote server: %w", err)
		}
		defer grpcClient.Close()
		return grpcClient.DebugContainer(username)
	}
	return nil, fmt.Errorf("debug requires --server (remote daemon): the local-mode CLI does not run the diagnostic logic")
}

func printDebugReportHuman(username string, r *pb.DebugContainerResponse) {
	fmt.Printf("=== Debug report for %q ===\n\n", username)
	fmt.Printf("Container state:        %s\n", valueOrDash(r.ContainerState))
	fmt.Printf("Host user exists:       %t\n", r.HostUserExists)
	if r.HostUserShell != "" {
		fmt.Printf("Host user shell:        %s (exists: %t)\n", r.HostUserShell, r.HostUserShellExists)
	}

	if len(r.RecentSshdRejections) > 0 {
		fmt.Println()
		fmt.Println("Recent sshd journal lines:")
		for _, line := range r.RecentSshdRejections {
			fmt.Printf("  %s\n", line)
		}
	}

	fmt.Println()
	fmt.Printf("Likely cause: %s\n", valueOrDash(r.LikelyCause))

	if len(r.NextActions) > 0 {
		fmt.Println()
		fmt.Println("Next actions:")
		for i, action := range r.NextActions {
			fmt.Printf("  %d. %s\n", i+1, action)
		}
	}
}

func valueOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
