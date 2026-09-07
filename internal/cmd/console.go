package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	"github.com/spf13/cobra"
)

var consoleLog bool

var consoleCmd = &cobra.Command{
	Use:   "console <username>",
	Short: "Read a VM instance's boot-time console log",
	Long: `Read a container's console ring-buffer log.

Unlike SSH, this does not require the instance's own network stack or sshd
to be up — it reads the console device the hypervisor exposes, so it works
even when the instance is stuck at BIOS/UEFI POST, hung in the bootloader,
or has panicked before bringing up networking.

Empty output means either the instance is an LXC container (no serial
console device) or a VM that hasn't produced any console output yet.

Live interactive attach (no --log) requires --http with an http(s)://
--server address — it dials a WebSocket, which a plain gRPC endpoint has
no upgrade path for. To detach without killing the instance, press
<ctrl>+a then q (matching Incus's own console command's convention).

Examples:
  containarium console alice --log
  containarium console alice --http --server https://daemon.example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runConsole,
}

func init() {
	rootCmd.AddCommand(consoleCmd)
	consoleCmd.Flags().BoolVar(&consoleLog, "log", false, "Print the console ring-buffer log (currently the only supported mode)")
}

func runConsole(cmd *cobra.Command, args []string) error {
	username := args[0]
	if isCloudTarget(serverAddr, authToken) {
		return errUnsupportedOnCloud("console", "use `containarium connect "+username+"` to inspect the box")
	}
	if !consoleLog {
		return attachConsole(username)
	}

	resp, err := fetchConsoleLog(username)
	if err != nil {
		return err
	}
	if resp.Log == "" {
		fmt.Println("(no console output — this is either an LXC container with no serial console, or a VM that hasn't produced output yet)")
		return nil
	}
	fmt.Print(resp.Log)
	return nil
}

func fetchConsoleLog(username string) (*consoleLogResponse, error) {
	if httpMode && serverAddr != "" {
		httpClient, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP client: %w", err)
		}
		defer func() { _ = httpClient.Close() }()
		resp, err := httpClient.GetConsoleLog(username)
		if err != nil {
			return nil, err
		}
		return &consoleLogResponse{Log: resp.Log}, nil
	}
	if serverAddr != "" {
		grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to remote server: %w", err)
		}
		defer func() { _ = grpcClient.Close() }()
		resp, err := grpcClient.GetConsoleLog(username)
		if err != nil {
			return nil, err
		}
		return &consoleLogResponse{Log: resp.Log}, nil
	}
	return nil, fmt.Errorf("console requires --server (remote daemon): the local-mode CLI does not run against a backend directly")
}

// consoleLogResponse decouples runConsole from the pb type so a future
// live-attach mode can share this command without every caller depending
// on the generated struct's exact shape.
type consoleLogResponse struct {
	Log string
}
