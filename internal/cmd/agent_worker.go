package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// agent_worker.go — start the consumer side of the pull-based run queue
// (prototype). The daemon provisions the skill's box, mints a queue credential
// scoped to agents:run, and launches the in-box runtime in poll mode; the
// worker then leases and runs tasks enqueued with `agent enqueue`.
// See docs/AGENT-MODEL-GATEWAY-DESIGN.md (pull-queue section).

var (
	agentWorkerBackendID string
	agentWorkerPool      string
	agentWorkerID        string
)

var agentWorkerCmd = &cobra.Command{
	Use:   "worker <skill-id>",
	Short: "Start a pull-queue worker box for a skill (prototype)",
	Long: `Provision the skill's box, mint a queue credential (scoped to agents:run,
separate from the skill's in-box token), and launch the in-box runtime in poll
mode. The worker leases tasks for the skill, runs them locally, and reports the
results back — all outbound from the box.

Pair with the producer: enqueue work with 'containarium agent enqueue'.

Examples:
  containarium agent worker hello-agent --server <host>
  containarium agent enqueue hello-agent --input '{"q":"hi"}' --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runAgentWorker,
}

func init() {
	agentCmd.AddCommand(agentWorkerCmd)
	agentWorkerCmd.Flags().StringVar(&agentWorkerBackendID, "backend-id", "",
		"Target backend ID (must be the local backend in the prototype)")
	agentWorkerCmd.Flags().StringVar(&agentWorkerPool, "pool", "",
		"Target pool (not supported in the prototype)")
	agentWorkerCmd.Flags().StringVar(&agentWorkerID, "worker-id", "",
		"Stable worker id for audit/debug (defaults to the box name)")
}

func runAgentWorker(cmd *cobra.Command, args []string) error {
	skillID := args[0]

	c, err := newAgentClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	fmt.Printf("Starting pull-queue worker for skill %q...\n", skillID)
	resp, err := c.StartAgentWorker(skillID, agentWorkerBackendID, agentWorkerPool, agentWorkerID)
	if err != nil {
		return err
	}

	if resp.Container != nil {
		fmt.Printf("\n✓ worker box ready: %s (%s)\n", resp.Container.Name, resp.Container.State)
	}
	fmt.Printf("  worker id: %s\n", resp.WorkerId)
	fmt.Println("  polling for tasks — enqueue with: containarium agent enqueue " + skillID + " --input '{...}'")
	return nil
}
