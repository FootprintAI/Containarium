package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	agentProvisionBoxBackendID string
	agentProvisionBoxPool      string
)

var agentProvisionBoxCmd = &cobra.Command{
	Use:   "provision-box <skill-id>",
	Short: "Provision a skill's box ahead of any run, with no model call",
	Long: `Creates or reuses the skill's deterministic box (agent-<skill-id>)
WITHOUT running it: no token is minted, nothing is seeded, and the model is
never called.

This exists so a crew member's box can be made to exist, and a human can
sign in to its coding agent, BEFORE any inference credential does.
'agent run'/crew runs are otherwise the only path that creates this box, and
both require a credential just to get that far — this breaks that
chicken-and-egg.

Typical flow:
  containarium agent provision-box engineer-crew-member --server <host>
  containarium connect agent-engineer-crew-member
  claude   # (or codex) — complete the device-code sign-in, once
  containarium agent credential-status engineer-crew-member --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runAgentProvisionBox,
}

func init() {
	agentCmd.AddCommand(agentProvisionBoxCmd)
	agentProvisionBoxCmd.Flags().StringVar(&agentProvisionBoxBackendID, "backend-id", "",
		"Target backend ID (must be the local backend in v1)")
	agentProvisionBoxCmd.Flags().StringVar(&agentProvisionBoxPool, "pool", "",
		"Target pool (not supported in v1)")
}

func runAgentProvisionBox(cmd *cobra.Command, args []string) error {
	skillID := args[0]

	c, err := newAgentClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	fmt.Printf("Provisioning box for skill %q (no credential needed, no model call)...\n", skillID)
	resp, err := c.ProvisionSkillBox(skillID, agentProvisionBoxBackendID, agentProvisionBoxPool)
	if err != nil {
		return err
	}

	boxName := resp.GetContainer().GetName()
	if resp.GetContainer() != nil {
		verb := "reused"
		if resp.GetFreshlyProvisioned() {
			verb = "created"
		}
		fmt.Printf("\n✓ box %s: %s (%s)\n", verb, boxName, resp.GetContainer().GetState())
	}
	if boxName != "" {
		fmt.Printf("\nNext: `containarium connect %s` and sign in to the coding agent interactively (e.g. `claude`).\n", boxName)
	}
	return nil
}
