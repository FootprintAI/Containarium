package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var (
	recipeDeployGPU       string
	recipeDeployBackendID string
	recipeDeployPool      string
	recipeDeployParams    []string
)

var recipeDeployCmd = &cobra.Command{
	Use:   "deploy <recipe-id> <name>",
	Short: "Deploy a recipe as a new dedicated container",
	Long: `Provision a new dedicated container from a recipe, run the recipe's
image inside it, and expose its ports.

In v1 the recipe deploys on the backend that --server points at. To deploy on
a GPU node, point --server at that node's daemon and pass --gpu.

Examples:
  containarium recipe deploy ollama ol1 --gpu 0 --param model=llama3 --server <host>
  containarium recipe deploy llamacpp lc1 --gpu 0 --param hf_repo=ggml-org/gemma-3-1b-it-GGUF --server <host>`,
	Args: cobra.ExactArgs(2),
	RunE: runRecipeDeploy,
}

func init() {
	recipeCmd.AddCommand(recipeDeployCmd)
	recipeDeployCmd.Flags().StringVar(&recipeDeployGPU, "gpu", "",
		"GPU device ID for passthrough (e.g. '0'); required for GPU recipes")
	recipeDeployCmd.Flags().StringVar(&recipeDeployBackendID, "backend-id", "",
		"Target backend ID (must be the local backend in v1)")
	recipeDeployCmd.Flags().StringVar(&recipeDeployPool, "pool", "",
		"Target pool (not supported in v1)")
	recipeDeployCmd.Flags().StringArrayVar(&recipeDeployParams, "param", nil,
		"Recipe parameter as key=value (repeatable)")
}

func runRecipeDeploy(cmd *cobra.Command, args []string) error {
	recipeID, name := args[0], args[1]

	params, err := parseKeyValues(recipeDeployParams)
	if err != nil {
		return err
	}

	c, err := newRecipeClient()
	if err != nil {
		return err
	}
	defer c.Close()

	fmt.Printf("Deploying recipe %q as %q...\n", recipeID, name)
	resp, err := c.DeployRecipe(recipeID, name, recipeDeployGPU, recipeDeployBackendID, recipeDeployPool, params)
	if err != nil {
		return err
	}

	fmt.Printf("\n✓ %s\n", resp.Message)
	if resp.Url != "" {
		fmt.Printf("  URL: %s\n", resp.Url)
	}
	if resp.Container != nil {
		fmt.Printf("  Container: %s (%s)\n", resp.Container.Name, resp.Container.State)
	}
	return nil
}

// parseKeyValues parses repeated "key=value" flags into a map.
func parseKeyValues(pairs []string) (map[string]string, error) {
	out := map[string]string{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid parameter %q (expected key=value)", p)
		}
		out[k] = v
	}
	return out, nil
}
