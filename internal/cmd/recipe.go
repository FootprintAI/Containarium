package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var recipeCmd = &cobra.Command{
	Use:   "recipe",
	Short: "Deploy declarative GPU/app recipes (ollama, llama.cpp, …)",
	Long: `Recipes are one-command deployments of GPU/app workloads onto a
Containarium backend. A recipe provisions a new dedicated container and runs
its image inside it, then exposes the configured ports.

  containarium recipe list
  containarium recipe get ollama
  containarium recipe deploy ollama ol1 --gpu 0 --param model=llama3 --server <host>`,
}

func init() {
	rootCmd.AddCommand(recipeCmd)
}

// recipeAPI is the subset of the typed client used by recipe commands. Both
// the gRPC and HTTP clients satisfy it, so commands dispatch on --http without
// duplicating method calls.
type recipeAPI interface {
	ListRecipes() ([]*pb.Recipe, error)
	GetRecipe(id string) (*pb.Recipe, error)
	DeployRecipe(recipeID, name, gpu, backendID, pool string, params map[string]string) (*pb.DeployRecipeResponse, error)
	GetWorkspaceAccess(name string) (*pb.GetWorkspaceAccessResponse, error)
	Close() error
}

// newRecipeClient returns a recipe-capable client for the configured server.
func newRecipeClient() (recipeAPI, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}
