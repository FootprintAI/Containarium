package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var recipeListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List available recipes",
	Long: `List built-in recipes. Reads the embedded catalog when no --server is
given, or the daemon's catalog when --server is set.`,
	Args: cobra.NoArgs,
	RunE: runRecipeList,
}

func init() {
	recipeCmd.AddCommand(recipeListCmd)
}

func runRecipeList(cmd *cobra.Command, args []string) error {
	var list []*pb.Recipe
	if serverAddr == "" {
		// Offline: the catalog is compiled into the CLI binary too.
		list = recipes.GetDefault().List()
	} else {
		c, err := newRecipeClient()
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		list, err = c.ListRecipes()
		if err != nil {
			return err
		}
	}

	if len(list) == 0 {
		fmt.Println("No recipes available.")
		return nil
	}
	fmt.Printf("%-12s %-10s %-30s %s\n", "ID", "GPU", "IMAGE", "DESCRIPTION")
	fmt.Println(strings.Repeat("-", 90))
	for _, r := range list {
		gpu := "no"
		if r.RequiresGpu {
			gpu = "required"
		}
		fmt.Printf("%-12s %-10s %-30s %s\n", r.Id, gpu, r.Image, r.Description)
	}
	return nil
}
