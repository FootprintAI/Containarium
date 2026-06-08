package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var recipeGetCmd = &cobra.Command{
	Use:   "get <recipe-id>",
	Short: "Show a recipe's definition",
	Args:  cobra.ExactArgs(1),
	RunE:  runRecipeGet,
}

func init() {
	recipeCmd.AddCommand(recipeGetCmd)
}

func runRecipeGet(cmd *cobra.Command, args []string) error {
	id := args[0]

	var r *pb.Recipe
	var err error
	if serverAddr == "" {
		r, err = recipes.GetDefault().Get(id)
	} else {
		var c recipeAPI
		c, err = newRecipeClient()
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		r, err = c.GetRecipe(id)
	}
	if err != nil {
		return err
	}

	fmt.Printf("ID:          %s\n", r.Id)
	fmt.Printf("Name:        %s\n", r.Name)
	fmt.Printf("Description: %s\n", r.Description)
	fmt.Printf("Image:       %s\n", r.Image)
	fmt.Printf("Requires GPU: %t\n", r.RequiresGpu)
	if r.Resources != nil {
		fmt.Printf("Resources:   cpu=%s memory=%s disk=%s\n",
			r.Resources.Cpu, r.Resources.Memory, r.Resources.Disk)
	}
	for _, p := range r.Ports {
		fmt.Printf("Port:        %d -> %s\n", p.ContainerPort, p.Subdomain)
	}
	for _, v := range r.Volumes {
		fmt.Printf("Volume:      %s at %s\n", v.Name, v.Path)
	}
	for _, p := range r.Parameters {
		req := ""
		if p.Required {
			req = " (required)"
		}
		fmt.Printf("Param:       %s [%s] default=%q%s — %s\n",
			p.Name, p.Type, p.Default, req, p.Description)
	}
	return nil
}
