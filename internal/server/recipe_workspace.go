package server

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/toolaccess"
	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// recipeWorkspace is the workspace a recipe keeps for its agent
// (Recipe.workspace_dir, #3679): its owner and absolute path on the box. The
// zero value is "no workspace".
type recipeWorkspace struct {
	user string
	path string
}

// env is the post_start export snippet for the workspace, "" for none.
func (w recipeWorkspace) env() string {
	if w.path == "" {
		return ""
	}
	return "export CONTAINARIUM_WORKSPACE_USER=" + shellSingleQuote(w.user) + "\n" +
		"export CONTAINARIUM_WORKSPACE_PATH=" + shellSingleQuote(w.path) + "\n"
}

// resolveRecipeWorkspace decides where a recipe's workspace lives before its
// post_start runs (#3679). With a run user configured (a tool-access level
// recorded on the box) it is the run user's <home>/<workspace_dir>; the run
// user is provisioned here, as a platform run would, so its home exists. Else
// it is the box user's (the box_user parameter) <home>/<workspace_dir>, which
// is ~/<workspace_dir> exactly as before. A recipe with no workspace_dir has
// none. post_start creates the directory and owns it to the user returned.
func resolveRecipeWorkspace(boxes recipeBoxes, recipe *pb.Recipe, containerName string, params map[string]string, runUser bool) (recipeWorkspace, error) {
	dir := recipe.GetWorkspaceDir()
	if dir == "" {
		return recipeWorkspace{}, nil
	}
	if runUser {
		rootExec := func(box, script string) (string, error) {
			out, stderr, err := boxes.ExecWithOutput(box, []string{"bash", "-c", script})
			if err != nil {
				return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr))
			}
			return out, nil
		}
		home, err := provisionBoxRunUser(rootExec, containerName)
		if err != nil {
			return recipeWorkspace{}, err
		}
		return recipeWorkspace{user: toolaccess.RunUser, path: home + "/" + dir}, nil
	}
	user := params[recipes.WorkspaceOwnerParam]
	if user == "" {
		return recipeWorkspace{}, fmt.Errorf("recipe %q has a workspace but no %s", recipe.GetId(), recipes.WorkspaceOwnerParam)
	}
	out, _, err := boxes.ExecWithOutput(containerName, []string{"getent", "passwd", user})
	if err != nil {
		return recipeWorkspace{}, fmt.Errorf("look up the home of %q: %w", user, err)
	}
	fields := strings.Split(strings.TrimSpace(out), ":")
	if len(fields) < 7 || !validHomePath(fields[5]) {
		return recipeWorkspace{}, fmt.Errorf("user %q has no usable home on the box", user)
	}
	return recipeWorkspace{user: user, path: fields[5] + "/" + dir}, nil
}
