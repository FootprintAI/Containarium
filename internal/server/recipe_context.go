package server

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// contextProfileScript is the login-shell file that carries the context
// directory's env var to later sessions in the box (#3726).
const contextProfileScript = "/etc/profile.d/containarium-context.sh"

// contextSetupScript is the post_start prelude for a recipe that declares a
// context (#3726). It creates ~<box_user>/.containarium/context/<recipe-id>/
// owned by the box user (mode 0755, so a run user can read the files the app
// writes), refuses a symlink at any of the directory's components, exports
// CONTAINARIUM_CONTEXT_DIR for post_start, and writes the same export into a
// profile.d file for later login shells. It returns "" for a recipe that
// declares no context, so such a recipe's post_start is unchanged.
func contextSetupScript(recipe *pb.Recipe, params map[string]string, profilePath string) string {
	if recipe.GetContext() == nil {
		return ""
	}
	user := params[recipes.ContextUserParam]
	var b strings.Builder
	fmt.Fprintf(&b, "ctx_user=%s\n", shellSingleQuote(user))
	b.WriteString("ctx_home=$(getent passwd \"$ctx_user\" | cut -d: -f6)\n")
	b.WriteString("if [ -z \"$ctx_home\" ]; then echo \"context: no home directory for box user $ctx_user\" >&2; exit 1; fi\n")
	b.WriteString("ctx_root=\"$ctx_home/.containarium\"\n")
	fmt.Fprintf(&b, "ctx_dir=\"$ctx_root/context/%s\"\n", recipe.GetId())
	b.WriteString("for ctx_path in \"$ctx_root\" \"$ctx_root/context\" \"$ctx_dir\"; do\n")
	b.WriteString("  if [ -L \"$ctx_path\" ]; then echo \"context: refusing symlink at $ctx_path\" >&2; exit 1; fi\n")
	b.WriteString("  install -d -m 0755 -o \"$ctx_user\" -g \"$ctx_user\" \"$ctx_path\"\n")
	b.WriteString("done\n")
	b.WriteString("export CONTAINARIUM_CONTEXT_DIR=\"$ctx_dir\"\n")
	fmt.Fprintf(&b, "printf '%%s\\n' \"export CONTAINARIUM_CONTEXT_DIR='$ctx_dir'\" > %s\n", shellSingleQuote(profilePath))
	return b.String()
}
