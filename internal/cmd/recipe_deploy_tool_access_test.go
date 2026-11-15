package cmd

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3679: `containarium recipe deploy --tool-access <level>` sends the level;
// no flag sends none; an unknown level is a flag error before any RPC.
func TestRecipeToolAccess(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    pb.BoxToolAccess
		wantErr bool
	}{
		{"", pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED, false},
		{"build-tools", pb.BoxToolAccess_BOX_TOOL_ACCESS_BUILD_TOOLS, false},
		{"full-sudo", pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO, false},
		{"none", pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE, false},
		{"root", pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED, true},
	} {
		got, err := recipeToolAccess(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("recipeToolAccess(%q) = (%v, %v), want (%v, err=%v)", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestRunRecipeDeploy_UnknownToolAccessFailsBeforeRPC(t *testing.T) {
	prev, prevServer := recipeDeployToolAccess, serverAddr
	t.Cleanup(func() { recipeDeployToolAccess, serverAddr = prev, prevServer })
	recipeDeployToolAccess, serverAddr = "root", ""
	err := runRecipeDeploy(recipeDeployCmd, []string{"slides-agent", "alice"})
	if err == nil {
		t.Fatal("an unknown --tool-access was accepted")
	}
	if got := err.Error(); got == "--server is required" {
		t.Errorf("error is the client's, not the flag's: %v", err)
	}
}
