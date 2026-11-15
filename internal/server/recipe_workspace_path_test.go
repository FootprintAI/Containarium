package server

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/toolaccess"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// workspaceBoxes models the two lookups a workspace needs (#3679): the box
// user's home (getent passwd) and the run user's provisioning script, which
// prints the run user's home. It records the tool-access config writes, the
// order of events, and the post_start script.
type workspaceBoxes struct {
	*fakeRecipeBoxes
	mu         sync.Mutex
	order      []string
	configSets map[string]string
	script     string
	toolAccess string // recorded level Get reports (rerun path)
	pending    bool
}

func (b *workspaceBoxes) ExecWithOutput(_ string, command []string) (string, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case len(command) == 3 && command[0] == "getent" && command[1] == "passwd":
		b.order = append(b.order, "getent "+command[2])
		return command[2] + ":x:1000:1000::/home/" + command[2] + ":/bin/bash\n", "", nil
	case len(command) == 3 && command[0] == "bash" && strings.Contains(command[2], "useradd"):
		b.order = append(b.order, "provision run user")
		return "/home/" + toolaccess.RunUser + "\n", "", nil
	}
	return b.fakeRecipeBoxes.ExecWithOutput("", command)
}

func (b *workspaceBoxes) ExecWithExitCode(name string, command []string) (string, string, int, error) {
	b.mu.Lock()
	b.order = append(b.order, "post_start")
	if len(command) == 3 {
		b.script = command[2]
	}
	b.mu.Unlock()
	return b.fakeRecipeBoxes.ExecWithExitCode(name, command)
}

func (b *workspaceBoxes) SetConfig(name, key, value string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.configSets == nil {
		b.configSets = map[string]string{}
	}
	b.configSets[name+" "+key] = value
	if key == incus.ToolAccessKey {
		b.order = append(b.order, "set tool_access")
	}
	return nil
}

func (b *workspaceBoxes) Get(string) (*incus.ContainerInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return &incus.ContainerInfo{ToolAccess: b.toolAccess, PostStartPending: b.pending}, nil
}

func (b *workspaceBoxes) UnsetConfig(string, string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pending = false
	return nil
}

func (b *workspaceBoxes) snapshot() (order []string, script string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.order...), b.script
}

const workspaceRecipeYAML = `recipes:
  - id: ws
    image: x
    workspace_dir: slides
    parameters:
      - name: box_user
        label: Box user
        type: string
        default: ubuntu
    post_start:
      - echo deck
  - id: plain
    image: x
    post_start:
      - echo plain
`

func newWorkspaceServer(t *testing.T) (*RecipeServer, *workspaceBoxes) {
	t.Helper()
	catalog := recipes.New()
	if err := catalog.LoadFromBytes([]byte(workspaceRecipeYAML)); err != nil {
		t.Fatal(err)
	}
	boxes := &workspaceBoxes{fakeRecipeBoxes: &fakeRecipeBoxes{}}
	return &RecipeServer{catalog: catalog, boxes: boxes}, boxes
}

// Without a run user the workspace stays in the box user's home (~/slides)
// and the deploy reports that absolute path (#3679).
func TestDeployRecipe_WorkspacePath_NoRunUser(t *testing.T) {
	srv, boxes := newWorkspaceServer(t)
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	resp, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{RecipeId: "ws", Name: "alice"})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got := resp.GetWorkspacePath(); got != "/home/ubuntu/slides" {
		t.Errorf("workspace_path = %q, want /home/ubuntu/slides", got)
	}
	order, script := boxes.snapshot()
	if _, ok := boxes.configSets["alice-container "+incus.ToolAccessKey]; ok {
		t.Error("no tool_access requested, but a level was recorded")
	}
	for _, o := range order {
		if o == "provision run user" {
			t.Error("no run user configured, but the run user was provisioned")
		}
	}
	for _, want := range []string{
		"export CONTAINARIUM_WORKSPACE_USER='ubuntu'\n",
		"export CONTAINARIUM_WORKSPACE_PATH='/home/ubuntu/slides'\n",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("post_start script missing %q:\n%s", want, script)
		}
	}
}

// With a run user configured (a tool-access level requested at deploy), the
// level is recorded and the run user provisioned BEFORE post_start, and the
// workspace is the run user's <home>/slides, exported to post_start as the
// owner and path and reported to the caller (#3679).
func TestDeployRecipe_WorkspacePath_RunUser(t *testing.T) {
	srv, boxes := newWorkspaceServer(t)
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	resp, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{
		RecipeId: "ws", Name: "alice", ToolAccess: pb.BoxToolAccess_BOX_TOOL_ACCESS_BUILD_TOOLS,
	})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	want := "/home/" + toolaccess.RunUser + "/slides"
	if got := resp.GetWorkspacePath(); got != want {
		t.Errorf("workspace_path = %q, want %q", got, want)
	}
	if got := boxes.configSets["alice-container "+incus.ToolAccessKey]; got != incus.ToolAccessBuildTools {
		t.Errorf("recorded tool_access = %q, want %q", got, incus.ToolAccessBuildTools)
	}
	order, script := boxes.snapshot()
	if got := strings.Join(order, ","); got != "set tool_access,provision run user,post_start" {
		t.Errorf("order = %s, want set tool_access,provision run user,post_start", got)
	}
	for _, w := range []string{
		"export CONTAINARIUM_WORKSPACE_USER='" + toolaccess.RunUser + "'\n",
		"export CONTAINARIUM_WORKSPACE_PATH='" + want + "'\n",
	} {
		if !strings.Contains(script, w) {
			t.Errorf("post_start script missing %q:\n%s", w, script)
		}
	}
}

// An async deploy reports the path too: it is resolved before post_start.
func TestDeployRecipe_WorkspacePath_Async(t *testing.T) {
	srv, boxes := newWorkspaceServer(t)
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	resp, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{
		RecipeId: "ws", Name: "alice", Async: true, ToolAccess: pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE,
	})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got, want := resp.GetWorkspacePath(), "/home/"+toolaccess.RunUser+"/slides"; got != want {
		t.Errorf("workspace_path = %q, want %q", got, want)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, script := boxes.snapshot(); script != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("async post_start never ran")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A recipe with no workspace reports none and exports none.
func TestDeployRecipe_WorkspacePath_NoWorkspace(t *testing.T) {
	srv, boxes := newWorkspaceServer(t)
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	resp, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{RecipeId: "plain", Name: "alice"})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got := resp.GetWorkspacePath(); got != "" {
		t.Errorf("workspace_path = %q, want empty", got)
	}
	if _, script := boxes.snapshot(); strings.Contains(script, "CONTAINARIUM_WORKSPACE_") {
		t.Errorf("a recipe without a workspace must export none:\n%s", script)
	}
}

// An unknown tool_access value refuses the deploy before any box exists.
func TestDeployRecipe_UnknownToolAccessRefused(t *testing.T) {
	srv, boxes := newWorkspaceServer(t)
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	if _, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{RecipeId: "ws", Name: "alice", ToolAccess: 99}); err == nil {
		t.Fatal("deploy with an unknown tool_access succeeded")
	}
	if len(boxes.created) != 0 {
		t.Errorf("a refused deploy created %v", boxes.created)
	}
}

// Re-running a pending post_start on a box whose level is recorded puts the
// workspace in the run user's home again, not the box user's (#3679).
func TestRerunPendingPostStart_WorkspaceFollowsRecordedRunUser(t *testing.T) {
	srv, boxes := newWorkspaceServer(t)
	boxes.toolAccess = incus.ToolAccessFullSudo
	boxes.pending = true
	if _, err := srv.rerunPendingPostStart(tenantWithScopes("alice"), "ws", "alice", nil); err != nil {
		t.Fatalf("rerun: %v", err)
	}
	_, script := boxes.snapshot()
	if want := "export CONTAINARIUM_WORKSPACE_PATH='/home/" + toolaccess.RunUser + "/slides'\n"; !strings.Contains(script, want) {
		t.Errorf("post_start script missing %q:\n%s", want, script)
	}
}
