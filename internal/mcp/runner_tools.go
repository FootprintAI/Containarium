package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/footprintai/containarium/internal/runner"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// runnerToolDescriptions is the MCP-side tool catalog for the
// runner-provision feature. Defined as a function (not a slice
// literal at file scope) so the registration list in tools.go
// can pull it in via runnerTools() — keeps tools.go's slice
// literal length manageable.
//
// Per CLAUDE.md: every tool here is a thin Go wrapper over the
// same function the CLI handler calls (runner.Provision /
// runner.List / runner.Remove in internal/runner). DO NOT make
// these tools talk to a different code path than the CLI does.
func runnerTools() []Tool {
	return []Tool{
		{
			Name: "provision_runners",
			Description: "Provision N Containarium boxes as ephemeral GitHub Actions " +
				"self-hosted runners for a given repo. Each runner registers with " +
				"`[self-hosted, containarium, ephemeral]` labels (overridable). " +
				"Idempotent: re-running with the same args after a partial failure " +
				"is a safe reconcile — boxes that already exist are not recreated, " +
				"and boxes whose containarium-runner.service is already enabled " +
				"are not re-installed.\n\n" +
				"Returns a per-runner status array (name, box_id, state, " +
				"last_error). The top-level partial_failure flag is true when " +
				"any runner failed; the call still succeeds (the per-runner " +
				"detail is the agent's hint for what to retry).\n\n" +
				"State values:\n" +
				"  - provisioned: box created + service installed + GitHub registered\n" +
				"  - registering: install OK, GitHub poll timed out (usually transient)\n" +
				"  - exists:      idempotent re-run — both box and service were already set up\n" +
				"  - failed:      see last_error for the reason\n\n" +
				"This wraps the same code path as `containarium runner provision` " +
				"on the CLI — agents and operators get identical runners.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"repo": map[string]interface{}{
						"type":        "string",
						"description": "GitHub repo in owner/repo format (e.g. footprintai/containarium).",
					},
					"github_pat": map[string]interface{}{
						"type":        "string",
						"description": "GitHub Personal Access Token with `repo` scope. Used both to register the runner and to poll the runners-list API.",
					},
					"count": map[string]interface{}{
						"type":        "integer",
						"description": "Number of runners to provision (1..100). Default 1.",
					},
					"name_prefix": map[string]interface{}{
						"type":        "string",
						"description": "Prefix for generated box names. Default 'ci-runner'.",
					},
					"labels": map[string]interface{}{
						"type":        "string",
						"description": "Comma-separated runner labels. Default 'containarium,ephemeral'.",
					},
					"runner_name_template": map[string]interface{}{
						"type":        "string",
						"description": "Template for box names; {prefix} and {i} are substituted. Default '{prefix}-{i}'.",
					},
					"sentinel": map[string]interface{}{
						"type":        "string",
						"description": "Sentinel SSH host (default $CONTAINARIUM_SENTINEL_HOST). The install step SSHes into each new box through sshpiper at this address.",
					},
					"ssh_key_path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the SSH public key used to create boxes and SSH into them for install. Default ~/.ssh/id_rsa.pub.",
					},
				},
				"required": []string{"repo", "github_pat"},
			},
			Handler: handleProvisionRunners,
		},
		{
			Name: "list_runners",
			Description: "List provisioned runner boxes. Merges the local (boxes whose " +
				"name starts with name_prefix) and GitHub (registered runners) " +
				"views into a single result so the agent can tell at a glance " +
				"whether a box is online, offline, busy, or unregistered.\n\n" +
				"Read-only.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"repo": map[string]interface{}{
						"type":        "string",
						"description": "GitHub repo in owner/repo format.",
					},
					"github_pat": map[string]interface{}{
						"type":        "string",
						"description": "GitHub PAT with `repo` scope.",
					},
					"name_prefix": map[string]interface{}{
						"type":        "string",
						"description": "Box name prefix to filter on. Default 'ci-runner'.",
					},
				},
				"required": []string{"repo", "github_pat"},
			},
			Handler: handleListRunners,
		},
		{
			Name: "remove_runner",
			Description: "Drain, deregister, and delete one runner box. The drain step is " +
				"implicit in the --ephemeral runner model: stopping the systemd unit " +
				"waits for the in-flight job to exit because each iteration of the run " +
				"loop is exactly one job.\n\n" +
				"GitHub-side deregister is best-effort: if the API fails the box is " +
				"still deleted, so a transient github.com blip doesn't leak a box. " +
				"A stale 'offline' row may remain in GitHub's UI; remove it manually " +
				"or re-run once the API recovers.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"repo": map[string]interface{}{
						"type":        "string",
						"description": "GitHub repo in owner/repo format.",
					},
					"github_pat": map[string]interface{}{
						"type":        "string",
						"description": "GitHub PAT with `repo` scope.",
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Box / runner name to remove.",
					},
				},
				"required": []string{"repo", "github_pat", "name"},
			},
			Handler: handleRemoveRunner,
		},
	}
}

// mcpDaemonAPI adapts the MCP HTTP Client to the runner.DaemonAPI
// interface. The MCP client doesn't return incus.ContainerInfo
// directly — we translate from its own Container shape, copying
// over the fields runner.List needs (just Name, in practice).
type mcpDaemonAPI struct{ c *Client }

func (a *mcpDaemonAPI) ListContainers() ([]incus.ContainerInfo, error) {
	resp, err := a.c.ListContainers()
	if err != nil {
		return nil, err
	}
	out := make([]incus.ContainerInfo, 0, len(resp.Containers))
	for _, c := range resp.Containers {
		out = append(out, incus.ContainerInfo{Name: c.Name, State: c.State})
	}
	return out, nil
}

func (a *mcpDaemonAPI) GetContainer(username string) (*incus.ContainerInfo, error) {
	resp, err := a.c.GetContainer(username)
	if err != nil {
		return nil, err
	}
	return &incus.ContainerInfo{Name: resp.Container.Name, State: resp.Container.State}, nil
}

func (a *mcpDaemonAPI) DeleteContainer(username string, force bool) error {
	_, err := a.c.DeleteContainer(username, force)
	return err
}

// buildRunnerDeps wires the production runner.Deps for an MCP
// tool call. Two flavors:
//   - withSSH=true:  full Provision flow (needs sentinel + SSH key)
//   - withSSH=false: List / Remove path (no SSH required)
//
// Per CLAUDE.md: this is the same shape of dependency graph the
// CLI builds in internal/cmd/runner.go — both call into
// internal/runner with the same orchestrator.
func buildMCPRunnerDeps(client *Client, sentinel, sshKeyPath string, withSSH bool) (runner.Deps, string, error) {
	api := &mcpDaemonAPI{c: client}
	creator := func(_ context.Context, name, sshPubKey string) (string, error) {
		req := CreateContainerRequest{
			Username: name,
			Resources: &ResourceLimits{
				CPU:    "4",
				Memory: "4GB",
				Disk:   "50GB",
			},
			Image:        "images:ubuntu/24.04",
			EnablePodman: true,
			SSHKeys:      splitMCPKey(sshPubKey),
		}
		resp, err := client.CreateContainer(req)
		if err != nil {
			return "", err
		}
		return resp.Container.Name, nil
	}
	boxes := runner.NewDaemonBoxManager(api, creator)

	deps := runner.Deps{
		Boxes:  boxes,
		GitHub: runner.NewGitHubClient(nil),
	}

	var sshPubKey string
	if withSSH {
		if sentinel == "" {
			sentinel = client.SentinelHost
		}
		if sentinel == "" {
			return runner.Deps{}, "", fmt.Errorf("sentinel host is required (pass `sentinel` arg or set CONTAINARIUM_SENTINEL_HOST in the MCP env)")
		}
		pubPath, privPath, err := resolveMCPSSHKey(sshKeyPath)
		if err != nil {
			return runner.Deps{}, "", err
		}
		pubBytes, err := os.ReadFile(pubPath)
		if err != nil {
			return runner.Deps{}, "", fmt.Errorf("read ssh public key %s: %w", pubPath, err)
		}
		sshPubKey = string(pubBytes)
		installer, err := runner.NewSSHInstaller(runner.SSHInstallerConfig{
			Endpoint: runner.SSHEndpointFunc(func(_ context.Context, boxName string) (string, string, error) {
				host, port, err := net.SplitHostPort(sentinel)
				if err != nil {
					host = sentinel
					port = "22"
				}
				return boxName, net.JoinHostPort(host, port), nil
			}),
			PrivateKeyPath: privPath,
		})
		if err != nil {
			return runner.Deps{}, "", err
		}
		deps.SSH = installer
	}
	return deps, sshPubKey, nil
}

func splitMCPKey(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return []string{s}
}

// resolveMCPSSHKey picks public + private paths the same way the
// CLI's resolveOperatorSSHKey does. Kept separate (rather than
// importing internal/cmd) to avoid the cmd↔mcp coupling that
// would otherwise creep in.
func resolveMCPSSHKey(pubPathFlag string) (pubPath, privPath string, err error) {
	pubPath = pubPathFlag
	if pubPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", fmt.Errorf("home dir: %w", err)
		}
		pubPath = home + "/.ssh/id_rsa.pub"
	}
	if strings.HasPrefix(pubPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", fmt.Errorf("home dir: %w", err)
		}
		pubPath = home + pubPath[1:]
	}
	privPath = strings.TrimSuffix(pubPath, ".pub")
	if privPath == pubPath {
		privPath = pubPath
	}
	if _, err := os.Stat(pubPath); err != nil {
		return "", "", fmt.Errorf("ssh public key %s not found (pass ssh_key_path arg or create ~/.ssh/id_rsa.pub): %w", pubPath, err)
	}
	return pubPath, privPath, nil
}

// handleProvisionRunners is the MCP-tool entry point. Parses the
// args, builds deps, calls runner.Provision, returns the typed
// result as JSON so the agent has structured fields to reason
// about (not just a human-readable paragraph).
func handleProvisionRunners(client *Client, args map[string]interface{}) (string, error) {
	repo, _ := args["repo"].(string)
	pat, _ := args["github_pat"].(string)
	if repo == "" || pat == "" {
		return "", fmt.Errorf("repo and github_pat are required")
	}
	count := 1
	if n, ok := getIntArg(args, "count"); ok {
		count = n
	}
	opts := runner.Options{
		Repo:         repo,
		PAT:          pat,
		Count:        count,
		NamePrefix:   getStringArg(args, "name_prefix", "ci-runner"),
		Labels:       getStringArg(args, "labels", "containarium,ephemeral"),
		NameTemplate: getStringArg(args, "runner_name_template", "{prefix}-{i}"),
	}
	if err := runner.ValidateOptions(opts); err != nil {
		return "", err
	}

	sentinel := getStringArg(args, "sentinel", "")
	sshKeyPath := getStringArg(args, "ssh_key_path", "")
	deps, sshPubKey, err := buildMCPRunnerDeps(client, sentinel, sshKeyPath, true)
	if err != nil {
		return "", err
	}
	opts.SSHKey = sshPubKey

	res, err := runner.Provision(context.Background(), deps, opts)
	if err != nil {
		return "", err
	}
	return renderRunnerResultJSON(res), nil
}

func handleListRunners(client *Client, args map[string]interface{}) (string, error) {
	repo, _ := args["repo"].(string)
	pat, _ := args["github_pat"].(string)
	if repo == "" || pat == "" {
		return "", fmt.Errorf("repo and github_pat are required")
	}
	deps, _, err := buildMCPRunnerDeps(client, "", "", false)
	if err != nil {
		return "", err
	}
	res, err := runner.List(context.Background(), deps, runner.Options{
		Repo:       repo,
		PAT:        pat,
		NamePrefix: getStringArg(args, "name_prefix", "ci-runner"),
	})
	if err != nil {
		return "", err
	}
	return renderRunnerResultJSON(res), nil
}

func handleRemoveRunner(client *Client, args map[string]interface{}) (string, error) {
	repo, _ := args["repo"].(string)
	pat, _ := args["github_pat"].(string)
	name, _ := args["name"].(string)
	if repo == "" || pat == "" || name == "" {
		return "", fmt.Errorf("repo, github_pat, and name are required")
	}
	deps, _, err := buildMCPRunnerDeps(client, "", "", false)
	if err != nil {
		return "", err
	}
	st, err := runner.Remove(context.Background(), deps, runner.Options{
		Repo: repo, PAT: pat,
	}, name)
	if err != nil {
		return "", err
	}
	out, _ := json.MarshalIndent(st, "", "  ")
	return string(out), nil
}

// renderRunnerResultJSON serializes a runner.Result in the shape
// documented in the tool descriptions: top-level partial_failure
// flag + a runners array of {name, box_id, state, registered,
// last_error}.
func renderRunnerResultJSON(res *runner.Result) string {
	type row struct {
		Name       string `json:"name"`
		BoxID      string `json:"box_id"`
		State      string `json:"state"`
		Registered bool   `json:"registered"`
		LastError  string `json:"last_error,omitempty"`
	}
	rows := make([]row, 0, len(res.Runners))
	for _, r := range res.Runners {
		rows = append(rows, row{
			Name:       r.Name,
			BoxID:      r.BoxID,
			State:      r.State,
			Registered: r.Registered,
			LastError:  r.LastError,
		})
	}
	out := map[string]interface{}{
		"runners":         rows,
		"partial_failure": res.PartialFailure,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b)
}
