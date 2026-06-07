package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/runner"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/ostype"
	"github.com/spf13/cobra"
)

// Flags for `containarium runner provision`. Kept as package-level
// vars to match the pattern in create.go / delete.go / list.go.
var (
	runnerRepo         string
	runnerPAT          string
	runnerCount        int
	runnerNamePrefix   string
	runnerLabels       string
	runnerNameTemplate string
	runnerSSHKeyPath   string
	runnerSentinelHost string
	runnerSSHUser      string

	// runner list / remove
	runnerListFormat string
)

var runnerCmd = &cobra.Command{
	Use:   "runner",
	Short: "Manage Containarium boxes as GitHub Actions self-hosted runners",
	Long: `Provision, list, and remove Containarium boxes configured as
ephemeral GitHub Actions self-hosted runners.

This is the agent-friendly counterpart to the manual flow documented in
hacks/runner/README.md. The CLI verbs here drive the same install script
(embedded at compile time), so an agent calling ` + "`provision_runners`" + `
via MCP and a human running ` + "`containarium runner provision`" + ` both
end up with provably identical runners.

See ` + "`containarium runner provision --help`" + ` for the most common
entry point.`,
}

var runnerProvisionCmd = &cobra.Command{
	Use:   "provision <repo>",
	Short: "Create N runner boxes and register them as ephemeral GHA runners",
	Long: `Create N Containarium boxes and configure each as an ephemeral
GitHub Actions self-hosted runner for the given repo.

This verb is idempotent: re-running with the same args after a partial
failure is safe. Boxes that already exist are not recreated; boxes that
already have containarium-runner.service installed and enabled are not
re-installed. Agents can call this repeatedly to reconcile state.

Examples:
  # Provision 3 ephemeral runners for footprintai/containarium
  containarium runner provision footprintai/containarium \
      --github-pat ghp_xxxx --count 3

  # Override the prefix (boxes named ci-myrepo-1, -2, -3)
  containarium runner provision footprintai/containarium \
      --github-pat ghp_xxxx --count 3 --name-prefix ci-myrepo

  # Custom labels (workflows target with runs-on: [self-hosted, gpu])
  containarium runner provision footprintai/containarium \
      --github-pat ghp_xxxx --count 2 --labels gpu,containarium`,
	Args: cobra.ExactArgs(1),
	RunE: runRunnerProvision,
}

var runnerListCmd = &cobra.Command{
	Use:   "list <repo>",
	Short: "List provisioned runner boxes and their GitHub registration status",
	Long: `List Containarium boxes whose name starts with --name-prefix and
merge their GitHub-side registration status (online / offline / busy /
unregistered) into a single view.

Read-only.`,
	Args: cobra.ExactArgs(1),
	RunE: runRunnerList,
}

var runnerRemoveCmd = &cobra.Command{
	Use:   "remove <repo> <name>",
	Short: "Drain a runner, deregister it from GitHub, and delete the box",
	Long: `Stop the runner service inside the box (which waits for the in-flight
ephemeral job to finish — this is what "drain" means in the ephemeral
model), deregister the runner from GitHub, then delete the Containarium
box.

GitHub-side deregister is best-effort: if the API call fails, we still
proceed to delete the box so a transient GitHub blip doesn't leak a
box. A stale "offline" row may remain in GitHub's UI; remove it manually
or re-run this command once the API is back.`,
	Args: cobra.ExactArgs(2),
	RunE: runRunnerRemove,
}

func init() {
	rootCmd.AddCommand(runnerCmd)
	runnerCmd.AddCommand(runnerProvisionCmd)
	runnerCmd.AddCommand(runnerListCmd)
	runnerCmd.AddCommand(runnerRemoveCmd)

	// Provision flags.
	runnerProvisionCmd.Flags().StringVar(&runnerPAT, "github-pat", os.Getenv("GH_PAT"), "GitHub PAT with `repo` scope (env: GH_PAT). REQUIRED.")
	runnerProvisionCmd.Flags().IntVar(&runnerCount, "count", 1, "How many runners to provision (1..100)")
	runnerProvisionCmd.Flags().StringVar(&runnerNamePrefix, "name-prefix", "ci-runner", "Prefix for generated box names")
	runnerProvisionCmd.Flags().StringVar(&runnerLabels, "labels", "containarium,ephemeral", "Comma-separated runner labels")
	runnerProvisionCmd.Flags().StringVar(&runnerNameTemplate, "runner-name-template", "{prefix}-{i}", "Template for box names; {prefix} and {i} are substituted")
	runnerProvisionCmd.Flags().StringVar(&runnerSSHKeyPath, "ssh-key", "", "Path to SSH public key used when creating new boxes (default: ~/.ssh/id_rsa.pub)")
	runnerProvisionCmd.Flags().StringVar(&runnerSentinelHost, "sentinel", os.Getenv("CONTAINARIUM_SENTINEL_HOST"), "Sentinel SSH host (env: CONTAINARIUM_SENTINEL_HOST). REQUIRED for the install step.")
	runnerProvisionCmd.Flags().StringVar(&runnerSSHUser, "ssh-user", "", "SSH user to use when SSH'ing into a runner box (default: the runner name, via sshpiper)")

	// List flags.
	runnerListCmd.Flags().StringVar(&runnerPAT, "github-pat", os.Getenv("GH_PAT"), "GitHub PAT with `repo` scope (env: GH_PAT). REQUIRED.")
	runnerListCmd.Flags().StringVar(&runnerNamePrefix, "name-prefix", "ci-runner", "Box name prefix to filter on")
	runnerListCmd.Flags().StringVar(&runnerListFormat, "format", "table", "Output format: table or json")

	// Remove flags. Reuse PAT/sentinel from above.
	runnerRemoveCmd.Flags().StringVar(&runnerPAT, "github-pat", os.Getenv("GH_PAT"), "GitHub PAT with `repo` scope (env: GH_PAT). REQUIRED.")
}

// runRunnerProvision is the cobra handler. Most of the actual
// work lives in runner.Provision; this glue layer's job is to
// turn cobra flags into a runner.Options + Deps and render the
// resulting Result for the human.
func runRunnerProvision(_ *cobra.Command, args []string) error {
	repo := args[0]
	opts := runner.Options{
		Repo:         repo,
		PAT:          runnerPAT,
		Count:        runnerCount,
		NamePrefix:   runnerNamePrefix,
		Labels:       runnerLabels,
		NameTemplate: runnerNameTemplate,
	}
	if err := runner.ValidateOptions(opts); err != nil {
		return err
	}
	if runnerSentinelHost == "" {
		return fmt.Errorf("--sentinel is required (or set CONTAINARIUM_SENTINEL_HOST); the install step needs to SSH into each new box")
	}

	deps, sshKey, err := buildRunnerDeps(runnerSentinelHost, runnerSSHUser)
	if err != nil {
		return err
	}
	// Reuse the operator's existing SSH public key when creating
	// the boxes so the same private key auths the install step.
	opts.SSHKey = sshKey

	fmt.Printf("Provisioning %d runner(s) for %s …\n", opts.Count, opts.Repo)
	res, err := runner.Provision(context.Background(), deps, opts)
	if err != nil {
		return err
	}

	printRunnerTable(res.Runners)
	if res.PartialFailure {
		// Non-zero exit so CI / shell wrappers can detect partial
		// failure without parsing the table.
		return fmt.Errorf("one or more runners failed to provision (see table above)")
	}
	return nil
}

func runRunnerList(_ *cobra.Command, args []string) error {
	repo := args[0]
	deps, _, err := buildRunnerDeps("", "") // list doesn't ssh
	if err != nil {
		return err
	}
	res, err := runner.List(context.Background(), deps, runner.Options{
		Repo:       repo,
		PAT:        runnerPAT,
		NamePrefix: runnerNamePrefix,
	})
	if err != nil {
		return err
	}
	switch runnerListFormat {
	case "table":
		printRunnerTable(res.Runners)
	case "json":
		return printRunnerJSON(res.Runners)
	default:
		return fmt.Errorf("unknown format %q (use: table, json)", runnerListFormat)
	}
	return nil
}

func runRunnerRemove(_ *cobra.Command, args []string) error {
	repo := args[0]
	name := args[1]
	deps, _, err := buildRunnerDeps("", "") // remove doesn't need to ssh (drain handled server-side by --ephemeral)
	if err != nil {
		return err
	}
	st, err := runner.Remove(context.Background(), deps, runner.Options{
		Repo: repo,
		PAT:  runnerPAT,
	}, name)
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s: %s\n", st.Name, st.State)
	if st.LastError != "" {
		fmt.Printf("  note: %s\n", st.LastError)
	}
	return nil
}

// buildRunnerDeps wires the production BoxManager / SSH installer /
// GitHub client. Returns the deps PLUS the public SSH key text
// that will be used to create new boxes (so the caller can pass it
// to runner.Options.SSHKey). Empty sentinel/sshUser means "skip
// the SSH installer" — caller is using list/remove which don't ssh.
func buildRunnerDeps(sentinel, sshUser string) (runner.Deps, string, error) {
	if serverAddr == "" {
		return runner.Deps{}, "", fmt.Errorf("--server is required (runner provision is a daemon-side operation; local-only Incus mode would need a different SSH path)")
	}

	// Pick the daemon API — same gRPC vs HTTP toggle used by
	// create / list / delete elsewhere in the CLI.
	api, creator, err := buildDaemonAPI()
	if err != nil {
		return runner.Deps{}, "", err
	}
	boxes := runner.NewDaemonBoxManager(api, creator)

	deps := runner.Deps{
		Boxes:  boxes,
		GitHub: runner.NewGitHubClient(nil),
	}

	var sshPubKey string
	if sentinel != "" {
		// Read the operator's existing SSH public key (default
		// ~/.ssh/id_rsa.pub) and use it for both directions:
		// the box authorizes that key, and the install step
		// signs with the matching private key.
		pubPath, privPath, err := resolveOperatorSSHKey(runnerSSHKeyPath)
		if err != nil {
			return runner.Deps{}, "", err
		}
		// gosec G304: pubPath comes from a CLI flag the operator
		// passed themselves. The CLI runs as the operator's UID;
		// any file it can open, the operator can already `cat`.
		// Constraining the path would just block legitimate
		// custom-key-location use cases without any real security
		// benefit. (Contrast with internal/mcp/runner_tools.go,
		// where the path IS constrained because the caller may
		// be a different identity than the daemon.)
		pubBytes, err := os.ReadFile(pubPath) // #nosec G304 -- operator-supplied path; CLI runs as operator's UID
		if err != nil {
			return runner.Deps{}, "", fmt.Errorf("read public key %s: %w", pubPath, err)
		}
		sshPubKey = string(pubBytes)

		installer, err := runner.NewSSHInstaller(runner.SSHInstallerConfig{
			Endpoint: runner.SSHEndpointFunc(func(_ context.Context, boxName string) (string, string, error) {
				user := sshUser
				if user == "" {
					// sshpiper routes ssh user "<boxname>"
					// to the right backend box; this is the
					// idiomatic Containarium SSH path.
					user = boxName
				}
				host, port, err := net.SplitHostPort(sentinel)
				if err != nil {
					// No port → default 22.
					host = sentinel
					port = "22"
				}
				return user, net.JoinHostPort(host, port), nil
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

// resolveOperatorSSHKey picks the SSH key pair to use. If the
// caller passed --ssh-key it points at the *public* half (matching
// the convention used by `containarium create --ssh-key`); we
// derive the private path by trimming a trailing .pub. Empty
// falls back to ~/.ssh/id_rsa.pub.
func resolveOperatorSSHKey(pubPathFlag string) (pubPath, privPath string, err error) {
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
		// User didn't give us a .pub path. Be conservative:
		// treat the supplied path as both public and private —
		// they'll get a useful "parse private key" error if
		// it was actually a public key.
		privPath = pubPath
	}
	if _, err := os.Stat(pubPath); err != nil {
		return "", "", fmt.Errorf("ssh public key %s not found (pass --ssh-key or create ~/.ssh/id_rsa.pub): %w", pubPath, err)
	}
	return pubPath, privPath, nil
}

// daemonAPIWrapper adapts an HTTPClient or GRPCClient to the
// runner.DaemonAPI interface. Done as a thin wrapper struct
// (rather than declaring the methods directly on the client
// types, which would be the wrong place for runner-specific
// glue) so the runner package stays decoupled.
type daemonAPIWrapper struct {
	list   func() ([]incus.ContainerInfo, error)
	get    func(string) (*incus.ContainerInfo, error)
	delete func(string, bool) error
}

func (w *daemonAPIWrapper) ListContainers() ([]incus.ContainerInfo, error) { return w.list() }
func (w *daemonAPIWrapper) GetContainer(u string) (*incus.ContainerInfo, error) {
	return w.get(u)
}
func (w *daemonAPIWrapper) DeleteContainer(u string, force bool) error {
	return w.delete(u, force)
}

// buildDaemonAPI returns a runner.DaemonAPI + DaemonCreator
// backed by either the HTTP or gRPC client, mirroring the
// transport toggle elsewhere in the CLI. The creator closure
// captures all the box-shape defaults (small CPU/memory, runner-
// flavored image) so the runner package doesn't have to know
// about them.
func buildDaemonAPI() (runner.DaemonAPI, runner.DaemonCreator, error) {
	if httpMode && serverAddr != "" {
		httpClient, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, nil, fmt.Errorf("http client: %w", err)
		}
		api := &daemonAPIWrapper{
			list:   httpClient.ListContainers,
			get:    httpClient.GetContainer,
			delete: httpClient.DeleteContainer,
		}
		creator := func(_ context.Context, name, sshKey string) (string, string, error) {
			info, err := httpClient.CreateContainer(
				name,
				"images:ubuntu/24.04",
				"4",
				"4GB",
				"50GB",
				splitNonEmpty(sshKey),
				true, // podman
				"",   // stack
				"",   // gpu
				ostype.OSTypeFromString("ubuntu"),
				false,                  // monitoring
				"",                     // pool
				"",                     // backend-id
				client.GitSourceOpts{}, // no git-source for runner boxes
				0,                      // ttl: runner sets its own lifecycle; birth-TTL wiring is #526
				0,                      // idle-stop: runner boxes are long-lived; not auto-slept
			)
			if err != nil {
				return "", "", err
			}
			return info.Name, info.Username, nil
		}
		return api, creator, nil
	}

	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, nil, fmt.Errorf("grpc client: %w", err)
	}
	api := &daemonAPIWrapper{
		list:   grpcClient.ListContainers,
		get:    grpcClient.GetContainer,
		delete: grpcClient.DeleteContainer,
	}
	creator := func(_ context.Context, name, sshKey string) (string, string, error) {
		info, err := grpcClient.CreateContainer(
			name,
			"images:ubuntu/24.04",
			"4",
			"4GB",
			"50GB",
			splitNonEmpty(sshKey),
			true,
			"",
			"",
			ostype.OSTypeFromString("ubuntu"),
			false,
			"",
			"",
			client.GitSourceOpts{}, // no git-source for runner boxes
			0,                      // ttl: runner sets its own lifecycle; birth-TTL wiring is #526
			0,                      // idle-stop: runner boxes are long-lived; not auto-slept
		)
		if err != nil {
			return "", "", err
		}
		return info.Name, info.Username, nil
	}
	return api, creator, nil
}

// splitNonEmpty returns a single-element []string{s} when s is
// non-empty, else nil. The daemon's CreateContainer signature
// wants []string for ssh keys, but the runner orchestrator
// passes the public key as one string.
func splitNonEmpty(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return []string{s}
}

// printRunnerTable renders a compact summary table to stdout.
// Same field set the MCP tool returns as JSON, so the human and
// agent views stay in sync.
func printRunnerTable(runners []runner.RunnerStatus) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATE\tREGISTERED\tNOTE")
	for _, r := range runners {
		registered := "no"
		if r.Registered {
			registered = "yes"
		}
		note := r.LastError
		if note == "" {
			note = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Name, r.State, registered, note)
	}
	_ = w.Flush()
}

// printRunnerJSON emits the result as JSON for scripting.
func printRunnerJSON(runners []runner.RunnerStatus) error {
	// Lightweight inline encoder — avoids pulling in the
	// existing list.go JSON helper which expects []interface{}.
	type row struct {
		Name       string `json:"name"`
		BoxID      string `json:"box_id"`
		State      string `json:"state"`
		Registered bool   `json:"registered"`
		LastError  string `json:"last_error,omitempty"`
	}
	out := make([]row, 0, len(runners))
	for _, r := range runners {
		out = append(out, row{
			Name:       r.Name,
			BoxID:      r.BoxID,
			State:      r.State,
			Registered: r.Registered,
			LastError:  r.LastError,
		})
	}
	return writeJSON(os.Stdout, out)
}

// writeJSON renders v as indented JSON to w with a trailing
// newline. Tiny inline helper rather than pulling in
// internal/list.go's helper, which expects []interface{}.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
