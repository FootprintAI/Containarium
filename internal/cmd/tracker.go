package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// Tracker connections — where a tenant's issue tracker is, and which
// broker-only secret holds the credential the daemon uses to reach it
// (#1921). The credential never enters a box; only its name (a secret
// already set with `secrets set --delivery broker`) is accepted
// here. See docs/architecture/agent-tracker-broker.md.
//
// Remote-only, same reasoning as `secrets`: the daemon owns the
// Postgres connection this is stored in.
//
// Connection CRUD requires tracker:admin on the token — separate from
// the tracker:read / tracker:write scopes an agent's run gets for the
// tracker verbs themselves (#1922), which cannot repoint a connection.

var trackerCmd = &cobra.Command{
	Use:   "tracker",
	Short: "Manage tracker connections (GitHub/GitLab, broker-only credential)",
	Long: `Register where a tenant's issue tracker is and which broker-only
secret holds its credential, so agent runs can be granted tracker
access (#1922) without any box ever holding the credential.

See docs/architecture/agent-tracker-broker.md.`,
}

var trackerConnectCmd = &cobra.Command{
	Use:   "connect <username> <name>",
	Short: "Create or update a tracker connection",
	Long: `Idempotent — repeated calls with the same (username, name) replace
the connection's fields. --credential-secret must already name a
secret owned by username in broker-only delivery mode:

  containarium secrets set alice GH_TOKEN ghp_... --delivery broker
  containarium tracker connect alice default \
    --provider github --project acme/widgets --credential-secret GH_TOKEN

Referencing a secret in any other delivery mode is rejected — a
tracker connection must never point at a secret a box can also read.`,
	Args: cobra.ExactArgs(2),
	RunE: runTrackerConnect,
}

var trackerListCmd = &cobra.Command{
	Use:   "list <username>",
	Short: "List a tenant's tracker connections",
	Args:  cobra.ExactArgs(1),
	RunE:  runTrackerList,
}

var trackerDisconnectCmd = &cobra.Command{
	Use:     "disconnect <username> <name>",
	Aliases: []string{"rm", "remove", "delete"},
	Short:   "Remove a tracker connection",
	Long:    `Removes the named connection. Does NOT delete the credential secret it referenced.`,
	Args:    cobra.ExactArgs(2),
	RunE:    runTrackerDisconnect,
}

var (
	trackerProvider         string
	trackerBaseURL          string
	trackerProject          string
	trackerCredentialSecret string
)

func init() {
	rootCmd.AddCommand(trackerCmd)

	trackerCmd.AddCommand(trackerConnectCmd)
	trackerConnectCmd.Flags().StringVar(&trackerProvider, "provider", "",
		`Tracker provider: "github" or "gitlab". Required.`)
	trackerConnectCmd.Flags().StringVar(&trackerBaseURL, "base-url", "",
		`Empty selects the provider's SaaS endpoint (github.com / gitlab.com). `+
			`Set for GitHub Enterprise Server or self-managed GitLab.`)
	trackerConnectCmd.Flags().StringVar(&trackerProject, "project", "",
		`"owner/repo" (GitHub) or "group/subgroup/project" (GitLab). Required.`)
	trackerConnectCmd.Flags().StringVar(&trackerCredentialSecret, "credential-secret", "",
		`Name of a secret owned by username, in broker-only delivery mode. Required.`)

	trackerCmd.AddCommand(trackerListCmd)
	trackerCmd.AddCommand(trackerDisconnectCmd)
}

// parseTrackerProvider maps the CLI's --provider flag to the proto enum.
// Unlike --protocol elsewhere in this package, there is no default —
// provider is never inferred, per the design note (a self-managed host
// named "git.<company>" can be either product).
func parseTrackerProvider(s string) (pb.TrackerProvider, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "github":
		return pb.TrackerProvider_TRACKER_PROVIDER_GITHUB, nil
	case "gitlab":
		return pb.TrackerProvider_TRACKER_PROVIDER_GITLAB, nil
	default:
		return pb.TrackerProvider_TRACKER_PROVIDER_UNSPECIFIED, fmt.Errorf(`--provider must be "github" or "gitlab", got %q`, s)
	}
}

func runTrackerConnect(cmd *cobra.Command, args []string) error {
	username, name := args[0], args[1]
	if serverAddr == "" {
		return fmt.Errorf("--server is required for tracker commands (daemon owns the connection store)")
	}
	provider, err := parseTrackerProvider(trackerProvider)
	if err != nil {
		return err
	}
	if trackerProject == "" {
		return fmt.Errorf("--project is required")
	}
	if trackerCredentialSecret == "" {
		return fmt.Errorf("--credential-secret is required")
	}

	req := &pb.SetTrackerConnectionRequest{
		Username:         username,
		Name:             name,
		Provider:         provider,
		BaseUrl:          trackerBaseURL,
		Project:          trackerProject,
		CredentialSecret: trackerCredentialSecret,
	}

	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		_, msg, err := h.SetTrackerConnection(req)
		if err != nil {
			return err
		}
		fmt.Printf("✓ %s\n", msg)
		return nil
	}
	g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer func() { _ = g.Close() }()
	_, msg, err := g.SetTrackerConnection(req)
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s\n", msg)
	return nil
}

func runTrackerList(cmd *cobra.Command, args []string) error {
	username := args[0]
	if serverAddr == "" {
		return fmt.Errorf("--server is required for tracker commands")
	}

	var list []*pb.TrackerConnection
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		if list, err = h.ListTrackerConnections(username); err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		if list, err = g.ListTrackerConnections(username); err != nil {
			return err
		}
	}

	if len(list) == 0 {
		fmt.Printf("(no tracker connections for %s)\n", username)
		return nil
	}
	fmt.Printf("%-16s %-8s %-24s %s\n", "NAME", "PROVIDER", "PROJECT", "CREDENTIAL SECRET")
	for _, c := range list {
		fmt.Printf("%-16s %-8s %-24s %s\n", c.GetName(), trackerProviderLabel(c.GetProvider()), c.GetProject(), c.GetCredentialSecret())
	}
	return nil
}

func runTrackerDisconnect(cmd *cobra.Command, args []string) error {
	username, name := args[0], args[1]
	if serverAddr == "" {
		return fmt.Errorf("--server is required for tracker commands")
	}

	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		msg, err := h.DeleteTrackerConnection(username, name)
		if err != nil {
			return err
		}
		fmt.Printf("✓ %s\n", msg)
		return nil
	}
	g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer func() { _ = g.Close() }()
	msg, err := g.DeleteTrackerConnection(username, name)
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s\n", msg)
	return nil
}

// trackerProviderLabel renders the enum for the list table without the
// TRACKER_PROVIDER_ prefix.
func trackerProviderLabel(p pb.TrackerProvider) string {
	switch p {
	case pb.TrackerProvider_TRACKER_PROVIDER_GITHUB:
		return "github"
	case pb.TrackerProvider_TRACKER_PROVIDER_GITLAB:
		return "gitlab"
	default:
		return "unspecified"
	}
}
