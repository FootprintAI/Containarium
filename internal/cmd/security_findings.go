// `containarium security findings` — list and resolve security findings
// raised by the threat-detection sentry (#1643). CLI-first per the repo
// convention; the MCP tools (internal/mcp/security.go) wrap the same REST
// calls.
package cmd

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// securitySentryFindingsCmd IS the list command (per the #1643 acceptance
// criterion's literal syntax: `containarium security findings [--severity
// --tenant --since]`), with `resolve` as its only child action — cobra
// dispatches to a subcommand when the first arg matches one, and falls back
// to the parent's own RunE (list) otherwise.
var securitySentryFindingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "List and resolve security findings raised by the threat-detection sentry",
	Long: `Lists security findings raised by the background threat-detection sentry
(#1640-#1642), with evidence. Non-admin callers only see their own tenant.`,
	Args: cobra.NoArgs,
	RunE: runSecurityFindingsList,
}

var (
	findingsSeverity string
	findingsTenant   string
	findingsSince    string
	findingsState    string
	findingsLimit    int
	findingsJSONOut  bool
)

// securitySentryFindingsListCmd is an explicit `list` alias for the parent
// command's default action — some operators expect every noun to have a
// spelled-out verb (matches `security bad-destinations list`'s sibling
// shape); both run the identical RunE.
var securitySentryFindingsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List security findings, most recently seen first (same as `findings` with no subcommand)",
	Args:  cobra.NoArgs,
	RunE:  runSecurityFindingsList,
}

var securitySentryFindingsResolveCmd = &cobra.Command{
	Use:   "resolve <id>",
	Short: "Mark an open finding as resolved",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecurityFindingsResolve,
}

// findingEnvelope mirrors *Finding's grpc-gateway JSON shape (protojson
// default: camelCase, enums as their string names, int64 as a JSON string).
type findingEnvelope struct {
	ID        string             `json:"id"`
	Rule      string             `json:"rule"`
	Severity  string             `json:"severity"`
	TenantID  string             `json:"tenantId"`
	Container string             `json:"container"`
	BackendID string             `json:"backendId"`
	Subject   string             `json:"subject"`
	State     string             `json:"state"`
	Count     string             `json:"count"`
	Evidence  findingEvidenceEnv `json:"evidence"`
	FirstSeen string             `json:"firstSeen"`
	LastSeen  string             `json:"lastSeen"`
}

type findingEvidenceEnv struct {
	Flows  []map[string]interface{} `json:"flows"`
	Denies []map[string]interface{} `json:"denies"`
}

type listFindingsEnvelope struct {
	Findings []findingEnvelope `json:"findings"`
}

type resolveFindingEnvelope struct {
	Finding findingEnvelope `json:"finding"`
}

func runSecurityFindingsList(cmd *cobra.Command, _ []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	q := url.Values{}
	if findingsSeverity != "" {
		q.Set("severity", "THREAT_SEVERITY_"+strings.ToUpper(findingsSeverity))
	}
	if findingsTenant != "" {
		q.Set("tenant_id", findingsTenant)
	}
	if findingsSince != "" {
		q.Set("since", findingsSince)
	}
	if findingsState != "" {
		q.Set("state", "FINDING_STATE_"+strings.ToUpper(findingsState))
	}
	if findingsLimit > 0 {
		q.Set("limit", strconv.Itoa(findingsLimit))
	}
	base := strings.TrimSuffix(serverAddr, "/") + "/v1/security/findings"
	reqURL := base
	if enc := q.Encode(); enc != "" {
		reqURL = base + "?" + enc
	}
	var out listFindingsEnvelope
	if err := getJSON(reqURL, &out); err != nil {
		return err
	}
	if findingsJSONOut {
		return printJSON(out)
	}
	w := cmd.OutOrStdout()
	if len(out.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return nil
	}
	fmt.Fprintf(w, "%-6s %-28s %-10s %-8s %-14s %-6s %-10s %s\n",
		"ID", "RULE", "SEVERITY", "STATE", "TENANT", "COUNT", "LAST SEEN", "SUBJECT")
	for _, f := range out.Findings {
		fmt.Fprintf(w, "%-6s %-28s %-10s %-8s %-14s %-6s %-10s %s\n",
			f.ID,
			strings.TrimPrefix(f.Rule, "THREAT_RULE_ID_"),
			strings.TrimPrefix(f.Severity, "THREAT_SEVERITY_"),
			strings.TrimPrefix(f.State, "FINDING_STATE_"),
			f.TenantID,
			f.Count,
			f.LastSeen,
			f.Subject,
		)
	}
	return nil
}

func runSecurityFindingsResolve(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	id := args[0]
	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		return fmt.Errorf("invalid finding id %q: %w", id, err)
	}
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/security/findings/" + id + "/resolve"
	var out resolveFindingEnvelope
	if err := postJSON(url, []byte("{}"), &out); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Resolved finding %s (%s)\n", out.Finding.ID,
		strings.TrimPrefix(out.Finding.State, "FINDING_STATE_"))
	return nil
}

// addFindingsListFlags registers the --severity/--tenant/--since/--state/
// --limit/--json flag set. Called for both securitySentryFindingsCmd (the
// AC's literal `security findings [--severity ...]` syntax) and
// securitySentryFindingsListCmd (the explicit `list` alias) — both bind the same
// package-level vars, which is safe since only one RunE executes per
// invocation.
func addFindingsListFlags(c *cobra.Command) {
	c.Flags().StringVar(&findingsSeverity, "severity", "", "Filter by severity: low, medium, high, critical")
	c.Flags().StringVar(&findingsTenant, "tenant", "", "Filter by tenant id (admin only; non-admins always see their own tenant)")
	c.Flags().StringVar(&findingsSince, "since", "", "Only findings last seen at or after this RFC3339 timestamp")
	c.Flags().StringVar(&findingsState, "state", "", "Filter by state: open, resolved")
	c.Flags().IntVar(&findingsLimit, "limit", 0, "Max findings to return (default 50, cap 200)")
	c.Flags().BoolVar(&findingsJSONOut, "json", false, "Output raw JSON")
}

func init() {
	addFindingsListFlags(securitySentryFindingsCmd)
	addFindingsListFlags(securitySentryFindingsListCmd)
	securitySentryFindingsCmd.AddCommand(securitySentryFindingsListCmd)
	securitySentryFindingsCmd.AddCommand(securitySentryFindingsResolveCmd)
	securityCmd.AddCommand(securitySentryFindingsCmd)
}
