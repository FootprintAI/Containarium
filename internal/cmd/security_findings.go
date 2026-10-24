// `containarium security findings` — list and resolve security findings
// raised by the threat-detection sentry (#1643). CLI-first per the repo
// convention; the MCP tools (internal/mcp/security.go) wrap the same REST
// calls.
package cmd

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
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

// The list and resolve responses are decoded into the generated
// pb.ListFindingsResponse / pb.ResolveFindingResponse with protojson (the
// grpc-gateway's own encoding), so enums are typed values, never strings
// with a prefix trimmed off (#2768).

// enumLabel is an enum value's name without its type prefix, e.g.
// THREAT_RULE_ID_MINER_SIGNATURE -> MINER_SIGNATURE.
func enumLabel(name, prefix string) string { return strings.TrimPrefix(name, prefix) }

// describeResponse is the one-line text rendering of a response, e.g.
// `response ALERT NONE on box-a, process killed (pid 25872, kills 3)` or
// `response THROTTLE APPLIED on box-b, kill skipped: CONTAINER_INIT` (no
// `on <box>` for a response recorded before it named one).
func describeResponse(r *pb.FindingResponse) string {
	detail := fmt.Sprintf("response %s %s", enumLabel(r.GetAction().String(), "PROCESS_ACTION_"), enumLabel(r.GetState().String(), "RESPONSE_STATE_"))
	if r.GetContainer() != "" {
		detail += " on " + r.GetContainer()
	}
	if r.GetProcessKilled() {
		detail += ", process killed"
		if r.GetKilledPid() != 0 {
			detail += fmt.Sprintf(" (pid %d, kills %d)", r.GetKilledPid(), r.GetKills())
		}
	}
	if r.GetKillSkipReason() != pb.KillSkipReason_KILL_SKIP_REASON_UNSPECIFIED {
		detail += ", kill skipped: " + enumLabel(r.GetKillSkipReason().String(), "KILL_SKIP_REASON_")
	}
	return detail
}

// timestampText renders an optional timestamp as RFC 3339 UTC, "" when unset.
func timestampText(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
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
	var out pb.ListFindingsResponse
	if err := policyRoundTrip(http.MethodGet, reqURL, nil, &out); err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	if findingsJSONOut {
		b, err := protojson.MarshalOptions{Multiline: true}.Marshal(&out)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	}
	if len(out.GetFindings()) == 0 {
		fmt.Fprintln(w, "No findings.")
		return nil
	}
	fmt.Fprintf(w, "%-6s %-28s %-10s %-8s %-14s %-6s %-10s %s\n",
		"ID", "RULE", "SEVERITY", "STATE", "TENANT", "COUNT", "LAST SEEN", "SUBJECT")
	for _, f := range out.GetFindings() {
		fmt.Fprintf(w, "%-6d %-28s %-10s %-8s %-14s %-6d %-10s %s\n",
			f.GetId(),
			enumLabel(f.GetRule().String(), "THREAT_RULE_ID_"),
			enumLabel(f.GetSeverity().String(), "THREAT_SEVERITY_"),
			enumLabel(f.GetState().String(), "FINDING_STATE_"),
			f.GetTenantId(),
			f.GetCount(),
			timestampText(f.GetLastSeen()),
			f.GetSubject(),
		)
		ev := f.GetEvidence()
		for _, c := range ev.GetConfigs() {
			detail := fmt.Sprintf("%s=%s in %s", c.GetDirective(), c.GetValue(), c.GetPath())
			if c.GetRemediated() {
				detail += " (re-asserted)"
			}
			if c.GetNote() != "" {
				detail += " — " + c.GetNote()
			}
			fmt.Fprintf(w, "       %s\n", detail)
		}
		for _, x := range ev.GetExecs() {
			detail := fmt.Sprintf("exec pid %d %s (comm %s) argv %q", x.GetPid(), x.GetFilename(), x.GetComm(), x.GetArgv())
			if x.GetSha256() != "" {
				detail += " sha256 " + x.GetSha256()
			}
			if x.GetMatched() != "" {
				detail += " — matched " + x.GetMatched()
			}
			fmt.Fprintf(w, "       %s\n", detail)
		}
		if r := f.GetResponse(); r != nil {
			fmt.Fprintf(w, "       %s\n", describeResponse(r))
		}
		for _, l := range ev.GetListeners() {
			detail := fmt.Sprintf("ssh listener %s:%d pid %d %s", l.GetBindAddress(), l.GetPort(), l.GetPid(), l.GetBinary())
			if l.GetNote() != "" {
				detail += " — " + l.GetNote()
			}
			fmt.Fprintf(w, "       %s\n", detail)
		}
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
	var out pb.ResolveFindingResponse
	if err := policyRoundTrip(http.MethodPost, url, nil, &out); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Resolved finding %d (%s)\n", out.GetFinding().GetId(),
		enumLabel(out.GetFinding().GetState().String(), "FINDING_STATE_"))
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
