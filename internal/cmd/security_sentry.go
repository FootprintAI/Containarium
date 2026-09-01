// `containarium security sentry status` — the background threat-detection
// engine's on/off state and per-rule health (#1640). CLI-first per the repo
// convention; the MCP tool (internal/mcp/security.go) wraps the same
// GetSentryStatus REST call.
package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Continuous threat-detection sentry (background security engine)",
}

var securitySentryCmd = &cobra.Command{
	Use:   "sentry",
	Short: "Threat-detection sentry engine controls",
}

var sentryStatusJSONOut bool

var securitySentryStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the threat-detection sentry's on/off state and per-rule health",
	Long: `Show whether the background threat-detection engine (#1640) is running,
and if not, why: DISABLED (CONTAINARIUM_THREAT_SENTRY unset), UNAVAILABLE
(no eBPF object loaded, or no audit store), DEGRADED (running without
Postgres persistence for findings), or OK.`,
	Args: cobra.NoArgs,
	RunE: runSecuritySentryStatus,
}

// sentryStatusEnvelope mirrors GetSentryStatusResponse's grpc-gateway JSON
// shape (protojson default: camelCase, enums as their string names).
type sentryStatusEnvelope struct {
	State  string             `json:"state"`
	Reason string             `json:"reason"`
	Rules  []sentryRuleStatus `json:"rules"`
}

type sentryRuleStatus struct {
	Rule        string `json:"rule"`
	Healthy     bool   `json:"healthy"`
	LastError   string `json:"lastError"`
	LastErrorAt string `json:"lastErrorAt"`
}

func runSecuritySentryStatus(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	var out sentryStatusEnvelope
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/security/sentry/status"
	if err := getJSON(url, &out); err != nil {
		return err
	}
	if sentryStatusJSONOut {
		return printJSON(out)
	}
	printSentryStatus(cmd.OutOrStdout(), out)
	return nil
}

func printSentryStatus(w interface{ Write([]byte) (int, error) }, out sentryStatusEnvelope) {
	state := strings.TrimPrefix(out.State, "SENTRY_STATE_")
	if state == "" {
		state = "UNSPECIFIED"
	}
	fmt.Fprintf(w, "Sentry: %s\n", state)
	if out.Reason != "" {
		fmt.Fprintf(w, "Reason: %s\n", out.Reason)
	}
	if len(out.Rules) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%-32s %-8s %s\n", "RULE", "HEALTHY", "LAST ERROR")
	for _, r := range out.Rules {
		rule := strings.TrimPrefix(r.Rule, "THREAT_RULE_ID_")
		lastErr := r.LastError
		if lastErr == "" {
			lastErr = "-"
		}
		fmt.Fprintf(w, "%-32s %-8v %s\n", rule, r.Healthy, lastErr)
	}
}

func init() {
	securitySentryStatusCmd.Flags().BoolVar(&sentryStatusJSONOut, "json", false, "Output raw JSON")
	securitySentryCmd.AddCommand(securitySentryStatusCmd)
	securityCmd.AddCommand(securitySentryCmd)
	rootCmd.AddCommand(securityCmd)
}
