// `containarium bridge-dns status` — whether the bridge DNS record that
// resolves the app-hosting base domain to core-caddy matches core-caddy's live
// address (#2188). CLI-first per the repo convention; the MCP tool
// (internal/mcp/bridge_dns.go) wraps the same GetBridgeDNSStatus REST call.
package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

var bridgeDNSCmd = &cobra.Command{
	Use:   "bridge-dns",
	Short: "Bridge DNS record for the app-hosting base domain",
}

var bridgeDNSStatusJSONOut bool

var bridgeDNSStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether the bridge DNS record matches core-caddy's live address",
	Args:  cobra.NoArgs,
	RunE:  runBridgeDNSStatus,
}

// bridgeDNSStatusEnvelope mirrors GetBridgeDNSStatusResponse's grpc-gateway JSON
// shape (protojson default: camelCase, enums as their string names).
type bridgeDNSStatusEnvelope struct {
	State       string `json:"state"`
	Reason      string `json:"reason"`
	Bridge      string `json:"bridge"`
	CaddyIP     string `json:"caddyIp"`
	Desired     string `json:"desired"`
	Current     string `json:"current"`
	LastError   string `json:"lastError"`
	DriftCount  int    `json:"driftCount"`
	LastPass    string `json:"lastPass"`
	LastApplied string `json:"lastApplied"`
	LastAction  string `json:"lastAction"`
	CreatedAt   string `json:"createdAt"`
}

func runBridgeDNSStatus(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	var out bridgeDNSStatusEnvelope
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/system/bridge-dns"
	if err := getJSON(url, &out); err != nil {
		return err
	}
	if bridgeDNSStatusJSONOut {
		return printJSON(out)
	}
	printBridgeDNSStatus(cmd.OutOrStdout(), out)
	return nil
}

// printBridgeDNSStatus renders the reconciler's last pass. In sync there is one
// record to show; otherwise both the current and the desired record, so the
// operator can see the drift without a second command.
func printBridgeDNSStatus(w io.Writer, out bridgeDNSStatusEnvelope) {
	state := strings.TrimPrefix(out.State, "BRIDGE_DNS_STATE_")
	if state == "" {
		state = "UNSPECIFIED"
	}
	fmt.Fprintf(w, "Bridge DNS: %s\n", state)
	if out.Reason != "" {
		fmt.Fprintf(w, "Reason:     %s\n", out.Reason)
	}
	if out.Bridge != "" {
		fmt.Fprintf(w, "Bridge:     %s\n", out.Bridge)
	}
	if out.CaddyIP != "" {
		fmt.Fprintf(w, "core-caddy: %s\n", out.CaddyIP)
	}
	switch {
	case state == "IN_SYNC" && out.Current != "":
		printRecord(w, "Record:", out.Current)
	case out.Current != "" || out.Desired != "":
		printRecord(w, "Current:", out.Current)
		printRecord(w, "Desired:", out.Desired)
	}
	if out.DriftCount > 0 {
		fmt.Fprintf(w, "Drift passes: %d\n", out.DriftCount)
	}
	if out.LastPass != "" {
		fmt.Fprintf(w, "Last pass:    %s\n", out.LastPass)
	}
	if out.LastApplied != "" {
		fmt.Fprintf(w, "Last applied: %s\n", out.LastApplied)
	}
	if out.LastAction != "" {
		fmt.Fprintf(w, "Last action:  %s\n", out.LastAction)
	}
	if out.CreatedAt != "" {
		fmt.Fprintf(w, "Created by this daemon at %s — every name under the base domain resolves to core-caddy on this bridge; carve out any it must not capture with --dns-passthrough-host / --ssh-host.\n", out.CreatedAt)
	}
	if out.LastError != "" && out.LastError != out.Reason {
		fmt.Fprintf(w, "Last error:   %s\n", out.LastError)
	}
}

// printRecord prints a multi-line raw.dnsmasq value under a label, one indented
// line per directive; an empty value prints "(unset)" so a missing record is
// visible rather than an empty section.
func printRecord(w io.Writer, label, value string) {
	fmt.Fprintln(w, label)
	if strings.TrimSpace(value) == "" {
		fmt.Fprintln(w, "    (unset)")
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(value), "\n") {
		fmt.Fprintf(w, "    %s\n", line)
	}
}

func init() {
	bridgeDNSStatusCmd.Flags().BoolVar(&bridgeDNSStatusJSONOut, "json", false, "Output raw JSON")
	bridgeDNSCmd.AddCommand(bridgeDNSStatusCmd)
	rootCmd.AddCommand(bridgeDNSCmd)
}
