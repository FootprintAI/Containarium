package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

var networkPolicyStatusCmd = &cobra.Command{
	Use:   "status <tenant>",
	Short: "Show what this daemon has actually loaded for a tenant's network policy",
	Long: `Reports the tenant's policy as the daemon loaded it into the kernel, not as it
was requested: the effective mode and egress mode after this host's enforce
guard (CONTAINARIUM_NETWORK_POLICY_ENFORCE), when it was last applied, how many
of the tenant's running boxes have it loaded, and the traffic the eBPF policy
does not decide. When the daemon cannot tell, it says unknown.`,
	Args: cobra.ExactArgs(1),
	RunE: runNetworkPolicyStatus,
}

func init() {
	networkPolicyCmd.AddCommand(networkPolicyStatusCmd)
}

// statusEnvelope mirrors GetNetworkPolicyStatusResponse's grpc-gateway JSON.
type statusEnvelope struct {
	Status policyStatusJSON `json:"status"`
}

type policyStatusJSON struct {
	Tenant              string   `json:"tenant"`
	State               string   `json:"state"`
	EffectiveMode       string   `json:"effectiveMode"`
	EffectiveEgressMode string   `json:"effectiveEgressMode"`
	LastAppliedAt       string   `json:"lastAppliedAt"`
	EnforcementArmed    bool     `json:"enforcementArmed"`
	BoxesLoaded         uint32   `json:"boxesLoaded"`
	BoxesNotLoaded      uint32   `json:"boxesNotLoaded"`
	UncoveredPaths      []string `json:"uncoveredPaths"`
}

func runNetworkPolicyStatus(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	var out statusEnvelope
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/network-policies/" + args[0] + "/status"
	if err := getJSON(url, &out); err != nil {
		return err
	}
	if npJSONOut {
		return printJSON(out.Status)
	}
	printStatus(cmd.OutOrStdout(), out.Status)
	return nil
}

var appliedStateText = map[string]string{
	"NETWORK_POLICY_APPLIED_STATE_LOADED":               "loaded",
	"NETWORK_POLICY_APPLIED_STATE_NOT_LOADED":           "not loaded (no running box of this tenant has the policy loaded)",
	"NETWORK_POLICY_APPLIED_STATE_ENFORCER_NOT_RUNNING": "enforcer not running on this daemon (nothing is enforced or observed)",
}

var uncoveredPathText = map[string]string{
	"NETWORK_POLICY_UNCOVERED_PATH_IPV6":               "ipv6: the eBPF program checks IPv4 only; IPv6 traffic is not policed",
	"NETWORK_POLICY_UNCOVERED_PATH_DOMAIN_REFRESH_LAG": "domain refresh lag: egress domains are re-resolved at most every 60s, so an address change takes effect only after the next refresh",
}

// printStatus renders a tenant's applied state. Anything the daemon did not
// report reads "unknown", never a default.
func printStatus(w io.Writer, s policyStatusJSON) {
	state, ok := appliedStateText[s.State]
	if !ok {
		state = "unknown (the daemon cannot tell yet)"
	}
	mode := func(m string) string {
		if m == "" || m == "NETWORK_POLICY_MODE_UNSPECIFIED" {
			return "unknown"
		}
		return shortMode(m)
	}
	fmt.Fprintf(w, "  tenant:             %s\n", s.Tenant)
	fmt.Fprintf(w, "  state:              %s\n", state)
	fmt.Fprintf(w, "  effective-mode:     %s\n", mode(s.EffectiveMode))
	fmt.Fprintf(w, "  egress-mode:        %s\n", mode(s.EffectiveEgressMode))
	if s.LastAppliedAt != "" {
		fmt.Fprintf(w, "  last-applied:       %s\n", s.LastAppliedAt)
	}
	if s.EnforcementArmed {
		fmt.Fprintf(w, "  enforcement-armed:  true\n")
	} else {
		fmt.Fprintf(w, "  enforcement-armed:  false (a requested enforce is loaded as log_only on this host)\n")
	}
	if s.BoxesLoaded > 0 || s.BoxesNotLoaded > 0 {
		line := fmt.Sprintf("%d loaded", s.BoxesLoaded)
		if s.BoxesNotLoaded > 0 {
			line += fmt.Sprintf(", %d NOT loaded (their traffic is not policed)", s.BoxesNotLoaded)
		}
		fmt.Fprintf(w, "  boxes:              %s\n", line)
	}
	if len(s.UncoveredPaths) > 0 {
		fmt.Fprintln(w, "  not covered:")
		for _, p := range s.UncoveredPaths {
			text, ok := uncoveredPathText[p]
			if !ok {
				text = strings.ToLower(strings.TrimPrefix(p, "NETWORK_POLICY_UNCOVERED_PATH_"))
			}
			fmt.Fprintf(w, "    - %s\n", text)
		}
	}
}
