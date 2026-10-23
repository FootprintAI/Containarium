package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var networkPolicyStatusCmd = &cobra.Command{
	Use:   "status <tenant>",
	Short: "Show what this daemon has actually loaded for a tenant's network policy",
	Long: `Reports the tenant's policy as the daemon loaded it into the kernel, not as it
was requested: the effective mode and egress mode after this host's enforce
guard (CONTAINARIUM_NETWORK_POLICY_ENFORCE), how many of the tenant's running
boxes have it loaded, and the traffic the eBPF policy does not decide.

"loaded" means every running box of the tenant has the policy; "PARTIALLY
loaded" means some do not, and their traffic is not policed. last-reconciled is
the end of the daemon's last successful reconcile pass (refreshed about every
10s), not the time the policy last changed; if no pass has succeeded for more
than three reconcile intervals the state is "stale" and the modes are unknown.
When the daemon cannot tell, it says unknown.`,
	Args: cobra.ExactArgs(1),
	RunE: runNetworkPolicyStatus,
}

func init() {
	networkPolicyStatusCmd.Flags().BoolVar(&npJSONOut, "json", false, "Output the status as JSON")
	networkPolicyCmd.AddCommand(networkPolicyStatusCmd)
}

// networkPolicyStatusURL is the grpc-gateway route of GetNetworkPolicyStatus;
// the tenant is escaped as a single path segment.
func networkPolicyStatusURL(server, tenant string) string {
	return strings.TrimSuffix(server, "/") + "/v1/network-policies/" + url.PathEscape(tenant) + "/status"
}

// decodeStatus parses the gateway's JSON into the generated response type,
// ignoring fields a newer daemon may add.
func decodeStatus(raw []byte) (*pb.NetworkPolicyStatus, error) {
	var resp pb.GetNetworkPolicyStatusResponse
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode network policy status: %w", err)
	}
	return resp.GetStatus(), nil
}

func runNetworkPolicyStatus(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	var raw json.RawMessage
	if err := getJSON(networkPolicyStatusURL(serverAddr, args[0]), &raw); err != nil {
		return err
	}
	st, err := decodeStatus(raw)
	if err != nil {
		return err
	}
	if npJSONOut {
		out, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(st)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	}
	printStatus(cmd.OutOrStdout(), st)
	return nil
}

var appliedStateText = map[pb.NetworkPolicyAppliedState]string{
	pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED:               "loaded (every running box of this tenant has the policy)",
	pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_PARTIALLY_LOADED:     "PARTIALLY loaded: the tenant is NOT fully covered (the modes below apply to the loaded boxes only)",
	pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_STALE:                "stale: the reconciler has not completed a pass for over three intervals, so what is loaded now is unknown",
	pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED:           "not loaded (no running box of this tenant has the policy loaded)",
	pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_ENFORCER_NOT_RUNNING: "enforcer not running on this daemon (nothing is enforced or observed)",
}

var uncoveredPathText = map[pb.NetworkPolicyUncoveredPath]string{
	pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_IPV6:               "ipv6: the eBPF program checks IPv4 only; IPv6 traffic is not policed",
	pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_DOMAIN_REFRESH_LAG: "domain refresh lag: egress domains are re-resolved at most every 60s, so an address change takes effect only after the next refresh",
	pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_KERNEL_UNSUPPORTED: "kernel unsupported: this host's kernel cannot run egress enforcement",
}

// printStatus renders a tenant's applied state. Anything the daemon did not
// report reads "unknown", never a default.
func printStatus(w io.Writer, s *pb.NetworkPolicyStatus) {
	state, ok := appliedStateText[s.GetState()]
	if !ok {
		state = "unknown (the daemon cannot tell yet)"
	}
	mode := func(m pb.NetworkPolicyMode) string {
		switch m {
		case pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE:
			return shortMode(m.String())
		default:
			return "unknown"
		}
	}
	fmt.Fprintf(w, "  tenant:             %s\n", s.GetTenant())
	fmt.Fprintf(w, "  state:              %s\n", state)
	fmt.Fprintf(w, "  effective-mode:     %s\n", mode(s.GetEffectiveMode()))
	fmt.Fprintf(w, "  egress-mode:        %s\n", mode(s.GetEffectiveEgressMode()))
	if s.GetLastReconciledAt() != nil {
		fmt.Fprintf(w, "  last-reconciled:    %s\n", s.GetLastReconciledAt().AsTime().UTC().Format(time.RFC3339))
	}
	switch {
	case s.GetEnforcementArmed():
		fmt.Fprintf(w, "  enforcement-armed:  true\n")
	case policyLoaded(s.GetState()):
		fmt.Fprintf(w, "  enforcement-armed:  false (a requested enforce is loaded as log_only on this host)\n")
	default:
		fmt.Fprintf(w, "  enforcement-armed:  false\n")
	}
	if s.GetBoxesLoaded() > 0 || s.GetBoxesNotLoaded() > 0 {
		line := fmt.Sprintf("%d loaded", s.GetBoxesLoaded())
		if s.GetBoxesNotLoaded() > 0 {
			line += fmt.Sprintf(", %d NOT loaded (their traffic is not policed)", s.GetBoxesNotLoaded())
		}
		fmt.Fprintf(w, "  boxes:              %s\n", line)
	}
	if len(s.GetUncoveredPaths()) > 0 {
		fmt.Fprintln(w, "  not covered:")
		for _, p := range s.GetUncoveredPaths() {
			text, ok := uncoveredPathText[p]
			if !ok {
				text = strings.ToLower(strings.TrimPrefix(p.String(), "NETWORK_POLICY_UNCOVERED_PATH_"))
			}
			fmt.Fprintf(w, "    - %s\n", text)
		}
	}
}

// policyLoaded reports whether the state says some policy is in the kernel.
func policyLoaded(st pb.NetworkPolicyAppliedState) bool {
	return st == pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED ||
		st == pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_PARTIALLY_LOADED
}
