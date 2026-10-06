package cmd

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// network-guard status — the posture of both Incus NIC-ACL guards on the
// daemon's host (docs/architecture/tenant-network-guard.md): the core-infra
// guard (#2084, tenants kept off core-role containers) and the tenant
// guard (#2347, tenants kept off each other). Reads GET /v1/network/guard,
// the same endpoint the MCP tool network_guard_status wraps.

var networkGuardCmd = &cobra.Command{
	Use:   "network-guard",
	Short: "Incus NIC-ACL guards: tenant isolation posture on this backend",
	Long: `Both guards attach an Incus network ACL to a container's NIC with ingress
default-drop and a computed allow table. The core guard protects core-role
containers from tenants; the tenant guard protects tenants from each other.
Both are on unless CONTAINARIUM_CORE_GUARD / CONTAINARIUM_TENANT_GUARD=off,
and both need Incus's nftables firewall driver and the
network_bridge_acl_devices API extension (Incus 6.9+).`,
}

var networkGuardStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show both guards' last-pass state (admin)",
	RunE:  runNetworkGuardStatus,
}

var ngJSONOut bool

func init() {
	networkGuardStatusCmd.Flags().BoolVar(&ngJSONOut, "json", false, "Output as JSON")
	networkGuardCmd.AddCommand(networkGuardStatusCmd)
	rootCmd.AddCommand(networkGuardCmd)
}

// guardEntryJSON / guardStatusJSON / networkGuardStatusJSON mirror the proto
// NetworkGuardStatus as grpc-gateway renders it (camelCase, enum names).
type guardEntryJSON struct {
	Container string `json:"container"`
	Subject   string `json:"subject"`
	IP        string `json:"ip"`
	ACLName   string `json:"aclName"`
	Attached  bool   `json:"attached"`
	LastError string `json:"lastError"`
}

type guardStatusJSON struct {
	Mode           string           `json:"mode"`
	FirewallDriver string           `json:"firewallDriver"`
	Unsupported    bool             `json:"unsupported"`
	LastPass       string           `json:"lastPass"`
	LastError      string           `json:"lastError"`
	StaleSince     string           `json:"staleSince"`
	Entries        []guardEntryJSON `json:"entries"`
	Unresolved     []string         `json:"unresolved"`
	Subjects       int              `json:"subjects"`
}

type networkGuardStatusJSON struct {
	Core   *guardStatusJSON `json:"core"`
	Tenant *guardStatusJSON `json:"tenant"`
}

func runNetworkGuardStatus(cmd *cobra.Command, _ []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	var out networkGuardStatusJSON
	if err := getJSON(strings.TrimSuffix(serverAddr, "/")+"/v1/network/guard", &out); err != nil {
		return err
	}
	if ngJSONOut {
		return printJSON(out)
	}
	w := cmd.OutOrStdout()
	printGuard(w, "core guard (tenants → core infra, #2084)", out.Core)
	fmt.Fprintln(w)
	printGuard(w, "tenant guard (tenant → tenant, #2347)", out.Tenant)
	if !guardHealthy(out.Core) || !guardHealthy(out.Tenant) {
		return fmt.Errorf("at least one guard is not enforcing cleanly — see above")
	}
	return nil
}

// guardHealthy is the one-line verdict: a guard is healthy only when it is
// enforcing, supported here, its last pass had no error, every subject is
// attached, and nothing was left unresolved — an unguarded tenant is a
// failed guard even when the pass itself succeeded.
func guardHealthy(g *guardStatusJSON) bool {
	if g == nil || g.Mode != "GUARD_MODE_ENFORCE" || g.Unsupported || g.LastError != "" || len(g.Unresolved) > 0 {
		return false
	}
	for _, e := range g.Entries {
		if !e.Attached || e.LastError != "" {
			return false
		}
	}
	return true
}

func printGuard(w interface{ Write([]byte) (int, error) }, title string, g *guardStatusJSON) {
	fmt.Fprintf(w, "%s\n", title)
	if g == nil {
		fmt.Fprintln(w, "  not available on this backend (no incus client)")
		return
	}
	verdict := "OK"
	switch {
	case g.Mode != "GUARD_MODE_ENFORCE":
		verdict = "OFF"
	case g.Unsupported:
		verdict = "UNSUPPORTED — nothing guarded"
	case !guardHealthy(g):
		verdict = "DEGRADED — a subject is unattached, errored or unresolved"
	}
	fmt.Fprintf(w, "  verdict:   %s\n", verdict)
	fmt.Fprintf(w, "  mode:      %s\n", strings.TrimPrefix(g.Mode, "GUARD_MODE_"))
	fmt.Fprintf(w, "  firewall:  %s\n", orDash(g.FirewallDriver))
	fmt.Fprintf(w, "  last pass: %s\n", orDash(g.LastPass))
	if g.StaleSince != "" {
		fmt.Fprintf(w, "  stale since: %s (previous ACLs stay in force)\n", g.StaleSince)
	}
	if g.LastError != "" {
		fmt.Fprintf(w, "  last error: %s\n", g.LastError)
	}
	fmt.Fprintf(w, "  subjects:  %d guarded, %d entries, %d unresolved\n", g.Subjects, len(g.Entries), len(g.Unresolved))
	if len(g.Entries) > 0 {
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  CONTAINER\tSUBJECT\tIP\tACL\tATTACHED\tERROR")
		for _, e := range g.Entries {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%v\t%s\n", e.Container, e.Subject, orDash(e.IP), e.ACLName, e.Attached, e.LastError)
		}
		_ = tw.Flush()
	}
	for _, u := range g.Unresolved {
		fmt.Fprintf(w, "  unresolved: %s (left unguarded, reported)\n", u)
	}
}
