package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// poolCmd is the parent for the per-tenant BYO-compute pool commands —
// turning a spare host into a member of YOUR OWN pool and scheduling your
// own workloads across it (prd/oss/byo-compute-pool-join.md). This is the
// single-operator "I have more than one machine" path: no cross-tenant
// sharing, your data stays on your hosts.
//
// `pool list` reads the daemon's view of the pool (its discovered
// backends); `pool join` (host-side) turns a fresh host into a member.
var poolCmd = &cobra.Command{
	Use:   "pool",
	Short: "Manage your BYO-compute pool (add your own hosts, see members)",
	Long: `Manage the compute pool made up of hosts YOU bring — a single operator
pooling more than one machine so the daemon can schedule your own
workloads across them. Your workloads and data stay on your hosts; this
is not cross-tenant sharing.

Examples:
  # Show the pool's members + health (reads the daemon you point --server at)
  containarium pool list --server http://host:8080

  # Turn THIS host into a pool member (run on the new host, as root)
  sudo containarium pool join --sentinel sentinel.example.com:443 \
    --pool prod --token <scoped-join-token>`,
}

var poolListFormat string

var poolListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List the pool's member backends + health",
	Aliases: []string{"ls"},
	Long: `List the members of the pool from the daemon's view — every backend the
platform daemon sees (the local daemon plus tunnel-connected peer hosts).
When the daemon was started with --pool, that set IS the pool.

Reads /v1/backends (HTTP-only), so --server must point at the daemon's
HTTP address.`,
	RunE: runPoolList,
}

func init() {
	rootCmd.AddCommand(poolCmd)
	poolCmd.AddCommand(poolListCmd)
	poolListCmd.Flags().StringVarP(&poolListFormat, "format", "f", "table",
		"Output format: table, json")
}

func runPoolList(cmd *cobra.Command, args []string) error {
	members, err := fetchBackends()
	if err != nil {
		return err
	}
	switch poolListFormat {
	case "json":
		out, err := json.MarshalIndent(map[string]any{"members": members}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	case "table":
		printPoolTable(members)
	default:
		return fmt.Errorf("unknown format: %s (use: table, json)", poolListFormat)
	}
	return nil
}

// printPoolTable renders the pool's members in a membership-oriented view
// (role = local daemon vs tunnel-joined host, plus health/version).
func printPoolTable(members []backendInfo) {
	if len(members) == 0 {
		fmt.Println("No pool members (this daemon is running standalone — no joined hosts).")
		return
	}
	fmt.Printf("%-40s %-8s %-8s %-25s %-12s %s\n",
		"MEMBER ID", "ROLE", "HEALTH", "HOSTNAME", "VERSION", "CONTAINERS")
	fmt.Println(strings.Repeat("-", 105))
	healthy := 0
	for _, m := range members {
		health := "✗"
		if m.Healthy {
			health = "✓"
			healthy++
		}
		hostname := m.Hostname
		if hostname == "" {
			hostname = "-"
		}
		version := m.Version
		if version == "" {
			version = "-"
		}
		fmt.Printf("%-40s %-8s %-8s %-25s %-12s %d\n",
			m.ID, m.Type, health, hostname, version, m.ContainerCount)
	}
	fmt.Printf("\nTotal: %d member(s), %d healthy\n", len(members), healthy)
}
