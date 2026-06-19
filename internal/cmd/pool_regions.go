//go:build !windows

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// `pool regions --probe` (#699): print the region/RTT table for a set of
// candidate sentinels WITHOUT joining — the same measurement `pool join
// --region auto` uses to self-select, exposed standalone so an operator can see
// which region is closest before committing.

var poolRegionsSentinels []string
var poolRegionsProbe bool

var poolRegionsCmd = &cobra.Command{
	Use:   "regions",
	Short: "List candidate sentinels and (with --probe) their latency from this host",
	Long: `Show the candidate sentinels for a pool join and, with --probe, the measured
RTT from THIS host to each — the same latency measurement 'pool join --region
auto' uses to self-select the closest sentinel.

Example:
  containarium pool regions --probe \
    --sentinel us=us.sentinel.example.com:443 \
    --sentinel eu=eu.sentinel.example.com:443`,
	RunE: runPoolRegions,
}

func init() {
	poolCmd.AddCommand(poolRegionsCmd)
	poolRegionsCmd.Flags().StringArrayVar(&poolRegionsSentinels, "sentinel", nil, "Candidate sentinel as host:port or region=host:port (repeatable)")
	poolRegionsCmd.Flags().BoolVar(&poolRegionsProbe, "probe", false, "Measure RTT from this host to each candidate")
}

func runPoolRegions(cmd *cobra.Command, _ []string) error {
	cands, err := parseSentinelCandidates(poolRegionsSentinels)
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	if !poolRegionsProbe {
		for _, c := range cands {
			region := c.Region
			if region == "" {
				region = "-"
			}
			fmt.Fprintf(w, "  %-12s %s\n", region, c.Addr)
		}
		fmt.Fprintln(w, "\n(pass --probe to measure latency from this host)")
		return nil
	}
	rows := probeCandidates(cands, defaultProbeAttempts, defaultProbeTimeout)
	fmt.Fprint(w, formatRTTTable(rows))
	if chosen, perr := pickLowestRTT(rows); perr == nil {
		fmt.Fprintf(w, "\nClosest: %s (region %q)\n", chosen.Addr, chosen.Region)
	} else {
		return perr
	}
	return nil
}
