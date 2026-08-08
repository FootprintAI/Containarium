package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/storageprobe"
	"github.com/spf13/cobra"
)

var (
	storageProbeDir      string
	storageProbeOps      int
	storageProbeBaseline int
	storageProbeUnder    int
)

// storageProbeCmd groups the two halves of the contention measurement. Run
// `load` in one box and `probe` in another on the same backend; the ratio
// between a quiet probe and one taken under that load is the signal.
var storageProbeCmd = &cobra.Command{
	Use:   "storage-probe",
	Short: "Measure whether a co-tenant's writeback stalls this box's fsync",
	Long: `Measure storage contention between tenants on the same backend.

Why this exists: an idle latency check reports the opposite of the truth.
On a backend where every tenant rootfs sits on one filesystem — and so on
one journal — the affected containers measure as the FASTEST storage in
the fleet at rest, while collapsing by ~700x once a neighbour writes.

  affected tenant, idle .................... 17 ms
  physical host, same partition ............ 46 ms
  a ZFS-backed backend, busy .............. 196 ms
  affected tenant, under co-tenant load .. 11,885 ms

So a single number here is not a health signal. The ratio between a quiet
baseline and a probe taken under co-tenant load is.

Usage — run these in two different boxes on the SAME backend:

  # box A: generate co-tenant dirty pages (Ctrl-C to stop)
  containarium storage-probe load

  # box B: measure, while A runs
  containarium storage-probe probe

To get a verdict, take the quiet baseline first, then the under-load
number, and hand both to "compare":

  containarium storage-probe compare --baseline-ms 17 --under-load-ms 11885

See docs/BACKEND-STORAGE-DRIVER.md and issue #1206.`,
}

var storageProbeRunCmd = &cobra.Command{
	Use:   "probe",
	Short: "Measure N x (4 KiB write + fsync) in this box",
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := storageprobe.Probe(storageProbeDir, storageProbeOps)
		if err != nil {
			return err
		}
		fmt.Printf("%d x (4KiB write + fsync) in %s: %d ms (%.1f ms each)\n",
			res.Ops, storageProbeDir,
			res.Total.Milliseconds(), float64(res.PerOp().Microseconds())/1000)
		fmt.Printf("\nA single number is not a health signal. Compare this against the\n")
		fmt.Printf("same measurement taken while a co-tenant generates load:\n")
		fmt.Printf("  containarium storage-probe compare --baseline-ms <quiet> --under-load-ms %d\n",
			res.Total.Milliseconds())
		return nil
	},
}

var storageProbeLoadCmd = &cobra.Command{
	Use:   "load",
	Short: "Generate co-tenant dirty pages until interrupted",
	Long: `Generate dirty pages to contend with a neighbouring tenant.

Writes at volume between syncs (64 MiB per fsync by default), because
dirty-page VOLUME is what reproduces the stall — a tight fsync loop with
small writes does not. Runs until interrupted; the scratch file is
removed on exit.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		cfg := storageprobe.DefaultLoadConfig()
		fmt.Printf("Generating dirty pages in %s (%d MiB per fsync). Ctrl-C to stop.\n",
			storageProbeDir, cfg.VolumePerSync()>>20)

		if err := storageprobe.Load(ctx, storageProbeDir, cfg); err != nil {
			return err
		}
		fmt.Println("Stopped; scratch file removed.")
		return nil
	},
}

var storageProbeCompareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Classify a quiet baseline against an under-load measurement",
	RunE: func(cmd *cobra.Command, args []string) error {
		if storageProbeBaseline <= 0 || storageProbeUnder <= 0 {
			return fmt.Errorf("--baseline-ms and --under-load-ms are both required and must be positive")
		}
		ms := func(v int) storageprobe.Result {
			return storageprobe.Result{Ops: storageProbeOps, Total: time.Duration(v) * time.Millisecond}
		}
		a := storageprobe.Classify(ms(storageProbeBaseline), ms(storageProbeUnder))

		fmt.Printf("baseline:   %d ms\n", storageProbeBaseline)
		fmt.Printf("under load: %d ms\n", storageProbeUnder)
		fmt.Printf("ratio:      %.1fx\n", a.Ratio)
		fmt.Printf("verdict:    %s\n\n", a.Verdict)

		switch a.Verdict {
		case storageprobe.VerdictSevere:
			fmt.Printf("A co-tenant's writeback collapses this box's fsync latency. That is\n")
			fmt.Printf("the signature of tenants sharing one filesystem journal: a tenant can\n")
			fmt.Printf("degrade its neighbours by writing normally, with no privilege and no\n")
			fmt.Printf("misconfiguration. Check the backend's storage driver:\n")
			fmt.Printf("  containarium backends list --server <host:port>\n")
			fmt.Printf("See docs/BACKEND-STORAGE-DRIVER.md and issue #1206.\n")
		case storageprobe.VerdictDegraded:
			fmt.Printf("Co-tenant load measurably slows this box's fsync, short of the\n")
			fmt.Printf("order-of-magnitude collapse a shared journal produces. Worth\n")
			fmt.Printf("re-running under heavier load before drawing a conclusion.\n")
		case storageprobe.VerdictIsolated:
			fmt.Printf("Co-tenant load did not meaningfully affect this box's fsync latency.\n")
		default:
			fmt.Printf("Not classifiable — the baseline was unusable. This is not a pass.\n")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(storageProbeCmd)
	storageProbeCmd.AddCommand(storageProbeRunCmd, storageProbeLoadCmd, storageProbeCompareCmd)

	storageProbeCmd.PersistentFlags().StringVar(&storageProbeDir, "dir", os.TempDir(),
		"Directory to write in. Must be on the filesystem you want to measure — on a container this is the rootfs by default, which is where the contention shows up.")
	storageProbeCmd.PersistentFlags().IntVar(&storageProbeOps, "ops", 50,
		"Number of write+fsync operations per probe")

	storageProbeCompareCmd.Flags().IntVar(&storageProbeBaseline, "baseline-ms", 0,
		"Total milliseconds from the quiet probe")
	storageProbeCompareCmd.Flags().IntVar(&storageProbeUnder, "under-load-ms", 0,
		"Total milliseconds from the probe taken under co-tenant load")
}
