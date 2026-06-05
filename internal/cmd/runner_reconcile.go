package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/runner"
	"github.com/spf13/cobra"
)

// Flags specific to `containarium runner reconcile`.
var (
	runnerMaxTotal         int
	runnerReconcileDesired int
	runnerReconcilePoll    time.Duration
)

var runnerReconcileCmd = &cobra.Command{
	Use:   "reconcile <repo>",
	Short: "Keep a capped pool of ephemeral runners topped up (standalone controller)",
	Long: `Run a long-lived controller that keeps the runner fleet for <repo> at a
target size without ever exceeding the system-wide cap.

This is the "queue the rest" half of runner capacity management. Each tick
it counts the live runner boxes (names starting with --name-prefix) and, if
the fleet is below the target, provisions the difference — but the
provisioning path enforces --max-total, so the fleet never grows past the
cap. Jobs beyond the cap simply wait in GitHub's own queue until an
ephemeral runner finishes and frees a slot, at which point the next tick
tops the pool back up.

It is STATELESS: the desired state is re-derived from reality every tick, so
the controller can be killed and restarted at any time with no bookkeeping
to lose. Run it under systemd / a process supervisor.

Unlike folding this into the daemon, the controller authenticates as an
ordinary client (the same --server / token path as every other CLI verb),
so no GitHub PAT or privileged auth context has to live inside the daemon.

Examples:
  # Keep up to 20 runners warm for the repo (cap = 20), poll every 15s
  containarium runner reconcile footprintai/containarium \
      --github-pat ghp_xxxx --sentinel sentinel.example.com:22 \
      --max-total 20

  # Keep a small warm pool of 5 (cap stays at 20), poll every 30s
  containarium runner reconcile footprintai/containarium \
      --github-pat ghp_xxxx --sentinel sentinel.example.com:22 \
      --max-total 20 --desired 5 --poll 30s`,
	Args: cobra.ExactArgs(1),
	RunE: runRunnerReconcile,
}

func init() {
	runnerCmd.AddCommand(runnerReconcileCmd)

	runnerReconcileCmd.Flags().StringVar(&runnerPAT, "github-pat", os.Getenv("GH_PAT"), "GitHub PAT with `repo` scope (env: GH_PAT). REQUIRED.")
	runnerReconcileCmd.Flags().StringVar(&runnerSentinelHost, "sentinel", os.Getenv("CONTAINARIUM_SENTINEL_HOST"), "Sentinel SSH host (env: CONTAINARIUM_SENTINEL_HOST). REQUIRED for the install step.")
	runnerReconcileCmd.Flags().StringVar(&runnerSSHUser, "ssh-user", "", "SSH user when SSH'ing into a runner box (default: the runner name, via sshpiper)")
	runnerReconcileCmd.Flags().StringVar(&runnerSSHKeyPath, "ssh-key", "", "Path to SSH public key used when creating new boxes (default: ~/.ssh/id_rsa.pub)")
	runnerReconcileCmd.Flags().StringVar(&runnerNamePrefix, "name-prefix", "ci-runner", "Prefix for generated box names (also the count filter)")
	runnerReconcileCmd.Flags().StringVar(&runnerLabels, "labels", "containarium,ephemeral", "Comma-separated runner labels")
	runnerReconcileCmd.Flags().StringVar(&runnerNameTemplate, "runner-name-template", "{prefix}-{i}", "Template for box names; {prefix} and {i} are substituted")
	runnerReconcileCmd.Flags().IntVar(&runnerMaxTotal, "max-total", 0, "System-wide cap on concurrent runner boxes (0 = env MAX_RUNNERS_TOTAL or built-in default)")
	runnerReconcileCmd.Flags().IntVar(&runnerReconcileDesired, "desired", 0, "Target warm-pool size to maintain, capped by --max-total (0 = maintain at the cap)")
	runnerReconcileCmd.Flags().DurationVar(&runnerReconcilePoll, "poll", 15*time.Second, "How often to reconcile the fleet")
}

func runRunnerReconcile(_ *cobra.Command, args []string) error {
	repo := args[0]

	// Resolve the cap once for the validation/logging banner; the
	// per-tick provisioning re-resolves it (so a changed
	// MAX_RUNNERS_TOTAL is picked up live) by passing MaxTotal
	// through Options.
	capTotal := runnerMaxTotal
	if capTotal <= 0 {
		capTotal = runner.MaxRunnersTotal()
	}
	target := runnerReconcileDesired
	if target <= 0 || target > capTotal {
		// Default to "maintain at the cap"; also clamp a target that
		// was set above the cap (the cap always wins).
		target = capTotal
	}
	if runnerReconcilePoll <= 0 {
		return fmt.Errorf("--poll must be > 0")
	}

	// Validate the provision inputs up front using the same checks
	// the one-shot provision verb uses (repo shape, PAT present).
	if err := runner.ValidateOptions(runner.Options{Repo: repo, PAT: runnerPAT, Count: 1}); err != nil {
		return err
	}
	if runnerSentinelHost == "" {
		return fmt.Errorf("--sentinel is required (or set CONTAINARIUM_SENTINEL_HOST); the install step needs to SSH into each new box")
	}

	deps, sshKey, err := buildRunnerDeps(runnerSentinelHost, runnerSSHUser)
	if err != nil {
		return err
	}

	// Stop cleanly on SIGINT/SIGTERM so a supervisor restart doesn't
	// leave a half-finished provision; in-flight Provision calls run
	// to completion because we only check ctx between ticks.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Printf("runner reconcile: repo=%s target=%d cap=%d poll=%s prefix=%q\n",
		repo, target, capTotal, runnerReconcilePoll, runnerNamePrefix)
	fmt.Println("watching fleet — Ctrl-C to stop")

	// Reconcile once immediately so an operator sees action without
	// waiting a full poll interval, then on the ticker.
	reconcileOnce(ctx, deps, repo, sshKey, target)

	t := time.NewTicker(runnerReconcilePoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nstopping reconcile loop")
			return nil
		case <-t.C:
			reconcileOnce(ctx, deps, repo, sshKey, target)
		}
	}
}

// reconcileOnce is one maintain pass: count the live fleet and, if
// below target, provision the difference. Provision itself enforces
// the system-wide cap (MaxTotal), so even a stale/oversized target
// can never push the fleet past the ceiling. Errors are logged and
// the loop continues — a transient daemon/GitHub blip shouldn't kill
// the controller.
func reconcileOnce(ctx context.Context, deps runner.Deps, repo, sshKey string, target int) {
	live, err := runner.CountLiveRunners(ctx, deps, runnerNamePrefix)
	if err != nil {
		fmt.Printf("  [reconcile] count live runners: %v (skipping)\n", err)
		return
	}
	need := target - live
	if need <= 0 {
		return // fleet at/above target; ephemeral runners self-remove after jobs
	}

	res, err := runner.Provision(ctx, deps, runner.Options{
		Repo:         repo,
		PAT:          runnerPAT,
		Count:        need,
		NamePrefix:   runnerNamePrefix,
		Labels:       runnerLabels,
		NameTemplate: runnerNameTemplate,
		SSHKey:       sshKey,
		MaxTotal:     runnerMaxTotal, // 0 → runner.MaxRunnersTotal()
	})
	if err != nil {
		fmt.Printf("  [reconcile] provision: %v\n", err)
		return
	}
	created := 0
	for _, r := range res.Runners {
		switch r.State {
		case "provisioned", "registering", "exists":
			created++
		}
	}
	fmt.Printf("  [reconcile] live=%d target=%d → provisioned %d (deferred=%d)\n",
		live, target, created, res.Deferred)
}
