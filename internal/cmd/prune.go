package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/spf13/cobra"
)

var (
	pruneState        string
	pruneNameContains string
	pruneOlderThan    string
	pruneLabels       []string
	pruneDryRun       bool
	pruneYes          bool
	pruneForce        bool
)

var pruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Bulk-delete containers matching a filter (fleet cleanup)",
	Long: `Delete every container matching a filter in one command, instead of
deleting them one by one.

Built for fleet hygiene: reaping a pile of leaked/finished ephemeral boxes
(e.g. CI debug boxes that outlived their run). It LISTs containers, narrows by
the filters you pass, shows exactly which boxes match, and — after you confirm —
deletes each. Core platform containers are never eligible.

At least one filter is required (refusing to prune everything by accident).
Filters combine with AND. By default you're prompted to confirm; use --yes to
skip the prompt (e.g. in scripts) or --dry-run to only preview.

Examples:
  # Preview which stopped boxes would be deleted (no deletion)
  containarium prune --state stopped --dry-run

  # Delete all stopped boxes created over an hour ago, after confirming
  containarium prune --state stopped --older-than 1h

  # Reap all CI boxes by label, no prompt (scripted)
  containarium prune --label managed_by=ci --yes

  # Delete boxes whose name contains "pr-" older than a day
  containarium prune --name-contains pr- --older-than 24h --yes`,
	Args: cobra.NoArgs,
	RunE: runPrune,
}

func init() {
	rootCmd.AddCommand(pruneCmd)
	pruneCmd.Flags().StringVar(&pruneState, "state", "", "Only containers in this state: running | stopped")
	pruneCmd.Flags().StringVar(&pruneNameContains, "name-contains", "", "Only containers whose name/username contains this substring")
	pruneCmd.Flags().StringVar(&pruneOlderThan, "older-than", "", "Only containers created longer ago than this (Go duration: '1h', '24h', '7d' is not valid — use '168h')")
	pruneCmd.Flags().StringSliceVar(&pruneLabels, "label", nil, "Only containers with this label (key=value); repeatable, all must match")
	pruneCmd.Flags().BoolVar(&pruneDryRun, "dry-run", false, "Show what would be deleted and exit without deleting")
	pruneCmd.Flags().BoolVarP(&pruneYes, "yes", "y", false, "Skip the confirmation prompt (delete immediately)")
	pruneCmd.Flags().BoolVar(&pruneForce, "force", false, "Force-stop running containers before deleting (passed to each delete)")
}

func runPrune(_ *cobra.Command, _ []string) error {
	// Require at least one narrowing filter. Without this guard a bare
	// `prune` would match (and offer to delete) every container — exactly the
	// foot-gun bulk delete must not have.
	if pruneState == "" && pruneNameContains == "" && pruneOlderThan == "" && len(pruneLabels) == 0 {
		return fmt.Errorf("refusing to prune without a filter: pass at least one of --state, --name-contains, --older-than, --label (they combine with AND to narrow the set)")
	}

	switch pruneState {
	case "", "running", "stopped":
	default:
		return fmt.Errorf("--state must be 'running' or 'stopped', got %q", pruneState)
	}

	var olderThan time.Duration
	if pruneOlderThan != "" {
		d, err := time.ParseDuration(pruneOlderThan)
		if err != nil {
			return fmt.Errorf("invalid --older-than %q: %w (expected Go duration like '1h', '24h', '168h')", pruneOlderThan, err)
		}
		if d <= 0 {
			return fmt.Errorf("--older-than must be positive, got %s", pruneOlderThan)
		}
		olderThan = d
	}

	labelFilter := parseLabels(pruneLabels)

	containers, err := pruneList()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	now := time.Now()
	matches := filterForPrune(containers, pruneState, pruneNameContains, olderThan, labelFilter, now)

	if len(matches) == 0 {
		fmt.Println("No containers match the filter — nothing to prune.")
		return nil
	}

	fmt.Printf("%d container(s) match:\n", len(matches))
	for _, c := range matches {
		fmt.Printf("  - %-24s state=%-8s %s\n", pruneDeleteKey(c), c.State, ageString(now, c.CreatedAt))
	}

	if pruneDryRun {
		fmt.Printf("\ndry-run: would delete %d container(s). Re-run without --dry-run to delete.\n", len(matches))
		return nil
	}

	if !pruneYes {
		fmt.Printf("\nDelete these %d container(s)? [y/N]: ", len(matches))
		reader := bufio.NewReader(os.Stdin)
		resp, _ := reader.ReadString('\n')
		if r := strings.TrimSpace(strings.ToLower(resp)); r != "y" && r != "yes" {
			fmt.Println("Cancelled — nothing deleted.")
			return nil
		}
	}

	var deleted, failed int
	for _, c := range matches {
		key := pruneDeleteKey(c)
		if err := pruneDelete(key, pruneForce); err != nil {
			fmt.Printf("  ✗ %s: %v\n", key, err)
			failed++
			continue
		}
		fmt.Printf("  ✓ %s deleted\n", key)
		deleted++
	}
	fmt.Printf("\nPruned %d/%d container(s).\n", deleted, len(matches))
	if failed > 0 {
		return fmt.Errorf("%d container(s) failed to delete", failed)
	}
	return nil
}

// filterForPrune is the pure selection logic: which containers match the
// filters. Core containers are NEVER matched (infrastructure safety). Filters
// combine with AND. olderThan == 0 / state == "" / nameContains == "" /
// empty labels each mean "don't filter on that". A box with no CreatedAt is
// excluded by an olderThan filter (can't prove it's old enough). Pure — no IO,
// `now` injected — so it's unit-tested directly.
func filterForPrune(containers []incus.ContainerInfo, state, nameContains string, olderThan time.Duration, labels map[string]string, now time.Time) []incus.ContainerInfo {
	var matches []incus.ContainerInfo
	for _, c := range containers {
		if c.Role.IsCoreRole() {
			continue
		}
		if state == "running" && !strings.EqualFold(c.State, "Running") {
			continue
		}
		if state == "stopped" && !strings.EqualFold(c.State, "Stopped") {
			continue
		}
		if nameContains != "" &&
			!strings.Contains(c.Name, nameContains) &&
			!strings.Contains(c.Username, nameContains) {
			continue
		}
		if olderThan > 0 {
			if c.CreatedAt.IsZero() || now.Sub(c.CreatedAt) < olderThan {
				continue
			}
		}
		if len(labels) > 0 && !incus.MatchLabels(c.Labels, labels) {
			continue
		}
		matches = append(matches, c)
	}
	return matches
}

// pruneDeleteKey is the identifier delete is addressed by: the container's
// Username (the cloud-assigned cld-<id> on a cloud backend, or the bare
// username on an OSS daemon) — NOT the friendly name. Falls back to the
// name with the "-container" suffix stripped when Username is empty.
func pruneDeleteKey(c incus.ContainerInfo) string {
	if c.Username != "" {
		return c.Username
	}
	return strings.TrimSuffix(c.Name, "-container")
}

// ageString renders how long ago the box was created, for the preview list.
func ageString(now, created time.Time) string {
	if created.IsZero() {
		return "age=unknown"
	}
	return fmt.Sprintf("age=%s", now.Sub(created).Round(time.Minute))
}

// pruneList / pruneDelete reuse the exact gRPC / HTTP / local dispatch the
// list and delete commands use, so prune is purely a filter+loop over the
// existing per-container surface — no new server endpoint.
func pruneList() ([]incus.ContainerInfo, error) {
	if httpMode && serverAddr != "" {
		return listRemoteHTTP()
	}
	if serverAddr != "" {
		return listRemote()
	}
	return listLocal()
}

func pruneDelete(username string, force bool) error {
	if httpMode && serverAddr != "" {
		return deleteRemoteHTTP(username, force)
	}
	if serverAddr != "" {
		return deleteRemote(username, force)
	}
	return deleteLocal(username, force)
}
