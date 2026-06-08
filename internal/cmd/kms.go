package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// These are the REMOTE (API) KMS admin commands — they call the
// daemon's KmsService over gRPC/HTTP and require an admin token with
// the kms:admin scope. They mirror the surface the dashboard consumes.
//
// The host-only counterparts under `secrets migrate-to-envelope` /
// `secrets envelope-coverage` (secrets_migrate.go) open the Postgres
// store directly and run ON the daemon host with master-key access —
// use those for on-box maintenance without a token.

var (
	kmsMigrateDryRun    bool
	kmsMigrateBatchSize int64
	kmsMigrateMaxRows   int64
)

var kmsCmd = &cobra.Command{
	Use:   "kms",
	Short: "Inspect KMS envelope-encryption status and trigger migration (remote)",
	Long: `Administer the tenant-secrets envelope-encryption layer over the API.

Requires an admin token carrying the kms:admin scope. Backend SELECTION
stays an operator/systemd concern (CONTAINARIUM_KMS_BACKEND + per-backend
env); these commands only read status / coverage and trigger migration.`,
}

var kmsStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the active KMS backend and envelope-retirement state",
	RunE:  runKMSStatus,
}

var kmsCoverageCmd = &cobra.Command{
	Use:   "envelope-coverage",
	Short: "Count stored secrets by encryption mode (legacy vs envelope)",
	RunE:  runKMSCoverage,
}

var kmsMigrateCmd = &cobra.Command{
	Use:   "migrate-to-envelope",
	Short: "Re-wrap legacy secrets under the active KMS KEK (remote)",
	RunE:  runKMSMigrate,
}

func init() {
	rootCmd.AddCommand(kmsCmd)
	kmsCmd.AddCommand(kmsStatusCmd)
	kmsCmd.AddCommand(kmsCoverageCmd)
	kmsCmd.AddCommand(kmsMigrateCmd)

	kmsMigrateCmd.Flags().BoolVar(&kmsMigrateDryRun, "dry-run", false, "Walk and verify rows would round-trip, but issue no writes")
	kmsMigrateCmd.Flags().Int64Var(&kmsMigrateBatchSize, "batch-size", 0, "Rows scanned per page (0 = server default 100)")
	kmsMigrateCmd.Flags().Int64Var(&kmsMigrateMaxRows, "max-rows", 0, "Cap on rows processed in one call (0 = unlimited)")
}

func runKMSStatus(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required for kms commands")
	}
	var resp *pb.GetKMSStatusResponse
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		resp, err = h.GetKMSStatus()
		if err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		resp, err = g.GetKMSStatus()
		if err != nil {
			return err
		}
	}
	fmt.Printf("KMS backend:       %s\n", resp.Backend)
	fmt.Printf("Description:       %s\n", resp.Description)
	fmt.Printf("KMS active:        %t\n", resp.KmsConfigured)
	fmt.Printf("Require envelope:  %t\n", resp.RequireEnvelope)
	return nil
}

func runKMSCoverage(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required for kms commands")
	}
	var resp *pb.GetEnvelopeCoverageResponse
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		resp, err = h.GetEnvelopeCoverage()
		if err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		resp, err = g.GetEnvelopeCoverage()
		if err != nil {
			return err
		}
	}
	fmt.Printf("Secrets envelope-encryption coverage:\n")
	fmt.Printf("  total:    %d\n", resp.Total)
	fmt.Printf("  legacy:   %d\n", resp.Legacy)
	fmt.Printf("  envelope: %d\n", resp.Envelope)
	if resp.Total > 0 && resp.Legacy == 0 {
		fmt.Printf("\n✓ Fully migrated — safe to set CONTAINARIUM_REQUIRE_ENVELOPE=true.\n")
	} else if resp.Legacy > 0 {
		fmt.Printf("\n%d legacy row(s) remain — run `containarium kms migrate-to-envelope`.\n", resp.Legacy)
	}
	return nil
}

func runKMSMigrate(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required for kms commands")
	}
	req := &pb.MigrateToEnvelopeRequest{
		DryRun:    kmsMigrateDryRun,
		BatchSize: kmsMigrateBatchSize,
		MaxRows:   kmsMigrateMaxRows,
	}
	var resp *pb.MigrateToEnvelopeResponse
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		resp, err = h.MigrateToEnvelope(req)
		if err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		resp, err = g.MigrateToEnvelope(req)
		if err != nil {
			return err
		}
	}
	mode := "MIGRATE"
	if resp.DryRun {
		mode = "DRY-RUN"
	}
	fmt.Printf("%s — complete\n", mode)
	fmt.Printf("  scanned:      %d\n", resp.Scanned)
	fmt.Printf("  migrated:     %d\n", resp.Migrated)
	fmt.Printf("  already done: %d\n", resp.AlreadyDone)
	fmt.Printf("  failed:       %d\n", resp.Failed)
	for _, e := range resp.Errors {
		fmt.Printf("  ✗ %s/%s — %s\n", e.Username, e.Name, e.Error)
	}
	if resp.Failed > 0 {
		return fmt.Errorf("%d row(s) failed migration", resp.Failed)
	}
	return nil
}
