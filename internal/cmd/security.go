// Security CLI subcommands — scan, findings, remediate. Same Go calls
// the MCP tools use (one function, two surfaces per CLAUDE.md
// CLI-first).
//
// Why one file for three commands: they share a tiny client and a
// small set of helpers; splitting across three files would mostly
// duplicate boilerplate. If any of them grows non-trivially, split.
package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/mcp"
	"github.com/spf13/cobra"
)

// --- containarium security-scan --------------------------------------------

var (
	scanUser string
	scanKind string
)

var securityScanCmd = &cobra.Command{
	Use:   "security-scan <username>",
	Short: "Trigger one or more security scans on a container",
	Long: `Trigger ClamAV (malware), pentest (CVE), or ZAP (DAST) scans on a
container. Default --kind=all runs all three. Scans run asynchronously
on the daemon; use 'security-findings' to read results.

Typical durations:
  - clamav: seconds
  - pentest: tens of seconds
  - zap: minutes

For continuous/scheduled scans, see the cloud product's security-patch
agent. This CLI command is the one-shot BYOA equivalent.`,
	Args: cobra.ExactArgs(1),
	RunE: runSecurityScan,
}

// --- containarium security-findings ----------------------------------------

var (
	findUser string
	findKind string
)

var securityFindingsCmd = &cobra.Command{
	Use:   "security-findings <username>",
	Short: "List security findings for a container (normalized across scanners)",
	Long: `List findings across ClamAV, pentest, and ZAP scanners, merged into a
single normalized shape with a 'kind' label.

Only findings with fixAvailable=true can be auto-remediated by
'security-remediate'. Today that's pentest findings only (the daemon's
RemediatePentestFinding runs a package upgrade).`,
	Args: cobra.ExactArgs(1),
	RunE: runSecurityFindings,
}

// --- containarium security-remediate ---------------------------------------

var securityRemediateCmd = &cobra.Command{
	Use:   "security-remediate <finding-id>",
	Short: "Apply the daemon's one-shot auto-fix for a security finding",
	Long: `Attempt to remediate a security finding by its ID (from
'security-findings'). Currently only pentest findings with
fixAvailable=true are supported — the daemon upgrades the affected
package.

This is a one-shot operator action. Do NOT chain scan → pick →
remediate in scripts without human confirmation; that's the cloud
product's hosted security-patch agent territory.`,
	Args: cobra.ExactArgs(1),
	RunE: runSecurityRemediate,
}

func init() {
	rootCmd.AddCommand(securityScanCmd)
	securityScanCmd.Flags().StringVar(&scanKind, "kind", "all", "clamav | pentest | zap | all")

	rootCmd.AddCommand(securityFindingsCmd)
	securityFindingsCmd.Flags().StringVar(&findKind, "kind", "all", "clamav | pentest | zap | all")

	rootCmd.AddCommand(securityRemediateCmd)
}

// runSecurityScan dispatches the scan via the same Go code path the
// MCP tool uses. Reuses mcp.Client because the CLI talks to the daemon
// over the same REST surface; no need for a parallel client layer.
func runSecurityScan(_ *cobra.Command, args []string) error {
	scanUser = args[0]
	c, err := newSecurityClient()
	if err != nil {
		return err
	}
	resp, err := c.TriggerSecurityScan(strings.ToLower(scanKind), scanUser+"-container", scanUser)
	if err != nil {
		return err
	}
	fmt.Printf("Scan(s) queued: kind=%s queued=%d\n  %s\n  → %s\n",
		resp.Kind, resp.Queued, resp.Message, resp.PollHint)
	return nil
}

func runSecurityFindings(_ *cobra.Command, args []string) error {
	findUser = args[0]
	c, err := newSecurityClient()
	if err != nil {
		return err
	}
	findings, err := c.ListSecurityFindings(strings.ToLower(findKind), findUser+"-container")
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		fmt.Println("No findings.")
		return nil
	}
	// One-line-per-finding for shell readability. Use --format=json if
	// you need machine output (drop into jq).
	if outputFormat == "json" {
		out, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	for _, f := range findings {
		fix := " "
		if f.FixAvailable {
			fix = "F"
		}
		fmt.Printf("[%s] [%-8s] [%s] id=%d %s\n",
			fix, f.Kind, padSeverity(f.Severity), f.ID, f.Title)
	}
	return nil
}

func runSecurityRemediate(_ *cobra.Command, args []string) error {
	fid, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("finding-id must be an integer: %w", err)
	}
	c, err := newSecurityClient()
	if err != nil {
		return err
	}
	resp, err := c.RemediateSecurityFinding(fid)
	if err != nil {
		return err
	}
	if !resp.Success {
		fmt.Printf("Remediation FAILED: %s\n", resp.Message)
		return fmt.Errorf("remediation reported failure")
	}
	fmt.Printf("Remediation OK: %s\n", resp.Message)
	if resp.PackageName != "" {
		fmt.Printf("  package: %s   %s → %s\n", resp.PackageName, resp.OldVersion, resp.NewVersion)
	}
	return nil
}

// newSecurityClient builds an mcp.Client pointed at the configured
// daemon. Reuses the same env vars the MCP server uses
// (CONTAINARIUM_SERVER_URL, CONTAINARIUM_JWT_TOKEN) so operators
// configure once.
func newSecurityClient() (*mcp.Client, error) {
	serverURL := os.Getenv("CONTAINARIUM_SERVER_URL")
	if serverURL == "" && serverAddr != "" {
		// Fall back to the global --server flag.
		serverURL = serverAddr
		if !strings.HasPrefix(serverURL, "http") {
			serverURL = "http://" + serverURL
		}
	}
	if serverURL == "" {
		return nil, fmt.Errorf("set CONTAINARIUM_SERVER_URL or use --server")
	}
	token := os.Getenv("CONTAINARIUM_JWT_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("set CONTAINARIUM_JWT_TOKEN to a daemon-issued JWT")
	}
	if _, err := url.Parse(serverURL); err != nil {
		return nil, fmt.Errorf("invalid CONTAINARIUM_SERVER_URL: %w", err)
	}
	c := mcp.NewClient(serverURL, token)
	_ = time.Second // placeholder for future timeout tuning
	return c, nil
}

// padSeverity right-pads to 8 chars so the table aligns ("critical"
// is the widest; "info" is 4).
func padSeverity(s string) string {
	const w = 8
	if len(s) >= w {
		return s[:w]
	}
	return s + strings.Repeat(" ", w-len(s))
}
