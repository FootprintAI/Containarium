// `containarium security scan-opt-in` — record, per container, whether the
// intrusive scanners (OpenVAS) may scan it (#2426). CLI-first per the repo
// convention; the decision is a consent record (who, when, why) that the
// scanner reads before every scan, and each change lands in the audit log.
package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

// pentestScannerOpenVAS is the REST/JSON name of PentestScanner.OPENVAS.
const pentestScannerOpenVAS = "PENTEST_SCANNER_OPENVAS"

var scanOptInReason string

var securityScanOptInCmd = &cobra.Command{
	Use:   "scan-opt-in",
	Short: "Record whether a container may be scanned by OpenVAS",
	Long: `Records the scan decision for a container. Scanning with OpenVAS is
opt-in: a container is scanned only if its owner (or an operator) allowed it,
or the operator listed it in CONTAINARIUM_OPENVAS_OPT_IN. A recorded refusal
overrides that list, so an owner can always say no.`,
}

var securityScanOptInAllowCmd = &cobra.Command{
	Use:   "allow <container>",
	Short: "Allow OpenVAS to scan a container",
	Args:  cobra.ExactArgs(1),
	RunE:  func(cmd *cobra.Command, args []string) error { return runScanOptInSet(cmd, args[0], true) },
}

var securityScanOptInRefuseCmd = &cobra.Command{
	Use:   "refuse <container>",
	Short: "Refuse OpenVAS scans of a container (overrides the operator-wide list)",
	Args:  cobra.ExactArgs(1),
	RunE:  func(cmd *cobra.Command, args []string) error { return runScanOptInSet(cmd, args[0], false) },
}

var scanOptInListJSONOut bool

var securityScanOptInListCmd = &cobra.Command{
	Use:   "list [container]",
	Short: "List recorded scan decisions (all of them needs admin)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScanOptInList,
}

// scanOptInSetBody is the request body of PUT /v1/pentest/scan-opt-ins/{name}.
type scanOptInSetBody struct {
	Scanner string `json:"scanner"`
	OptedIn bool   `json:"optedIn"`
	Reason  string `json:"reason"`
}

// scanOptInEnvelope mirrors PentestScanOptIn's grpc-gateway JSON shape.
type scanOptInEnvelope struct {
	ContainerName string `json:"containerName"`
	Scanner       string `json:"scanner"`
	OptedIn       bool   `json:"optedIn"`
	Reason        string `json:"reason"`
	UpdatedBy     string `json:"updatedBy"`
	UpdatedAt     string `json:"updatedAt"`
}

type setScanOptInEnvelope struct {
	OptIn scanOptInEnvelope `json:"optIn"`
}

type listScanOptInsEnvelope struct {
	OptIns []scanOptInEnvelope `json:"optIns"`
}

func scanOptInURL(container string) string {
	base := strings.TrimSuffix(serverAddr, "/") + "/v1/pentest/scan-opt-ins"
	if container == "" {
		return base
	}
	return base + "/" + url.PathEscape(container)
}

func runScanOptInSet(cmd *cobra.Command, container string, optedIn bool) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	var out setScanOptInEnvelope
	body := scanOptInSetBody{Scanner: pentestScannerOpenVAS, OptedIn: optedIn, Reason: scanOptInReason}
	if err := doJSON("PUT", scanOptInURL(container), body, &out); err != nil {
		return err
	}
	verb := "allowed"
	if !out.OptIn.OptedIn {
		verb = "refused"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "OpenVAS scans of %s: %s (recorded by %s)\n",
		out.OptIn.ContainerName, verb, out.OptIn.UpdatedBy)
	return nil
}

func runScanOptInList(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	container := ""
	if len(args) == 1 {
		container = args[0]
	}
	reqURL := scanOptInURL("")
	if container != "" {
		reqURL += "?" + url.Values{"container_name": {container}}.Encode()
	}
	var out listScanOptInsEnvelope
	if err := getJSON(reqURL, &out); err != nil {
		return err
	}
	if scanOptInListJSONOut {
		return printJSON(out)
	}
	w := cmd.OutOrStdout()
	if len(out.OptIns) == 0 {
		fmt.Fprintln(w, "No scan decisions recorded.")
		return nil
	}
	fmt.Fprintf(w, "%-32s %-24s %-9s %-16s %-22s %s\n", "CONTAINER", "SCANNER", "DECISION", "BY", "AT", "REASON")
	for _, o := range out.OptIns {
		decision := "refused"
		if o.OptedIn {
			decision = "allowed"
		}
		fmt.Fprintf(w, "%-32s %-24s %-9s %-16s %-22s %s\n",
			o.ContainerName, strings.TrimPrefix(o.Scanner, "PENTEST_SCANNER_"), decision, o.UpdatedBy, o.UpdatedAt, o.Reason)
	}
	return nil
}

func init() {
	securityScanOptInAllowCmd.Flags().StringVar(&scanOptInReason, "reason", "", "Why (kept with the decision and in the audit log)")
	securityScanOptInRefuseCmd.Flags().StringVar(&scanOptInReason, "reason", "", "Why (kept with the decision and in the audit log)")
	securityScanOptInListCmd.Flags().BoolVar(&scanOptInListJSONOut, "json", false, "Output raw JSON")
	securityScanOptInCmd.AddCommand(securityScanOptInAllowCmd, securityScanOptInRefuseCmd, securityScanOptInListCmd)
	securityCmd.AddCommand(securityScanOptInCmd)
}
