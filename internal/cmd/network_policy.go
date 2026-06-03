package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// networkPolicyCmd is the parent for `containarium network-policy <verb>`.
// It drives the admin-only NetworkPolicyService (#315 Phase A) over the
// daemon's HTTP/REST surface, so every subcommand requires --server and an
// admin --token. CLI-first per the repo convention; the platform MCP tool (a
// later increment) wraps the same endpoints.
var networkPolicyCmd = &cobra.Command{
	Use:     "network-policy",
	Short:   "Manage per-tenant network isolation policies (admin)",
	Aliases: []string{"netpolicy", "np"},
	Long: `Manage per-tenant network-isolation policies (#315, Phase A).

A network policy declares a tenant's allowed egress (CIDRs + domains) and
whether same-tenant containers may talk to each other. Phase A ships in
log_only mode: denied flows are observed and audited, nothing is dropped.

All subcommands are admin-only and talk to the daemon's HTTP API, so they
require --server (the daemon's HTTP address) and an admin --token.`,
}

// npJSONOut toggles raw-JSON output on the read subcommands.
var npJSONOut bool

// network-policy set flags
var (
	npAllowIntraTenant bool
	npEgressCidrs      []string
	npEgressDomains    []string
	npMode             string
	npAllowMetadata    bool
)

var networkPolicySetCmd = &cobra.Command{
	Use:   "set <tenant>",
	Short: "Create or update a tenant's network policy",
	Args:  cobra.ExactArgs(1),
	RunE:  runNetworkPolicySet,
}

var networkPolicyGetCmd = &cobra.Command{
	Use:   "get <tenant>",
	Short: "Show a tenant's network policy",
	Args:  cobra.ExactArgs(1),
	RunE:  runNetworkPolicyGet,
}

var networkPolicyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List every tenant's network policy",
	Args:  cobra.NoArgs,
	RunE:  runNetworkPolicyList,
}

var networkPolicyDeleteCmd = &cobra.Command{
	Use:     "delete <tenant>",
	Short:   "Delete a tenant's network policy",
	Aliases: []string{"rm"},
	Args:    cobra.ExactArgs(1),
	RunE:    runNetworkPolicyDelete,
}

func init() {
	rootCmd.AddCommand(networkPolicyCmd)
	networkPolicyCmd.AddCommand(networkPolicySetCmd, networkPolicyGetCmd, networkPolicyListCmd, networkPolicyDeleteCmd)

	networkPolicySetCmd.Flags().BoolVar(&npAllowIntraTenant, "allow-intra-tenant", false,
		"Allow container↔container traffic within the same tenant")
	networkPolicySetCmd.Flags().StringSliceVar(&npEgressCidrs, "egress-cidr", nil,
		"Allowed egress destination CIDR (repeatable, e.g. --egress-cidr 10.0.0.0/8)")
	networkPolicySetCmd.Flags().StringSliceVar(&npEgressDomains, "egress-domain", nil,
		"Allowed egress domain (repeatable, e.g. --egress-domain api.github.com)")
	networkPolicySetCmd.Flags().StringVar(&npMode, "mode", "log_only",
		"Enforcement mode: log_only | enforce")
	networkPolicySetCmd.Flags().BoolVar(&npAllowMetadata, "allow-metadata", false,
		"Allow reaching the cloud metadata service (169.254.169.254); default deny even if a CIDR would cover it")
	networkPolicySetCmd.Flags().BoolVar(&npJSONOut, "json", false, "Output the stored policy as JSON")

	networkPolicyGetCmd.Flags().BoolVar(&npJSONOut, "json", false, "Output as JSON")
	networkPolicyListCmd.Flags().BoolVar(&npJSONOut, "json", false, "Output as JSON")
}

// netPolicyJSON mirrors the NetworkPolicy wire shape (camelCase from
// grpc-gateway). Local so a server-side schema change surfaces as a decode
// failure here, not a silent field-drop.
type netPolicyJSON struct {
	Tenant           string   `json:"tenant"`
	AllowIntraTenant bool     `json:"allowIntraTenant"`
	EgressCidrs      []string `json:"egressCidrs"`
	EgressDomains    []string `json:"egressDomains"`
	AllowMetadata    bool     `json:"allowMetadata"`
	Mode             string   `json:"mode"`
	Source           string   `json:"source"`
}

type setNetworkPolicyRequest struct {
	Policy netPolicyJSON `json:"policy"`
}
type policyEnvelope struct {
	Policy netPolicyJSON `json:"policy"`
}
type policiesEnvelope struct {
	Policies []netPolicyJSON `json:"policies"`
}

// normalizeMode maps the friendly CLI mode string to the proto enum name the
// gateway expects.
func normalizeMode(m string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "", "log_only", "log-only", "logonly":
		return "NETWORK_POLICY_MODE_LOG_ONLY", nil
	case "enforce":
		return "NETWORK_POLICY_MODE_ENFORCE", nil
	default:
		return "", fmt.Errorf("invalid --mode %q (want log_only or enforce)", m)
	}
}

func runNetworkPolicySet(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	mode, err := normalizeMode(npMode)
	if err != nil {
		return err
	}
	body := setNetworkPolicyRequest{Policy: netPolicyJSON{
		Tenant:           args[0],
		AllowIntraTenant: npAllowIntraTenant,
		EgressCidrs:      npEgressCidrs,
		EgressDomains:    npEgressDomains,
		AllowMetadata:    npAllowMetadata,
		Mode:             mode,
	}}
	var out policyEnvelope
	if err := doJSON("POST", strings.TrimSuffix(serverAddr, "/")+"/v1/network-policies", body, &out); err != nil {
		return err
	}
	if npJSONOut {
		return printJSON(out.Policy)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ network policy set for %q\n", out.Policy.Tenant)
	printPolicy(cmd.OutOrStdout(), out.Policy)
	return nil
}

func runNetworkPolicyGet(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	var out policyEnvelope
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/network-policies/" + args[0]
	if err := getJSON(url, &out); err != nil {
		return err
	}
	if npJSONOut {
		return printJSON(out.Policy)
	}
	printPolicy(cmd.OutOrStdout(), out.Policy)
	return nil
}

func runNetworkPolicyList(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	var out policiesEnvelope
	if err := getJSON(strings.TrimSuffix(serverAddr, "/")+"/v1/network-policies", &out); err != nil {
		return err
	}
	if npJSONOut {
		return printJSON(out.Policies)
	}
	w := cmd.OutOrStdout()
	if len(out.Policies) == 0 {
		fmt.Fprintln(w, "No network policies.")
		return nil
	}
	fmt.Fprintf(w, "%-20s %-12s %-6s %s\n", "TENANT", "MODE", "INTRA", "EGRESS")
	for _, p := range out.Policies {
		fmt.Fprintf(w, "%-20s %-12s %-6v %s\n", p.Tenant, shortMode(p.Mode), p.AllowIntraTenant, egressSummary(p))
	}
	return nil
}

func runNetworkPolicyDelete(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/network-policies/" + args[0]
	if err := doJSON("DELETE", url, nil, nil); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ network policy deleted for %q\n", args[0])
	return nil
}

func errServerRequired() error {
	return fmt.Errorf("--server is required (the platform daemon's HTTP address, e.g. http://host:8080)")
}

func shortMode(m string) string {
	return strings.TrimPrefix(m, "NETWORK_POLICY_MODE_")
}

func egressSummary(p netPolicyJSON) string {
	parts := make([]string, 0, len(p.EgressCidrs)+len(p.EgressDomains))
	parts = append(parts, p.EgressCidrs...)
	parts = append(parts, p.EgressDomains...)
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, ",")
}

func printPolicy(w io.Writer, p netPolicyJSON) {
	fmt.Fprintf(w, "  tenant:             %s\n", p.Tenant)
	fmt.Fprintf(w, "  mode:               %s\n", shortMode(p.Mode))
	fmt.Fprintf(w, "  allow-intra-tenant: %v\n", p.AllowIntraTenant)
	fmt.Fprintf(w, "  allow-metadata:     %v\n", p.AllowMetadata)
	if p.Source != "" {
		fmt.Fprintf(w, "  source:             %s\n", p.Source)
	}
	if len(p.EgressCidrs) > 0 {
		fmt.Fprintf(w, "  egress-cidrs:       %s\n", strings.Join(p.EgressCidrs, ", "))
	}
	if len(p.EgressDomains) > 0 {
		fmt.Fprintf(w, "  egress-domains:     %s\n", strings.Join(p.EgressDomains, ", "))
	}
}

// doJSON does an admin-authenticated request with an optional JSON body and
// decodes the JSON response into out (out may be nil to discard the body).
func doJSON(method, url string, body, out interface{}) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
