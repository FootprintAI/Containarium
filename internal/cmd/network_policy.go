package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
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

// network-policy patch — virtual-patch deny rules (#660). A deny rule blocks a
// tenant's egress to a CIDR (optionally a port/proto) regardless of the
// allow-list, to "virtually patch" a known-vulnerable destination until the
// real fix ships. patch add/rm read-modify-write only the deny_rules of the
// tenant's policy, leaving the allow-list untouched.
var networkPolicyPatchCmd = &cobra.Command{
	Use:   "patch",
	Short: "Manage virtual-patch deny rules for a tenant (#660)",
	Long: `Manage virtual-patch deny rules — temporary, network-level blocks that
stop traffic to a known-vulnerable destination before it reaches the
vulnerable software, buying time until the real upstream patch ships.

A deny rule is evaluated BEFORE the egress allow-list (deny beats allow) and,
like the rest of network-policy, only drops when the daemon is armed
(CONTAINARIUM_NETWORK_POLICY_ENFORCE=1); otherwise it is observed and audited.`,
}

var (
	npDenyCidr    string
	npDenyPort    uint32
	npDenyProto   string
	npDenyNote    string
	npDenyExpires string
)

var networkPolicyPatchAddCmd = &cobra.Command{
	Use:   "add <tenant> --cidr <cidr> [--port N] [--proto tcp|udp] [--note CVE-…] [--expires RFC3339]",
	Short: "Add or update a virtual-patch deny rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runNetworkPolicyPatchAdd,
}

var networkPolicyPatchRmCmd = &cobra.Command{
	Use:   "rm <tenant> --cidr <cidr> [--port N] [--proto tcp|udp]",
	Short: "Remove a virtual-patch deny rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runNetworkPolicyPatchRm,
}

var networkPolicyPatchListCmd = &cobra.Command{
	Use:   "list <tenant>",
	Short: "List a tenant's virtual-patch deny rules",
	Args:  cobra.ExactArgs(1),
	RunE:  runNetworkPolicyPatchList,
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

	networkPolicyCmd.AddCommand(networkPolicyPatchCmd)
	networkPolicyPatchCmd.AddCommand(networkPolicyPatchAddCmd, networkPolicyPatchRmCmd, networkPolicyPatchListCmd)
	// add carries the full rule; rm identifies a rule by CIDR alone (there is at
	// most one deny rule per CIDR — see compileDenyRules).
	networkPolicyPatchAddCmd.Flags().StringVar(&npDenyCidr, "cidr", "", "Destination CIDR or host IP to block (required, IPv4)")
	networkPolicyPatchAddCmd.Flags().Uint32Var(&npDenyPort, "port", 0, "Destination port to scope the block (0 = any)")
	networkPolicyPatchAddCmd.Flags().StringVar(&npDenyProto, "proto", "", "Protocol to scope the block: tcp | udp (empty = any)")
	networkPolicyPatchAddCmd.Flags().StringVar(&npDenyNote, "note", "", "Operator note, typically the CVE id this virtual-patches")
	networkPolicyPatchAddCmd.Flags().StringVar(&npDenyExpires, "expires", "", "RFC3339 expiry; the rule auto-removes after this (empty = never)")
	networkPolicyPatchRmCmd.Flags().StringVar(&npDenyCidr, "cidr", "", "Destination CIDR or host IP of the rule to remove (required)")
	networkPolicyPatchAddCmd.Flags().BoolVar(&npJSONOut, "json", false, "Output the stored policy as JSON")
	networkPolicyPatchListCmd.Flags().BoolVar(&npJSONOut, "json", false, "Output as JSON")
}

// netPolicyJSON mirrors the NetworkPolicy wire shape (camelCase from
// grpc-gateway). Local so a server-side schema change surfaces as a decode
// failure here, not a silent field-drop.
type netPolicyJSON struct {
	Tenant           string         `json:"tenant"`
	AllowIntraTenant bool           `json:"allowIntraTenant"`
	EgressCidrs      []string       `json:"egressCidrs"`
	EgressDomains    []string       `json:"egressDomains"`
	AllowMetadata    bool           `json:"allowMetadata"`
	Mode             string         `json:"mode"`
	Source           string         `json:"source"`
	DenyRules        []denyRuleJSON `json:"denyRules,omitempty"`
}

// denyRuleJSON mirrors NetworkPolicyDenyRule (#660), grpc-gateway camelCase.
type denyRuleJSON struct {
	Cidr      string `json:"cidr"`
	Port      uint32 `json:"port,omitempty"`
	Proto     string `json:"proto,omitempty"`
	Note      string `json:"note,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
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
	// `set` declares the allow-policy but has no deny-rule flags; a NetworkPolicy
	// POST replaces the whole record, so fetch and carry over any virtual-patch
	// deny rules (#660) rather than silently wiping them. Use `network-policy
	// patch` to manage those. A real fetch error aborts (don't clobber on a blip);
	// a missing policy is fine (no rules to preserve).
	existing, _, err := getNetworkPolicy(args[0])
	if err != nil {
		return fmt.Errorf("fetch existing policy to preserve deny rules: %w", err)
	}
	body := setNetworkPolicyRequest{Policy: netPolicyJSON{
		Tenant:           args[0],
		AllowIntraTenant: npAllowIntraTenant,
		EgressCidrs:      npEgressCidrs,
		EgressDomains:    npEgressDomains,
		AllowMetadata:    npAllowMetadata,
		Mode:             mode,
		DenyRules:        existing.DenyRules,
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
	// PATCHES surfaces the count of virtual-patch deny rules (#660) so a
	// vulnerable-and-blocked tenant is visible in the fleet overview, not only via
	// `get`/`patch list <tenant>`. The --json path above carries the full rules.
	fmt.Fprintf(w, "%-20s %-12s %-6s %-8s %s\n", "TENANT", "MODE", "INTRA", "PATCHES", "EGRESS")
	for _, p := range out.Policies {
		fmt.Fprintf(w, "%-20s %-12s %-6v %-8d %s\n", p.Tenant, shortMode(p.Mode), p.AllowIntraTenant, len(p.DenyRules), egressSummary(p))
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

// --- virtual-patch deny rules (#660) ---

func runNetworkPolicyPatchAdd(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	rule, err := denyRuleFromFlags(true)
	if err != nil {
		return err
	}
	pol, _, err := getNetworkPolicy(args[0])
	if err != nil {
		return err
	}
	pol.DenyRules = upsertDenyRule(pol.DenyRules, rule)
	out, err := putNetworkPolicy(pol)
	if err != nil {
		return err
	}
	if npJSONOut {
		return printJSON(out)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ virtual-patch deny rule set for %q: %s\n", args[0], denyRuleSummary(rule))
	printDenyRules(cmd.OutOrStdout(), out.DenyRules)
	return nil
}

func runNetworkPolicyPatchRm(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	target, err := denyRuleFromFlags(false)
	if err != nil {
		return err
	}
	pol, found, err := getNetworkPolicy(args[0])
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no network policy for tenant %q", args[0])
	}
	k := denyKeyOf(target)
	kept := make([]denyRuleJSON, 0, len(pol.DenyRules))
	removed := false
	for _, r := range pol.DenyRules {
		if denyKeyOf(r) == k {
			removed = true
			continue
		}
		kept = append(kept, r)
	}
	if !removed {
		return fmt.Errorf("no matching deny rule (%s) for tenant %q", denyRuleSummary(target), args[0])
	}
	pol.DenyRules = kept
	if _, err := putNetworkPolicy(pol); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ removed virtual-patch deny rule for %q: %s\n", args[0], denyRuleSummary(target))
	return nil
}

func runNetworkPolicyPatchList(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	pol, found, err := getNetworkPolicy(args[0])
	if err != nil {
		return err
	}
	if npJSONOut {
		return printJSON(pol.DenyRules)
	}
	w := cmd.OutOrStdout()
	if !found || len(pol.DenyRules) == 0 {
		fmt.Fprintf(w, "No virtual-patch deny rules for %q.\n", args[0])
		return nil
	}
	fmt.Fprintf(w, "%-22s %-6s %-6s %-22s %s\n", "CIDR", "PORT", "PROTO", "EXPIRES", "NOTE")
	for _, r := range pol.DenyRules {
		fmt.Fprintf(w, "%-22s %-6s %-6s %-22s %s\n", r.Cidr, denyPortStr(r.Port), denyProtoStr(r.Proto), denyExpiresStr(r.ExpiresAt), r.Note)
	}
	return nil
}

// denyRuleFromFlags builds a denyRuleJSON from the --cidr/--port/--proto (and,
// for add, --note/--expires) flags, validating them. withMeta includes the
// note/expiry fields (add) vs. only the identity fields (rm).
func denyRuleFromFlags(withMeta bool) (denyRuleJSON, error) {
	cidr := strings.TrimSpace(npDenyCidr)
	if cidr == "" {
		return denyRuleJSON{}, fmt.Errorf("--cidr is required")
	}
	proto := strings.ToLower(strings.TrimSpace(npDenyProto))
	switch proto {
	case "", "tcp", "udp":
	default:
		return denyRuleJSON{}, fmt.Errorf("--proto must be tcp, udp, or empty (got %q)", npDenyProto)
	}
	if npDenyPort > 65535 {
		return denyRuleJSON{}, fmt.Errorf("--port %d out of range (0-65535)", npDenyPort)
	}
	r := denyRuleJSON{Cidr: cidr, Port: npDenyPort, Proto: proto}
	if withMeta {
		r.Note = strings.TrimSpace(npDenyNote)
		r.ExpiresAt = strings.TrimSpace(npDenyExpires)
	}
	return r, nil
}

// denyKeyOf is the identity of a deny rule for upsert/remove: the CIDR alone.
// The kernel deny_cidr map is keyed by CIDR (port/proto/note live in the value),
// so there is at most one deny rule per destination — re-adding the same CIDR
// replaces the whole rule (port, proto, note, expiry included). Matches
// compileDenyRules' CIDR-only dedup.
func denyKeyOf(r denyRuleJSON) string {
	return strings.ToLower(strings.TrimSpace(r.Cidr))
}

func upsertDenyRule(rules []denyRuleJSON, r denyRuleJSON) []denyRuleJSON {
	k := denyKeyOf(r)
	for i := range rules {
		if denyKeyOf(rules[i]) == k {
			rules[i] = r
			return rules
		}
	}
	return append(rules, r)
}

func denyRuleSummary(r denyRuleJSON) string {
	s := r.Cidr
	if r.Proto != "" {
		s += "/" + r.Proto
	}
	if r.Port != 0 {
		s += ":" + strconv.Itoa(int(r.Port))
	}
	return s
}

func printDenyRules(w io.Writer, rules []denyRuleJSON) {
	if len(rules) == 0 {
		return
	}
	fmt.Fprintf(w, "  deny-rules (virtual patches):\n")
	for _, r := range rules {
		extra := ""
		if r.Note != "" {
			extra += " (" + r.Note + ")"
		}
		if r.ExpiresAt != "" {
			extra += " expires " + r.ExpiresAt
		}
		fmt.Fprintf(w, "    - %s%s\n", denyRuleSummary(r), extra)
	}
}

func denyPortStr(p uint32) string {
	if p == 0 {
		return "any"
	}
	return strconv.Itoa(int(p))
}

func denyProtoStr(p string) string {
	if p == "" {
		return "any"
	}
	return p
}

func denyExpiresStr(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// getNetworkPolicy fetches a tenant's policy, distinguishing a genuine 404
// (found=false, no error) from a transport/other error — so a read-modify-write
// caller can start from an empty policy on 404 but abort on a real failure
// rather than clobbering. On 404 the returned policy has Tenant pre-filled.
func getNetworkPolicy(tenant string) (netPolicyJSON, bool, error) {
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/network-policies/" + tenant
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return netPolicyJSON{}, false, fmt.Errorf("create request: %w", err)
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return netPolicyJSON{}, false, fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return netPolicyJSON{Tenant: tenant}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return netPolicyJSON{}, false, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var env policyEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return netPolicyJSON{}, false, fmt.Errorf("decode policy: %w", err)
	}
	if env.Policy.Tenant == "" {
		env.Policy.Tenant = tenant
	}
	return env.Policy, true, nil
}

// putNetworkPolicy upserts a full NetworkPolicy via the set endpoint and returns
// the stored (normalized) form.
func putNetworkPolicy(p netPolicyJSON) (netPolicyJSON, error) {
	var out policyEnvelope
	if err := doJSON("POST", strings.TrimSuffix(serverAddr, "/")+"/v1/network-policies", setNetworkPolicyRequest{Policy: p}, &out); err != nil {
		return netPolicyJSON{}, err
	}
	return out.Policy, nil
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
	printDenyRules(w, p.DenyRules)
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
