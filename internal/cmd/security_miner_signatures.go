// `containarium security miner-signatures list|add|remove` — the signature
// list the miner-signature rule (#2638) matches every exec in a box against:
// binary names, command-line markers and executable SHA-256 hashes.
// CLI-first per the repo convention; talks to the grpc-gateway REST routes
// with the generated protobuf types (protojson), so the matcher kind is the
// MinerSignatureKind enum, never free text.
package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const minerSignaturesPath = "/v1/security/miner-signatures"

var securityMinerSignaturesCmd = &cobra.Command{
	Use:   "miner-signatures",
	Short: "Manage the miner-signature list (name, argv and sha256 matchers, #2638)",
}

// minerSigKindNames maps the CLI spelling to the proto enum.
var minerSigKindNames = map[string]pb.MinerSignatureKind{
	"name":   pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME,
	"argv":   pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV,
	"sha256": pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256,
}

const minerSigKindAllowed = "name, argv, sha256"

func parseMinerSigKind(s string) (pb.MinerSignatureKind, error) {
	k, ok := minerSigKindNames[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return pb.MinerSignatureKind_MINER_SIGNATURE_KIND_UNSPECIFIED,
			fmt.Errorf("invalid --kind %q: allowed values are %s", s, minerSigKindAllowed)
	}
	return k, nil
}

func minerSigKindLabel(k pb.MinerSignatureKind) string {
	return strings.ToLower(strings.TrimPrefix(k.String(), "MINER_SIGNATURE_KIND_"))
}

func renderMinerSignatures(w io.Writer, r *pb.ListMinerSignaturesResponse) {
	fmt.Fprintf(w, "Baseline version: %s\n", r.GetBaselineVersion())
	if len(r.GetSignatures()) == 0 {
		fmt.Fprintln(w, "No miner signatures configured.")
		return
	}
	fmt.Fprintf(w, "%-7s %-9s %-26s %s\n", "KIND", "SOURCE", "PATTERN", "LABEL")
	for _, s := range r.GetSignatures() {
		source := "operator"
		if s.GetBuiltin() {
			source = "baseline"
		}
		// %q keeps a significant trailing space ("--coin ") visible.
		fmt.Fprintf(w, "%-7s %-9s %-26q %s\n", minerSigKindLabel(s.GetKind()), source, s.GetPattern(), s.GetLabel())
	}
}

func newMinerSignaturesListCmd() *cobra.Command {
	var jsonOut bool
	c := &cobra.Command{
		Use:   "list",
		Short: "List the merged baseline + operator-added miner signatures",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if serverAddr == "" {
				return errServerRequired()
			}
			var out pb.ListMinerSignaturesResponse
			if err := policyRoundTrip(http.MethodGet, strings.TrimSuffix(serverAddr, "/")+minerSignaturesPath, nil, &out); err != nil {
				return err
			}
			if jsonOut {
				b, err := protojson.MarshalOptions{Multiline: true}.Marshal(&out)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			renderMinerSignatures(cmd.OutOrStdout(), &out)
			return nil
		},
	}
	c.Flags().BoolVar(&jsonOut, "json", false, "Output raw JSON")
	return c
}

func newMinerSignaturesAddCmd() *cobra.Command {
	var kind, label string
	c := &cobra.Command{
		Use:   "add --kind name|argv|sha256 <pattern>",
		Short: "Add an operator entry to the miner-signature list (admin)",
		Long: `Adds an entry, effective immediately — no daemon rebuild or restart.

  containarium security miner-signatures add --kind name 'srbminer*'
  containarium security miner-signatures add --kind argv -- '--algo randomx'
  containarium security miner-signatures add --kind argv -- '-o *:3334'
  containarium security miner-signatures add --kind sha256 <64 hex chars>

name matches the basename of the exec'd file and the task comm (exact or
glob, case-insensitive). argv matches the joined command line: a literal
substring, or, with a glob character, space-separated globs matched against
consecutive arguments. sha256 matches the executable's hash, computed off
the hot path only when no cheaper entry matched.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverAddr == "" {
				return errServerRequired()
			}
			k, err := parseMinerSigKind(kind)
			if err != nil {
				return err
			}
			req := &pb.AddMinerSignatureRequest{Signature: &pb.MinerSignature{Kind: k, Pattern: args[0], Label: label}}
			var out pb.AddMinerSignatureResponse
			if err := policyRoundTrip(http.MethodPost, strings.TrimSuffix(serverAddr, "/")+minerSignaturesPath, req, &out); err != nil {
				return err
			}
			s := out.GetSignature()
			fmt.Fprintf(cmd.OutOrStdout(), "Added %s %q (%s)\n", minerSigKindLabel(s.GetKind()), s.GetPattern(), s.GetLabel())
			return nil
		},
	}
	c.Flags().StringVar(&kind, "kind", "", "Matcher kind: "+minerSigKindAllowed)
	c.Flags().StringVar(&label, "label", "", "Human-readable label for the entry")
	_ = c.MarkFlagRequired("kind")
	return c
}

func newMinerSignaturesRemoveCmd() *cobra.Command {
	var kind string
	c := &cobra.Command{
		Use:   "remove --kind name|argv|sha256 <pattern>",
		Short: "Remove an operator-added miner signature (admin)",
		Long:  `Removes a previously operator-added entry. Baseline entries cannot be removed.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverAddr == "" {
				return errServerRequired()
			}
			k, err := parseMinerSigKind(kind)
			if err != nil {
				return err
			}
			q := url.Values{"kind": {k.String()}, "pattern": {args[0]}}
			u := strings.TrimSuffix(serverAddr, "/") + minerSignaturesPath + "?" + q.Encode()
			var out pb.RemoveMinerSignatureResponse
			if err := policyRoundTrip(http.MethodDelete, u, nil, &out); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s %q\n", minerSigKindLabel(k), args[0])
			return nil
		},
	}
	c.Flags().StringVar(&kind, "kind", "", "Matcher kind: "+minerSigKindAllowed)
	_ = c.MarkFlagRequired("kind")
	return c
}

func init() {
	securityMinerSignaturesCmd.AddCommand(newMinerSignaturesListCmd())
	securityMinerSignaturesCmd.AddCommand(newMinerSignaturesAddCmd())
	securityMinerSignaturesCmd.AddCommand(newMinerSignaturesRemoveCmd())
	securityCmd.AddCommand(securityMinerSignaturesCmd)
}
